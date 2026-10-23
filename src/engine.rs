//! Independent compile-once keyword and regex secret detection.
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose};
use regex::bytes::Regex;
use serde::{Deserialize, Serialize};

pub use crate::rules::Confidence;

const REDACTED: &str = "[REDACTED]";
use crate::rules::{self, CompiledRule, RuleInfo};

/// No network validation or process-global configuration is used.
///
/// A fingerprint key enables keyed BLAKE3 fingerprints. Without a key, fingerprints
/// are ordinary digests and do not protect low-entropy secrets from guessing.
#[derive(Clone)]
pub struct EngineConfig {
    pub builtin_rules: bool,
    pub custom_rule_paths: Vec<PathBuf>,
    pub min_confidence: Confidence,
    pub enable_base64: bool,
    pub min_entropy: Option<f32>,
    pub fingerprint_key: Option<[u8; 32]>,
}

impl Default for EngineConfig {
    fn default() -> Self {
        Self {
            builtin_rules: true,
            custom_rule_paths: Vec::new(),
            min_confidence: Confidence::Medium,
            enable_base64: true,
            min_entropy: None,
            fingerprint_key: None,
        }
    }
}

/// A finding with no raw secret, capture values, source snippets, or rule patterns.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Finding {
    pub rule_id: String,
    /// Sorted rule evidence, including `rule_id`, when multiple rules matched
    /// the same secret span in the same decoded content. Empty for single hits.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_rule_ids: Vec<String>,
    pub path: Arc<str>,
    /// Zero-based start byte offset in `coordinate_space`.
    pub start: usize,
    /// Exclusive end byte offset. Base64 findings cover the encoded container.
    pub end: usize,
    /// One-based line number.
    pub line: usize,
    /// Zero-based byte column, not a Unicode scalar or UTF-16 column.
    pub column: usize,
    pub redacted: String,
    /// Domain-separated digest of rule, path and secret; stable across line moves.
    pub fingerprint: String,
    pub explanation: Arc<str>,
    #[serde(default)]
    pub confidence: String,
    #[serde(default)]
    pub is_base64_encoded: bool,
    /// Always `source_bytes`; Base64 findings reference their encoded container.
    #[serde(default = "source_coordinates")]
    pub coordinate_space: String,
}

fn source_coordinates() -> String {
    "source_bytes".into()
}

impl Default for Finding {
    fn default() -> Self {
        Self {
            rule_id: String::new(),
            matched_rule_ids: Vec::new(),
            path: Arc::from(""),
            start: 0,
            end: 0,
            line: 0,
            column: 0,
            redacted: REDACTED.into(),
            fingerprint: String::new(),
            explanation: Arc::from(""),
            confidence: String::new(),
            is_base64_encoded: false,
            coordinate_space: source_coordinates(),
        }
    }
}

/// Thread-safe scanner sharing immutable compiled regexes and keyword automaton.
/// Repeated calls are independent and deterministic; no global state or network.
pub struct Engine {
    rules: Vec<CompiledRule>,
    keywords: Option<AhoCorasick>,
    keyword_rules: Vec<Vec<usize>>,
    unconditional: Vec<usize>,
    base64_candidates: Regex,
    rust_visibility: Regex,
    enable_base64: bool,
    min_entropy: Option<f32>,
    fingerprint_key: Option<[u8; 32]>,
    configuration_id: String,
}

#[derive(Clone, Copy)]
struct ContentEncoding {
    base64: bool,
    utf16: bool,
}

impl Engine {
    pub fn new(config: EngineConfig) -> Result<Self> {
        if let Some(entropy) = config.min_entropy {
            ensure!(
                entropy.is_finite() && (0.0..=8.0).contains(&entropy),
                "minimum byte entropy must be finite and between 0 and 8"
            );
        }
        let rules = rules::compile(
            config.builtin_rules,
            &config.custom_rule_paths,
            config.min_confidence,
        )?;
        let configuration_id = configuration_id(&rules, &config)?;
        let mut keyword_map: BTreeMap<String, Vec<usize>> = BTreeMap::new();
        let mut unconditional = Vec::new();
        for (id, rule) in rules.iter().enumerate() {
            if rule.spec.keywords.is_empty() {
                unconditional.push(id);
            }
            for keyword in &rule.spec.keywords {
                keyword_map
                    .entry(keyword.to_ascii_lowercase())
                    .or_default()
                    .push(id);
            }
        }
        let keywords = if keyword_map.is_empty() {
            None
        } else {
            Some(
                AhoCorasick::builder()
                    .ascii_case_insensitive(true)
                    .build(keyword_map.keys())
                    .context("compiling keyword prefilter")?,
            )
        };
        // A SimplePath has identifier segments separated by whole `::` tokens.
        // Keep the match anchored to the current field's complete line prefix.
        let path_segment = r"(?:(?:r#)?(?:\p{XID_Start}\p{XID_Continue}*|_\p{XID_Continue}+))";
        let rust_visibility = Regex::new(&format!(
            r"\Apub(?:[ \t]*\([ \t]*(?:crate|self|super|in(?:[ \t]+|[ \t]*(?P<global>::)[ \t]*)(?P<path>{path_segment}(?:[ \t]*::[ \t]*{path_segment})*))[ \t]*\))?\z"
        ))?;
        Ok(Self {
            rules,
            keywords,
            keyword_rules: keyword_map.into_values().collect(),
            unconditional,
            base64_candidates: Regex::new(r"[A-Za-z0-9+/_-]{24,}={0,2}")?,
            rust_visibility,
            enable_base64: config.enable_base64,
            min_entropy: config.min_entropy,
            fingerprint_key: config.fingerprint_key,
            configuration_id,
        })
    }

    /// Stable, opaque identity of actual compiled rules and semantic configuration.
    /// Contains no serialized patterns or fingerprint key material.
    pub fn configuration_id(&self) -> &str {
        &self.configuration_id
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }

    pub fn rules(&self) -> Vec<RuleInfo> {
        self.rules
            .iter()
            .map(|rule| RuleInfo {
                id: rule.spec.id.clone(),
                name: rule.spec.name.clone(),
                confidence: rule.spec.confidence.to_string(),
            })
            .collect()
    }

    /// Scan raw bytes, BOM-marked UTF-16 and optionally one layer of Base64. Positions refer to source
    /// bytes; decoded findings cover their original encoded container.
    pub fn scan_bytes(&self, path: &str, bytes: &[u8]) -> Result<Vec<Finding>> {
        let identity = logical_identity(path);
        self.scan_bytes_with_identity(path, &identity, bytes)
    }

    /// Separate display/rule-matching path from the caller's stable source identity.
    /// `identity` is opaque and never interpreted through filesystem I/O.
    pub fn scan_bytes_with_identity(
        &self,
        path: &str,
        identity: &str,
        bytes: &[u8],
    ) -> Result<Vec<Finding>> {
        let decoded_utf16 = decode_utf16_bom(bytes)?;
        let content = decoded_utf16
            .as_ref()
            .map_or(bytes, |decoded| decoded.bytes.as_slice());
        let mut findings = Vec::new();
        let utf16 = decoded_utf16.is_some();
        self.scan_content(path, identity, content, None, utf16, &mut findings);
        if self.enable_base64 {
            for candidate in self.base64_candidates.find_iter(content) {
                let encoded = candidate.as_bytes();
                let decoded = [
                    general_purpose::STANDARD,
                    general_purpose::STANDARD_NO_PAD,
                    general_purpose::URL_SAFE,
                    general_purpose::URL_SAFE_NO_PAD,
                ]
                .iter()
                .find_map(|codec| codec.decode(encoded).ok());
                if let Some(decoded) = decoded {
                    self.scan_content(
                        path,
                        identity,
                        &decoded,
                        Some((candidate.start(), candidate.end())),
                        utf16,
                        &mut findings,
                    );
                }
            }
        }
        if !findings.is_empty() {
            if let Some(decoded) = &decoded_utf16 {
                map_utf16_findings(bytes, decoded.little_endian, &mut findings)?;
            } else {
                map_byte_findings(bytes, &mut findings);
            }
        }
        findings.sort_by(|a, b| {
            (&a.path, a.start, a.end, &a.rule_id, &a.fingerprint).cmp(&(
                &b.path,
                b.start,
                b.end,
                &b.rule_id,
                &b.fingerprint,
            ))
        });
        Ok(findings)
    }

    fn scan_content(
        &self,
        path: &str,
        identity: &str,
        bytes: &[u8],
        container: Option<(usize, usize)>,
        utf16: bool,
        out: &mut Vec<Finding>,
    ) {
        // Coordinates here refer to one content view, before Base64/UTF-16
        // mapping. Equal spans therefore mean equal bytes and provenance.
        let mut matches = Vec::new();
        let mut candidates = vec![false; self.rules.len()];
        for &id in &self.unconditional {
            candidates[id] = true;
        }
        if let Some(keywords) = &self.keywords {
            for found in keywords.find_overlapping_iter(bytes) {
                for &id in &self.keyword_rules[found.pattern().as_usize()] {
                    if !candidates[id] && self.rules[id].keyword_matches(bytes, found.start()) {
                        candidates[id] = true;
                    }
                }
            }
        }
        let single_candidate = candidates.iter().filter(|&&active| active).take(2).count() == 1;
        let mut rust_context = None;
        for (id, rule) in self.rules.iter().enumerate() {
            if !candidates[id]
                || rule
                    .path
                    .as_ref()
                    .is_some_and(|filter| !filter.is_match(path))
                || rule
                    .exclude_paths
                    .iter()
                    .any(|filter| filter.is_match(path))
                || rule
                    .allowlist
                    .iter()
                    .any(|group| group.matches_path_only(path))
            {
                continue;
            }
            for captures in rule.pattern.captures_iter(bytes) {
                let Some(full_match) = captures.get(0) else {
                    continue;
                };
                let secret = match rule.spec.secret_group {
                    Some(group) => captures.get(group),
                    None => captures
                        .iter()
                        .skip(1)
                        .flatten()
                        .find(|capture| !capture.is_empty())
                        .or(Some(full_match)),
                };
                let Some(secret) = secret else {
                    continue;
                };
                let value = secret.as_bytes();
                if value.is_empty()
                    || is_placeholder(value)
                    // A public Rust field's colon introduces a type, not a
                    // credential value. Keep this local to the matched field.
                    || (rule.builtin
                        && rule.spec.id == "generic-credential-unquoted"
                        && path.ends_with(".rs")
                        && container.is_none()
                        && bytes[full_match.start()..secret.start()]
                            .trim_ascii_end()
                            .ends_with(b":")
                        && rust_context
                            .get_or_insert_with(|| std::str::from_utf8(bytes).ok().map(rust_visibility_context))
                            .as_mut()
                            .and_then(|context| context(full_match.start()))
                            .is_some_and(|(start, field)| rust_field_visibility(&self.rust_visibility, bytes, start, field)))
                    || (matches!(
                        rule.spec.id.as_str(),
                        "generic-api-key" | "linkedin-client-id"
                    ) && assignment_capture_is_non_value(
                        &bytes[full_match.start()..secret.start()],
                        &bytes[secret.end()..],
                    ))
                    || (self.min_entropy.unwrap_or(rule.spec.min_entropy) > 0.0
                        && entropy(value) <= self.min_entropy.unwrap_or(rule.spec.min_entropy))
                    || (rule.spec.id.starts_with("generic-credential-")
                        && token_assignment_is_prose(
                            &bytes[full_match.start()..secret.start()],
                            value,
                        ))
                {
                    continue;
                }
                let line = if rule
                    .allowlist
                    .iter()
                    .any(|group| matches!(group.target, rules::AllowlistTarget::Line))
                {
                    surrounding_lines(bytes, full_match.start(), full_match.end())
                } else {
                    &[]
                };
                if rule
                    .allowlist
                    .iter()
                    .any(|group| group.allows(path, value, full_match.as_bytes(), line))
                {
                    continue;
                }
                if single_candidate {
                    // captures_iter has non-overlapping matches. A single rule
                    // cannot yield duplicate nonempty spans in this content view.
                    let shared_path = out
                        .last()
                        .map_or_else(|| Arc::from(path), |finding| Arc::clone(&finding.path));
                    out.push(self.make_finding(
                        rule,
                        shared_path,
                        identity,
                        value,
                        container.unwrap_or((secret.start(), secret.end())),
                        ContentEncoding {
                            base64: container.is_some(),
                            utf16,
                        },
                    ));
                } else {
                    matches.push((secret.start(), secret.end(), id));
                }
            }
        }
        // Prefer a provider-specific rule, then confidence, then rule ID. This
        // selects a deterministic primary fingerprint without losing rule evidence.
        matches.sort_by(|a, b| {
            let rank = |index: usize| {
                let spec = &self.rules[index].spec;
                (
                    spec.id.starts_with("generic-"),
                    std::cmp::Reverse(spec.confidence),
                    &spec.id,
                )
            };
            (a.0, a.1, rank(a.2)).cmp(&(b.0, b.1, rank(b.2)))
        });
        let mut matches = matches.into_iter().peekable();
        while let Some((secret_start, secret_end, id)) = matches.next() {
            let rule = &self.rules[id];
            let mut matched_rule_ids = Vec::new();
            while let Some(&(next_start, next_end, next_id)) = matches.peek() {
                if (secret_start, secret_end) != (next_start, next_end) {
                    break;
                }
                if matched_rule_ids.is_empty() {
                    matched_rule_ids.push(rule.spec.id.clone());
                }
                matched_rule_ids.push(self.rules[next_id].spec.id.clone());
                matches.next();
            }
            matched_rule_ids.sort_unstable();
            matched_rule_ids.dedup();
            let mut finding = self.make_finding(
                rule,
                out.last()
                    .map_or_else(|| Arc::from(path), |finding| Arc::clone(&finding.path)),
                identity,
                &bytes[secret_start..secret_end],
                container.unwrap_or((secret_start, secret_end)),
                ContentEncoding {
                    base64: container.is_some(),
                    utf16,
                },
            );
            finding.matched_rule_ids = matched_rule_ids;
            out.push(finding);
        }
    }

    fn make_finding(
        &self,
        rule: &CompiledRule,
        path: Arc<str>,
        identity: &str,
        value: &[u8],
        (start, end): (usize, usize),
        encoding: ContentEncoding,
    ) -> Finding {
        Finding {
            rule_id: rule.spec.id.clone(),
            matched_rule_ids: Vec::new(),
            path,
            start,
            end,
            line: 0,
            column: 0,
            redacted: REDACTED.into(),
            fingerprint: self.fingerprint(&rule.spec.id, identity, value),
            explanation: rule.explanation(encoding.base64, encoding.utf16),
            confidence: rule.spec.confidence.to_string(),
            is_base64_encoded: encoding.base64,
            coordinate_space: source_coordinates(),
        }
    }

    fn fingerprint(&self, rule: &str, path: &str, secret: &[u8]) -> String {
        let mut hash = match &self.fingerprint_key {
            Some(key) => blake3::Hasher::new_keyed(key),
            None => blake3::Hasher::new(),
        };
        hash.update(b"secret-scan/finding/v1\0");
        for part in [rule.as_bytes(), path.as_bytes(), secret] {
            hash.update(&(part.len() as u64).to_le_bytes());
            hash.update(part);
        }
        hash.finalize().to_hex().to_string()
    }
}

fn entropy(value: &[u8]) -> f32 {
    let mut counts = [0usize; 256];
    for &byte in value {
        counts[byte as usize] += 1;
    }
    let len = value.len() as f32;
    counts
        .into_iter()
        .filter(|&count| count > 0)
        .map(|count| {
            let p = count as f32 / len;
            -p * p.log2()
        })
        .sum()
}

fn is_placeholder(value: &[u8]) -> bool {
    if value.eq_ignore_ascii_case(REDACTED.as_bytes()) {
        return true;
    }
    if value.len() >= 8 && value.iter().all(|&byte| byte == value[0]) {
        return true;
    }
    [
        b"changeme".as_slice(),
        b"your_secret_here",
        b"your_api_key_here",
        b"replace_me",
        b"example",
        b"xxxxxxxx",
    ]
    .iter()
    .any(|placeholder| value.eq_ignore_ascii_case(placeholder))
}

struct DecodedUtf16 {
    bytes: Vec<u8>,
    little_endian: bool,
}

/// Preserve exact byte spans, including surrogate pairs. Malformed marked text
/// is a scan error rather than a silently truncated or falsely clean result.
fn decode_utf16_bom(source: &[u8]) -> Result<Option<DecodedUtf16>> {
    if source.starts_with(&[0xff, 0xfe, 0, 0]) {
        return Ok(None); // UTF-32 is not supported by this decoder.
    }
    let little = if source.starts_with(&[0xff, 0xfe]) {
        true
    } else if source.starts_with(&[0xfe, 0xff]) {
        false
    } else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    visit_utf16_scalars(source, little, |character, _, _| {
        bytes.extend_from_slice(character.encode_utf8(&mut [0; 4]).as_bytes());
    })?;
    Ok(Some(DecodedUtf16 {
        bytes,
        little_endian: little,
    }))
}

/// Iterate without allocating source maps. Used again only when findings need
/// locations; mapping memory is proportional to findings, not decoded bytes.
fn visit_utf16_scalars(
    source: &[u8],
    little: bool,
    mut visit: impl FnMut(char, usize, usize),
) -> Result<()> {
    ensure!(
        source.len().is_multiple_of(2),
        "malformed UTF-16: incomplete code unit"
    );
    let unit = |offset| {
        let bytes = [source[offset], source[offset + 1]];
        if little {
            u16::from_le_bytes(bytes)
        } else {
            u16::from_be_bytes(bytes)
        }
    };
    let mut at = 2;
    while at < source.len() {
        let start = at;
        let first = unit(at);
        at += 2;
        let scalar = if (0xd800..=0xdbff).contains(&first) {
            ensure!(
                at < source.len(),
                "malformed UTF-16: unpaired high surrogate"
            );
            let second = unit(at);
            ensure!(
                (0xdc00..=0xdfff).contains(&second),
                "malformed UTF-16: unpaired high surrogate"
            );
            at += 2;
            0x10000 + (((first as u32 - 0xd800) << 10) | (second as u32 - 0xdc00))
        } else {
            ensure!(
                !(0xdc00..=0xdfff).contains(&first),
                "malformed UTF-16: unpaired low surrogate"
            );
            first as u32
        };
        // The branches above construct only valid Unicode scalar values.
        let character = char::from_u32(scalar).context("invalid UTF-16 scalar")?;
        visit(character, start, at);
    }
    Ok(())
}

fn map_utf16_findings(source: &[u8], little: bool, findings: &mut [Finding]) -> Result<()> {
    // End boundaries sort before starts at the same offset: an end belongs to
    // the previous scalar and a start belongs to the following scalar.
    let mut boundaries: Vec<_> = findings
        .iter()
        .enumerate()
        .flat_map(|(index, finding)| [(finding.start, true, index), (finding.end, false, index)])
        .collect();
    boundaries.sort_unstable();
    let mut next = 0;
    let mut utf8_offset = 0;
    let mut line = 1;
    let mut line_start = 0;
    visit_utf16_scalars(source, little, |character, source_start, source_end| {
        let utf8_end = utf8_offset + character.len_utf8();
        while let Some(&(offset, is_start, index)) = boundaries.get(next) {
            if offset > utf8_end || (offset == utf8_end && is_start) {
                break;
            }
            if is_start {
                findings[index].start = source_start;
                findings[index].line = line;
                findings[index].column = source_start - line_start;
            } else {
                findings[index].end = source_end;
            }
            next += 1;
        }
        if character == '\n' {
            line += 1;
            line_start = source_end;
        }
        utf8_offset = utf8_end;
    })?;
    Ok(())
}

fn logical_identity(path: &str) -> String {
    Path::new(path)
        .components()
        .filter(|component| !matches!(component, Component::CurDir))
        .collect::<PathBuf>()
        .to_string_lossy()
        .into_owned()
}

// Candidates from the builtin rule arrive in source order. Advance the lexer
// once, retaining only the current visibility and nested macro context.
fn rust_visibility_context(source: &str) -> impl FnMut(usize) -> Option<(usize, usize)> + '_ {
    use ra_ap_rustc_lexer::{FrontmatterAllowed, TokenKind, tokenize};
    let mut tokens = tokenize(source, FrontmatterAllowed::Yes);
    let mut offset = 0;
    let mut last_pub = None;
    let mut groups = Vec::new();
    let mut in_macro = false;
    let mut macro_prefix = false;
    let mut macro_definition = false;
    let mut declaration_depth = None;
    let mut previous_name: Option<&str> = None;
    move |candidate| {
        if candidate < offset {
            return None;
        }
        for token in tokens.by_ref() {
            let start = offset;
            let end = start + token.len as usize;
            let mut code_identifier = false;
            match token.kind {
                TokenKind::Whitespace
                | TokenKind::LineComment { .. }
                | TokenKind::BlockComment { .. } => {}
                TokenKind::Bang => {
                    macro_definition = previous_name == Some("macro_rules");
                    macro_prefix |= previous_name.is_some_and(|name| {
                        !rust_reserved_keyword(name) && !matches!(name, "crate" | "self" | "super")
                    });
                }
                TokenKind::Pound => macro_prefix = true,
                TokenKind::OpenParen | TokenKind::OpenBrace | TokenKind::OpenBracket => {
                    let declaration = declaration_depth == Some(groups.len());
                    if declaration && token.kind == TokenKind::OpenBrace {
                        declaration_depth = None;
                    }
                    groups.push(in_macro);
                    in_macro |= macro_prefix || declaration;
                    macro_prefix = false;
                }
                TokenKind::CloseParen | TokenKind::CloseBrace | TokenKind::CloseBracket => {
                    in_macro = groups.pop().unwrap_or(false);
                    macro_prefix = false;
                }
                TokenKind::Ident | TokenKind::RawIdent if macro_prefix => {
                    macro_prefix = macro_definition;
                    macro_definition = false;
                }
                _ => {
                    code_identifier =
                        !in_macro && matches!(token.kind, TokenKind::Ident | TokenKind::RawIdent);
                    if code_identifier {
                        match &source[start..end] {
                            "pub" => last_pub = Some(start),
                            "macro" => declaration_depth = Some(groups.len()),
                            _ => {}
                        }
                    }
                    if token.kind == TokenKind::Semi && declaration_depth == Some(groups.len()) {
                        declaration_depth = None;
                    }
                    macro_prefix = false;
                }
            }
            match token.kind {
                TokenKind::Whitespace
                | TokenKind::LineComment { .. }
                | TokenKind::BlockComment { .. } => {}
                TokenKind::Ident | TokenKind::RawIdent => previous_name = Some(&source[start..end]),
                _ => previous_name = None,
            }
            offset = end;
            if candidate < end {
                let at_identifier = candidate == start
                    || (token.kind == TokenKind::RawIdent && candidate == start + 2);
                return if code_identifier && at_identifier {
                    last_pub.map(|public| (public, start))
                } else {
                    None
                };
            }
        }
        None
    }
}

fn rust_field_visibility(
    visibility: &Regex,
    bytes: &[u8],
    start: usize,
    field_start: usize,
) -> bool {
    use ra_ap_rustc_lexer::{FrontmatterAllowed, TokenKind, tokenize};
    let Ok(prefix) = std::str::from_utf8(&bytes[start..field_start]) else {
        return false;
    };
    let mut normalized = String::new();
    let mut offset = 0;
    for token in tokenize(prefix, FrontmatterAllowed::Yes) {
        let end = offset + token.len as usize;
        match token.kind {
            TokenKind::Whitespace
            | TokenKind::LineComment { .. }
            | TokenKind::BlockComment { .. } => normalized.push(' '),
            TokenKind::Ident
            | TokenKind::RawIdent
            | TokenKind::OpenParen
            | TokenKind::CloseParen
            | TokenKind::Colon => normalized.push_str(&prefix[offset..end]),
            _ => return false,
        }
        offset = end;
    }
    let Some(captures) = visibility.captures(normalized.trim_end().as_bytes()) else {
        return false;
    };
    let Some(path) = captures.name("path") else {
        return true;
    };
    let Ok(path) = std::str::from_utf8(path.as_bytes()) else {
        return false;
    };
    let global = captures.name("global").is_some();
    let mut super_prefix = !global;
    path.split("::").enumerate().all(|(index, segment)| {
        let segment = segment.trim();
        let root_position = match segment {
            "crate" | "self" => index == 0 && !global,
            "super" => super_prefix,
            _ => true,
        };
        super_prefix &= segment == "super" || (index == 0 && segment == "self");
        if !root_position {
            return false;
        }
        if let Some(raw) = segment.strip_prefix("r#") {
            return !matches!(raw, "crate" | "self" | "super" | "Self");
        }
        !rust_reserved_keyword(segment)
    })
}

// The scanner has no edition setting; keep identifiers legal in Rust 2015.
fn rust_reserved_keyword(segment: &str) -> bool {
    matches!(
        segment,
        "as" | "break"
            | "const"
            | "continue"
            | "else"
            | "enum"
            | "extern"
            | "false"
            | "fn"
            | "for"
            | "if"
            | "impl"
            | "in"
            | "let"
            | "loop"
            | "match"
            | "mod"
            | "move"
            | "mut"
            | "pub"
            | "ref"
            | "return"
            | "Self"
            | "static"
            | "struct"
            | "trait"
            | "true"
            | "type"
            | "unsafe"
            | "use"
            | "where"
            | "while"
            | "abstract"
            | "become"
            | "box"
            | "do"
            | "final"
            | "macro"
            | "override"
            | "priv"
            | "typeof"
            | "unsized"
            | "virtual"
            | "yield"
    )
}

fn configuration_id(rules: &[CompiledRule], config: &EngineConfig) -> Result<String> {
    let actual_rules: Vec<_> = rules
        .iter()
        .map(|rule| (&rule.spec, rule.builtin))
        .collect();
    let settings = (
        &actual_rules,
        config.enable_base64,
        config.min_entropy,
        config.min_confidence,
    );
    let serialized =
        serde_json::to_vec(&settings).context("serializing rule configuration identity")?;
    let mut digest = blake3::Hasher::new();
    digest.update(b"secret-scan/configuration/v11\0");
    digest.update(env!("CARGO_PKG_VERSION").as_bytes());
    digest.update(&(serialized.len() as u64).to_le_bytes());
    digest.update(&serialized);
    if let Some(key) = &config.fingerprint_key {
        digest.update(b"keyed\0");
        digest.update(blake3::keyed_hash(key, b"secret-scan/key-identity/v1").as_bytes());
    } else {
        digest.update(b"unkeyed\0");
    }
    Ok(digest.finalize().to_hex().to_string())
}

/// Walk the source at most once, stopping after the final needed start offset.
/// The only index scales with findings; newline-heavy clean files allocate none.
fn map_byte_findings(source: &[u8], findings: &mut [Finding]) {
    let mut starts: Vec<_> = findings
        .iter()
        .enumerate()
        .map(|(index, finding)| (finding.start, index))
        .collect();
    starts.sort_unstable();
    let (mut at, mut line, mut line_start) = (0, 1, 0);
    for (start, index) in starts {
        while at < start {
            if source[at] == b'\n' {
                line += 1;
                line_start = at + 1;
            }
            at += 1;
        }
        findings[index].line = line;
        findings[index].column = start - line_start;
    }
}

fn surrounding_lines(bytes: &[u8], start: usize, end: usize) -> &[u8] {
    let line_start = bytes[..start]
        .iter()
        .rposition(|&byte| byte == b'\n')
        .map_or(0, |at| at + 1);
    let last = end.saturating_sub(1);
    let line_end = bytes[last..]
        .iter()
        .position(|&byte| byte == b'\n')
        .map_or(bytes.len(), |at| last + at);
    &bytes[line_start..line_end]
}

/// Reject non-value spans in the two contextual catalog rules. Standalone
/// provider-format rules and custom rule IDs retain their matching behavior.
fn assignment_capture_is_non_value(prefix: &[u8], suffix: &[u8]) -> bool {
    let prefix = prefix.trim_ascii_end();
    let quoted_value = matches!(prefix.last(), Some(b'\'' | b'"'));
    if quoted_value
        && suffix.first() == prefix.last()
        && suffix[1..].trim_ascii_start().starts_with(b":")
    {
        // A previous contextual field matched across a comma into the next
        // quoted property name. This span is not its assigned value.
        return true;
    }
    if let Some(comma) = prefix.iter().position(|&byte| byte == b',') {
        // Keep quoted key/value tuples, but do not interpret prose following
        // an ordinary comma as a credential assignment.
        return !quoted_value
            || !matches!(prefix[..comma].trim_ascii_end().last(), Some(b'\'' | b'"'));
    }
    false
}

/// Narrow, heuristic context filter for token-like assignments only. Long prose
/// with clause punctuation is usually explanatory metadata. Password/secret keys
/// and short or unpunctuated natural-language literals deliberately remain findings.
fn token_assignment_is_prose(prefix: &[u8], value: &[u8]) -> bool {
    let Some(delimiter) = prefix.iter().position(|&byte| byte == b'=' || byte == b':') else {
        return false;
    };
    let key: Vec<_> = prefix[..delimiter]
        .iter()
        .copied()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase())
        .collect();
    if ![b"apikey".as_slice(), b"accesstoken", b"authtoken"]
        .iter()
        .any(|suffix| key.ends_with(suffix))
    {
        return false;
    }
    if value
        .split(|byte| byte.is_ascii_whitespace())
        .filter(|word| !word.is_empty())
        .take(8)
        .count()
        < 8
    {
        return false;
    }
    value.iter().enumerate().any(|(at, &byte)| {
        matches!(byte, b',' | b';' | b'.' | b'!' | b'?')
            && value
                .get(at + 1)
                .is_none_or(|next| next.is_ascii_whitespace())
    })
}
