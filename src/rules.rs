//! Rule schema and compilation for the independent detection engine.
use std::{
    collections::{BTreeMap, HashMap},
    fmt,
    path::{Path, PathBuf},
    sync::{Arc, OnceLock},
};

use aho_corasick::AhoCorasick;
use anyhow::{Context, Result, anyhow, ensure};
use regex::{
    Regex,
    bytes::{Regex as BytesRegex, RegexBuilder},
};
use regex_syntax::hir::{Hir, HirKind};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    #[default]
    Medium,
    High,
}

impl fmt::Display for Confidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        })
    }
}

/// Custom JSON rule. Keywords are OR-ed, ASCII-case-insensitive necessary conditions.
/// `secret_group` selects the regex capture whose bytes are redacted/fingerprinted.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSpec {
    pub id: String,
    pub name: String,
    pub pattern: String,
    #[serde(default)]
    pub secret_group: Option<usize>,
    #[serde(default)]
    pub keywords: Vec<String>,
    #[serde(default)]
    pub min_entropy: f32,
    #[serde(default)]
    pub confidence: Confidence,
    #[serde(default)]
    pub path: Option<String>,
    /// OR-ed groups of regex/path/stopword predicates.
    #[serde(default)]
    pub allowlist: Vec<AllowlistSpec>,
    #[serde(default)]
    pub exclude_paths: Vec<String>,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowlistCondition {
    #[default]
    Or,
    And,
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowlistTarget {
    #[default]
    Secret,
    Match,
    Line,
}

/// Within a category, predicates are OR-ed. `condition` combines populated
/// categories; separate groups are always OR-ed. Stopwords target the secret.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AllowlistSpec {
    #[serde(default)]
    pub condition: AllowlistCondition,
    #[serde(default)]
    pub target: AllowlistTarget,
    #[serde(default)]
    pub regexes: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub stopwords: Vec<String>,
}

pub(crate) struct CompiledAllowlist {
    pub condition: AllowlistCondition,
    pub target: AllowlistTarget,
    pub regexes: Vec<Arc<BytesRegex>>,
    pub paths: Vec<Arc<Regex>>,
    pub stopwords: Option<Arc<AhoCorasick>>,
}

impl CompiledAllowlist {
    pub fn matches_path_only(&self, path: &str) -> bool {
        let matched = self.paths.iter().any(|regex| regex.is_match(path));
        matched
            && (matches!(self.condition, AllowlistCondition::Or)
                || (self.regexes.is_empty() && self.stopwords.is_none()))
    }

    pub fn allows(&self, path: &str, secret: &[u8], full_match: &[u8], line: &[u8]) -> bool {
        let target = match self.target {
            AllowlistTarget::Secret => secret,
            AllowlistTarget::Match => full_match,
            AllowlistTarget::Line => line,
        };
        let checks = [
            (!self.paths.is_empty()).then(|| self.paths.iter().any(|regex| regex.is_match(path))),
            (!self.regexes.is_empty())
                .then(|| self.regexes.iter().any(|regex| regex.is_match(target))),
            self.stopwords.as_ref().map(|words| words.is_match(secret)),
        ];
        match self.condition {
            AllowlistCondition::Or => checks.into_iter().flatten().any(|matched| matched),
            AllowlistCondition::And => checks.into_iter().flatten().all(|matched| matched),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RuleInfo {
    pub id: String,
    pub name: String,
    pub confidence: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    rules: Vec<RuleSpec>,
}

pub(crate) struct CompiledRule {
    pub spec: RuleSpec,
    pub builtin: bool,
    pub pattern: BytesRegex,
    pub path: Option<Regex>,
    pub allowlist: Vec<CompiledAllowlist>,
    pub exclude_paths: Vec<Arc<Regex>>,
    keyword_suffix: OnceLock<Option<KeywordSuffix>>,
    explanations: [OnceLock<Arc<str>>; 4],
}

impl CompiledRule {
    pub fn explanation(&self, base64: bool, utf16: bool) -> Arc<str> {
        let index = usize::from(base64) | (usize::from(utf16) << 1);
        Arc::clone(self.explanations[index].get_or_init(|| {
            let base64_suffix = if base64 {
                "; detected inside Base64 content"
            } else {
                ""
            };
            let utf16_suffix = if utf16 {
                "; decoded UTF-16 BOM text"
            } else {
                ""
            };
            format!(
                "Matched {} ({} confidence){base64_suffix}; not live-validated{utf16_suffix}",
                self.spec.name, self.spec.confidence
            )
            .into()
        }))
    }

    pub fn keyword_matches(&self, bytes: &[u8], keyword_start: usize) -> bool {
        self.keyword_suffix
            .get_or_init(|| keyword_suffix(&self.spec.pattern, &self.spec.keywords))
            .as_ref()
            .is_none_or(|suffix| suffix.matches(bytes, keyword_start))
    }
}

#[derive(Debug, PartialEq, Eq)]
struct KeywordSuffix {
    offset: usize,
    literal: Box<[u8]>,
}

impl KeywordSuffix {
    pub fn matches(&self, bytes: &[u8], keyword_start: usize) -> bool {
        keyword_start
            .checked_add(self.offset)
            .and_then(|start| {
                start
                    .checked_add(self.literal.len())
                    .and_then(|end| bytes.get(start..end))
            })
            .is_some_and(|candidate| candidate == self.literal.as_ref())
    }
}

fn keyword_suffix(pattern: &str, keywords: &[String]) -> Option<KeywordSuffix> {
    if keywords.is_empty() || keywords.iter().any(String::is_empty) {
        return None;
    }
    let hir = regex_syntax::ParserBuilder::new()
        .unicode(false)
        .utf8(false)
        .build()
        .parse(pattern)
        .ok()?;
    let mut parts = Vec::new();
    flatten_concat(&hir, &mut parts);
    let mut parts = parts.into_iter();
    let HirKind::Literal(prefix) = parts.next()?.kind() else {
        return None;
    };
    if prefix.0.is_empty()
        || !keywords
            .iter()
            .all(|keyword| keyword.as_bytes().eq_ignore_ascii_case(&prefix.0))
    {
        return None;
    }
    // Every match starts with this keyword and has the same byte width up to
    // the required literal. Thus a real match always supplies an AC hit whose
    // suffix check succeeds. Extra AC hits may pass, but cannot hide a match.
    // Do not descend into alternatives/repetitions to select a literal: their
    // individual children need not occur in every match.
    let mut offset = prefix.0.len();
    for part in parts {
        if let HirKind::Literal(literal) = part.kind()
            && !literal.0.is_empty()
        {
            return Some(KeywordSuffix {
                offset,
                literal: literal.0.clone(),
            });
        }
        let width = part.properties().minimum_len()?;
        if part.properties().maximum_len()? != width {
            return None;
        }
        offset = offset.checked_add(width)?;
    }
    None
}

fn flatten_concat<'a>(hir: &'a Hir, parts: &mut Vec<&'a Hir>) {
    match hir.kind() {
        HirKind::Concat(children) => {
            for child in children {
                flatten_concat(child, parts);
            }
        }
        HirKind::Capture(capture) => flatten_concat(&capture.sub, parts),
        HirKind::Empty | HirKind::Look(_) => {}
        _ => parts.push(hir),
    }
}

pub(crate) fn compile(
    builtin: bool,
    paths: &[PathBuf],
    confidence: Confidence,
) -> Result<Vec<CompiledRule>> {
    let mut specs = BTreeMap::new();
    if builtin {
        let defaults: RuleFile = serde_json::from_str(include_str!("builtin_rules.json"))
            .context("parsing embedded rule catalog")?;
        for rule in defaults
            .rules
            .into_iter()
            .chain(generic_assignment_rules())
            .chain([uri_password_rule()])
        {
            specs.insert(rule.id.clone(), (rule, true));
        }
    }
    for path in paths {
        load_path(path, &mut specs)?;
    }
    let mut compiled = Vec::new();
    let mut shared_allowlists: HashMap<String, Arc<BytesRegex>> = HashMap::new();
    let mut shared_exclusions: HashMap<String, Arc<Regex>> = HashMap::new();
    let mut shared_stopwords: HashMap<Vec<String>, Arc<AhoCorasick>> = HashMap::new();
    for (spec, builtin) in specs
        .into_values()
        .filter(|(rule, _)| rule.confidence >= confidence)
    {
        ensure!(!spec.id.is_empty(), "rule ID must not be empty");
        ensure!(
            spec.min_entropy.is_finite() && (0.0..=8.0).contains(&spec.min_entropy),
            "invalid entropy threshold for rule {}",
            spec.id
        );
        let pattern = RegexBuilder::new(&spec.pattern)
            .unicode(false)
            .build()
            .map_err(|_| {
                anyhow!(
                    "invalid regex syntax or size limit in pattern for rule {}",
                    spec.id
                )
            })?;
        ensure!(
            spec.secret_group
                .is_none_or(|group| group < pattern.captures_len()),
            "capture group missing for rule {}",
            spec.id
        );
        ensure!(
            !pattern.is_match(b""),
            "rule {} matches empty input",
            spec.id
        );
        ensure!(
            spec.keywords.iter().all(|keyword| !keyword.is_empty()),
            "empty keyword for rule {}",
            spec.id
        );
        let path = spec
            .path
            .as_deref()
            .map(Regex::new)
            .transpose()
            .map_err(|_| {
                anyhow!(
                    "invalid regex syntax or size limit in path predicate for rule {}",
                    spec.id
                )
            })?;
        let mut allowlist = Vec::new();
        for group in &spec.allowlist {
            ensure!(
                !group.regexes.is_empty() || !group.paths.is_empty() || !group.stopwords.is_empty(),
                "empty allowlist group for rule {}",
                spec.id
            );
            let mut regexes = Vec::new();
            for expression in &group.regexes {
                let filter = if let Some(filter) = shared_allowlists.get(expression) {
                    Arc::clone(filter)
                } else {
                    let filter = Arc::new(
                        RegexBuilder::new(expression)
                            .unicode(false)
                            .build()
                            .map_err(|_| {
                                anyhow!(
                                    "invalid regex syntax or size limit in allowlist for rule {}",
                                    spec.id
                                )
                            })?,
                    );
                    shared_allowlists.insert(expression.clone(), Arc::clone(&filter));
                    filter
                };
                regexes.push(filter);
            }
            let mut paths = Vec::new();
            for expression in &group.paths {
                let filter = if let Some(filter) = shared_exclusions.get(expression) {
                    Arc::clone(filter)
                } else {
                    let filter = Arc::new(Regex::new(expression).map_err(|_| {
                        anyhow!(
                            "invalid regex syntax or size limit in allowlist path for rule {}",
                            spec.id
                        )
                    })?);
                    shared_exclusions.insert(expression.clone(), Arc::clone(&filter));
                    filter
                };
                paths.push(filter);
            }
            let stopwords = if group.stopwords.is_empty() {
                None
            } else {
                ensure!(
                    group.stopwords.iter().all(|word| !word.is_empty()),
                    "empty stopword for rule {}",
                    spec.id
                );
                let words = if let Some(words) = shared_stopwords.get(&group.stopwords) {
                    Arc::clone(words)
                } else {
                    let words = Arc::new(
                        AhoCorasick::builder()
                            .ascii_case_insensitive(true)
                            .build(&group.stopwords)
                            .map_err(|_| {
                                anyhow!("stopword automaton size limit for rule {}", spec.id)
                            })?,
                    );
                    shared_stopwords.insert(group.stopwords.clone(), Arc::clone(&words));
                    words
                };
                Some(words)
            };
            allowlist.push(CompiledAllowlist {
                condition: group.condition,
                target: group.target,
                regexes,
                paths,
                stopwords,
            });
        }
        let mut exclude_paths = Vec::new();
        for expression in &spec.exclude_paths {
            let filter = if let Some(filter) = shared_exclusions.get(expression) {
                Arc::clone(filter)
            } else {
                let filter = Arc::new(Regex::new(expression).map_err(|_| {
                    anyhow!(
                        "invalid regex syntax or size limit in excluded path for rule {}",
                        spec.id
                    )
                })?);
                shared_exclusions.insert(expression.clone(), Arc::clone(&filter));
                filter
            };
            exclude_paths.push(filter);
        }
        compiled.push(CompiledRule {
            keyword_suffix: OnceLock::new(),
            explanations: std::array::from_fn(|_| OnceLock::new()),
            spec,
            builtin,
            pattern,
            path,
            allowlist,
            exclude_paths,
        });
    }
    ensure!(
        !compiled.is_empty(),
        "no rules selected at the requested confidence"
    );
    Ok(compiled)
}

fn load_path(path: &Path, specs: &mut BTreeMap<String, (RuleSpec, bool)>) -> Result<()> {
    let metadata =
        std::fs::metadata(path).with_context(|| format!("reading rule path {}", path.display()))?;
    if metadata.is_dir() {
        let mut files = std::fs::read_dir(path)?
            .map(|entry| entry.map(|entry| entry.path()))
            .collect::<std::io::Result<Vec<_>>>()?;
        files.sort();
        for file in files {
            // Avoid directory symlink cycles; explicit file symlinks still work.
            let kind = std::fs::symlink_metadata(&file)?.file_type();
            if kind.is_dir()
                || (kind.is_file() && file.extension().is_some_and(|ext| ext == "json"))
            {
                load_path(&file, specs)?;
            }
        }
    } else {
        let bytes =
            std::fs::read(path).with_context(|| format!("reading rules {}", path.display()))?;
        let file: RuleFile = serde_json::from_slice(&bytes).map_err(|error| {
            anyhow!(
                "invalid JSON rule configuration at {}:{}:{} ({:?})",
                path.display(),
                error.line(),
                error.column(),
                error.classify()
            )
        })?;
        for rule in file.rules {
            specs.insert(rule.id.clone(), (rule, false));
        }
    }
    Ok(())
}

/// Independently authored assignment grammar. No entropy floor: weak literal
/// passwords are still credentials. Quoted literals may continue onto the next
/// physical line; blank lines, references and the following JSON key are not values.
fn generic_assignment_rules() -> Vec<RuleSpec> {
    let key = r#"(?im)\b(?:[a-z][a-z0-9_]{0,48}[_-])?(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\b["']?[ \t]*[:=]"#;
    [
        ("double", r#"[ \t]*(?:\r?\n[ \t]*)?"([^"\r\n\\]{4,128})"[ \t]*(?:[,;})\]]|#|//|/\*|\r?$)"#),
        ("single", r"[ \t]*(?:\r?\n[ \t]*)?'([^'\r\n\\]{4,128})'[ \t]*(?:[,;})\]]|#|//|/\*|\r?$)"),
        ("unquoted", r#"[ \t]*([A-Za-z0-9][A-Za-z0-9!@#%^&*_.:/+=~-]{3,127})(?:[ \t]*(?:[,;#]|\r?$))"#),
    ].into_iter().map(|(syntax, value)| RuleSpec {
        id: format!("generic-credential-{syntax}"),
        name: "Literal assigned to a credential key".into(),
        pattern: format!("{key}{value}"),
        secret_group: Some(1),
        keywords: ["password", "passwd", "pwd", "secret", "api", "access", "auth", "client"]
            .into_iter().map(String::from).collect(),
        min_entropy: 0.0,
        confidence: Confidence::Medium,
        path: None,
        allowlist: vec![AllowlistSpec { regexes: [
            r"(?i)^(?:true|false|null|none|undefined)$",
            r"^\s*(?:\$|\{\{|<%|<|%[A-Z_]+%)",
            r"(?i)^(?:process\.env\.|(?:os\.)?environ\b|(?:getenv|env)\b|secrets\.|vars\.)",
            r"(?i)^(?:your[_ -].*|replace[_ -].*|insert[_ -].*|example|sample|dummy|placeholder|redacted|<redacted>)$",
        ].into_iter().map(String::from).chain(
            (syntax == "unquoted").then_some(r"(?i)^config\.[a-z_]\w*(?:\.[a-z_]\w*)*$").into_iter().map(String::from)
        ).collect(), ..Default::default() }],
        exclude_paths: Vec::new(),
    }).collect()
}

/// Independently authored URI authority grammar: capture only a nonempty
/// password between userinfo's colon and @, without decoding source spelling.
fn uri_password_rule() -> RuleSpec {
    RuleSpec {
        id: "uri-userinfo-password".into(),
        name: "Password in URI authority userinfo".into(),
        pattern: r#"(?i)\b(?:postgres(?:ql)?|mysql|https?|rediss?)://[^:/@\s"'<>?#]*:([^/@\s"'<>?#]+)@(?:\[[0-9a-f:]+\]|[a-z0-9][a-z0-9.-]*)"#.into(),
        secret_group: Some(1),
        keywords: ["postgres", "mysql", "http", "redis"].into_iter().map(String::from).collect(),
        min_entropy: 0.0,
        confidence: Confidence::Medium,
        path: None,
        allowlist: vec![AllowlistSpec { regexes: [
            r"^(?:\$|\{\{|%[A-Z_]+%)",
            r"(?i)^(?:process\.env\.|(?:os\.)?environ\b|(?:getenv|env)\b|secrets\.|vars\.)",
            r"(?i)^(?:your[_ -].*|replace[_ -].*|insert[_ -].*|example|sample|dummy|placeholder|redacted|<redacted>)$",
        ].into_iter().map(String::from).collect(), ..Default::default() }],
        exclude_paths: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn suffix(pattern: &str, keywords: &[&str]) -> Option<KeywordSuffix> {
        keyword_suffix(
            pattern,
            &keywords
                .iter()
                .map(|keyword| (*keyword).into())
                .collect::<Vec<_>>(),
        )
    }

    #[test]
    fn keyword_suffix_uses_fixed_byte_offsets() {
        for (pattern, offset) in [
            (r"\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b", 17),
            (r"^((pat)([a-z]{2}))\..*$", 5),
            (r"pat(?:ab|cd)\.x+", 5),
            (r"pat(?u:[αβ])\.x+", 5),
            (r"pat[\x80-\xff]{2}\.x+", 5),
        ] {
            let derived = suffix(pattern, &["pat", "PAT"]).expect(pattern);
            assert_eq!(derived.offset, offset, "{pattern}");
            assert!(derived.literal.starts_with(b"."), "{pattern}");
        }
    }

    #[test]
    fn keyword_suffix_declines_unproven_positions_and_keyword_branches() {
        for (pattern, keywords) in [
            (r"pat[a-z]+\.x", vec!["pat"]),
            (r"pat[a-z]{1,2}\.x", vec!["pat"]),
            (r"pat(?:ab|c)\.x", vec!["pat"]),
            (r"pat(?u:[aα])\.x", vec!["pat"]),
            (r"pat(?:\.[a-z])?", vec!["pat"]),
            (r"pat[0-9]{2}(?:\.x|!y)", vec!["pat"]),
            (r"(?i)pat[a-z]{2}\.x", vec!["pat"]),
            (r"[a-z]pat[a-z]{2}\.x", vec!["pat"]),
            (r"(?:pat|key)[a-z]{2}\.x", vec!["pat", "key"]),
            (r"pat[a-z]{2}\.x", vec!["pat", "context"]),
            (r"pat[a-z]{2}\.x", vec!["pa"]),
            (r"pat[a-z]{2}\.x", vec![]),
            (r"pat[a-z]{2}\.x", vec![""]),
            (r"pat[a-z]{2}", vec!["pat"]),
            (r"[", vec!["pat"]),
        ] {
            assert_eq!(suffix(pattern, &keywords), None, "{pattern} {keywords:?}");
        }
    }

    #[test]
    fn keyword_suffix_checks_bounds_and_exact_literal() {
        let derived = suffix(r"pat[a-z]{2}\.[0-9]+", &["pat"]).unwrap();
        assert!(derived.matches(b"xpatab.123", 1));
        assert!(!derived.matches(b"xpatab!123", 1));
        assert!(!derived.matches(b"xpatab", 1));
        assert!(!derived.matches(b"xpatab.123", usize::MAX));
        assert!(!derived.matches(b"xpatab.123", usize::MAX - derived.offset));
    }
}
