use keyspoor::{Engine, EngineConfig, Finding};
use tempfile::TempDir;

const RULE: &str = r#"{"rules":[{"id":"synthetic.fixture","name":"Synthetic fixture token","pattern":"fixture_([A-Za-z0-9]{24})","secret_group":1,"keywords":["fixture_"],"confidence":"high"}]}"#;
const TOKEN: &str = "Ab3dEf7hIj9kLm2nOp4qRs6t";

fn custom_engine(rule: &str, key: Option<[u8; 32]>) -> (TempDir, Engine) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.json");
    std::fs::write(&path, rule).unwrap();
    let engine = Engine::new(EngineConfig {
        builtin_rules: false,
        custom_rule_paths: vec![path],
        fingerprint_key: key,
        ..Default::default()
    })
    .unwrap();
    (dir, engine)
}

#[test]
fn findings_are_redacted_precise_and_repeatable() {
    let (_dir, engine) = custom_engine(RULE, None);
    let input = format!("first line\n  fixture_{TOKEN}\n");
    let findings = engine.scan_bytes("config.txt", input.as_bytes()).unwrap();
    assert_eq!(findings.len(), 1);
    let found = &findings[0];
    assert_eq!(&input[found.start..found.end], TOKEN);
    assert_eq!((found.line, found.column), (2, 10));
    assert_eq!(found.coordinate_space, "source_bytes");
    assert_eq!(found.redacted, "[REDACTED]");
    assert!(found.explanation.contains("not live-validated"));
    assert!(!serde_json::to_string(&findings).unwrap().contains(TOKEN));
    assert!(!format!("{findings:?}").contains(TOKEN));
    assert_eq!(
        findings,
        engine.scan_bytes("config.txt", input.as_bytes()).unwrap()
    );
    let moved = engine
        .scan_bytes("config.txt", format!("\n{input}").as_bytes())
        .unwrap();
    assert_eq!(found.fingerprint, moved[0].fingerprint);
    assert_eq!(engine.rule_count(), 1);
    assert_eq!(engine.rules()[0].id, "synthetic.fixture");
}

#[test]
fn fingerprints_are_keyed_and_bound_to_path_and_secret() {
    let (_d1, a) = custom_engine(RULE, Some([1; 32]));
    let (_d2, b) = custom_engine(RULE, Some([2; 32]));
    let input = format!("fixture_{TOKEN}");
    let scan = |engine: &Engine, path| {
        engine.scan_bytes(path, input.as_bytes()).unwrap()[0]
            .fingerprint
            .clone()
    };
    assert_ne!(scan(&a, "a"), scan(&b, "a"));
    assert_ne!(scan(&a, "a"), scan(&a, "b"));
    let changed = a
        .scan_bytes("a", b"fixture_Zb3dEf7hIj9kLm2nOp4qRs6t")
        .unwrap();
    assert_ne!(scan(&a, "a"), changed[0].fingerprint);
}

#[test]
fn base64_detection_is_explicit_and_configurable() {
    let (_dir, engine) = custom_engine(RULE, None);
    // Synthetic ASCII fixture encoded once; never a real credential.
    let encoded = b"Zml4dHVyZV9BYjNkRWY3aElqOWtMbTJuT3A0cVJzNnQ=";
    let findings = engine.scan_bytes("encoded.txt", encoded).unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0].is_base64_encoded);
    assert_eq!((findings[0].start, findings[0].end), (0, encoded.len()));
    assert!(!serde_json::to_string(&findings).unwrap().contains(TOKEN));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.json");
    std::fs::write(&path, RULE).unwrap();
    let no_decode = Engine::new(EngineConfig {
        builtin_rules: false,
        custom_rule_paths: vec![path],
        enable_base64: false,
        ..Default::default()
    })
    .unwrap();
    assert!(
        no_decode
            .scan_bytes("encoded.txt", encoded)
            .unwrap()
            .is_empty()
    );
}

#[test]
fn custom_json_rules_obey_path_predicates() {
    let mut json: serde_json::Value = serde_json::from_str(RULE).unwrap();
    json["rules"][0]["path"] = serde_json::json!(r"\.env$");
    let (_dir, engine) = custom_engine(&json.to_string(), None);
    let input = format!("fixture_{TOKEN}");
    assert_eq!(
        engine
            .scan_bytes("settings.env", input.as_bytes())
            .unwrap()
            .len(),
        1
    );
    assert!(
        engine
            .scan_bytes("settings.txt", input.as_bytes())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn invalid_configuration_propagates_errors() {
    assert!(
        Engine::new(EngineConfig {
            builtin_rules: false,
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        Engine::new(EngineConfig {
            custom_rule_paths: vec!["/missing/secret-scan-rules.json".into()],
            ..Default::default()
        })
        .is_err()
    );
    for entropy in [f32::NAN, f32::INFINITY, -1.0, 8.1] {
        assert!(
            Engine::new(EngineConfig {
                min_entropy: Some(entropy),
                ..Default::default()
            })
            .is_err()
        );
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("invalid.json");
    std::fs::write(&path, "{invalid").unwrap();
    assert!(
        Engine::new(EngineConfig {
            builtin_rules: false,
            custom_rule_paths: vec![path.clone()],
            ..Default::default()
        })
        .is_err()
    );
    std::fs::write(&path, RULE.replace("fixture_([A-Za-z0-9]{24})", "(")).unwrap();
    assert!(
        Engine::new(EngineConfig {
            builtin_rules: false,
            custom_rule_paths: vec![path],
            ..Default::default()
        })
        .is_err()
    );
}

#[test]
fn one_compiled_engine_is_safe_for_parallel_calls() {
    let (_dir, engine) = custom_engine(RULE, None);
    let input = format!("fixture_{TOKEN}");
    std::thread::scope(|scope| {
        let workers: Vec<_> = (0..8)
            .map(|_| scope.spawn(|| engine.scan_bytes("same.txt", input.as_bytes()).unwrap()))
            .collect();
        let results: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert!(
            results
                .iter()
                .all(|result| result == &results[0] && result.len() == 1)
        );
    });
}

#[test]
fn finding_defaults_never_contain_unredacted_material() {
    let finding = Finding::default();
    assert_eq!(finding.redacted, "[REDACTED]");
    let roundtrip: Finding =
        serde_json::from_str(&serde_json::to_string(&finding).unwrap()).unwrap();
    assert_eq!(finding, roundtrip);
}

#[test]
fn entropy_allowlist_and_excluded_paths_filter_without_leaking() {
    let mut json: serde_json::Value = serde_json::from_str(RULE).unwrap();
    json["rules"][0]["exclude_paths"] = serde_json::json!(["(^|/)vendor/"]);
    json["rules"][0]["allowlist"] = serde_json::json!([{"regexes":["^Ab3d"]}]);
    let (_dir, engine) = custom_engine(&json.to_string(), None);
    assert!(
        engine
            .scan_bytes("app.txt", format!("fixture_{TOKEN}").as_bytes())
            .unwrap()
            .is_empty()
    );
    assert!(
        engine
            .scan_bytes("vendor/app.txt", b"fixture_Zb3dEf7hIj9kLm2nOp4qRs6t")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        engine
            .scan_bytes("app.txt", b"fixture_Zb3dEf7hIj9kLm2nOp4qRs6t")
            .unwrap()
            .len(),
        1
    );
    json["rules"][0]["min_entropy"] = serde_json::json!(4.0);
    let (_dir, threshold) = custom_engine(&json.to_string(), None);
    assert!(
        threshold
            .scan_bytes("a", b"fixture_aaaaaaaabbbbbbbbcccccccc")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn overlapping_and_case_insensitive_keywords_do_not_drop_rules() {
    let mut json: serde_json::Value = serde_json::from_str(RULE).unwrap();
    json["rules"][0]["keywords"] = serde_json::json!(["TURE", "FIXTURE_"]);
    let (_dir, engine) = custom_engine(&json.to_string(), None);
    assert_eq!(
        engine
            .scan_bytes("a", format!("fixture_{TOKEN}").as_bytes())
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn byte_offsets_and_columns_remain_correct_after_unicode_and_invalid_utf8() {
    let (_dir, engine) = custom_engine(RULE, None);
    let mut input = "你好\nλ ".as_bytes().to_vec();
    input.push(0xff);
    input.extend_from_slice(format!("fixture_{TOKEN}").as_bytes());
    let findings = engine.scan_bytes("binary.dat", &input).unwrap();
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!((finding.line, finding.column), (2, 12));
    assert_eq!(&input[finding.start..finding.end], TOKEN.as_bytes());
}

#[test]
fn embedded_catalog_compiles_and_detects_synthetic_github_fixture() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    assert!(engine.rule_count() >= 200);
    let fixture = b"token = 'ghp_9Zb2Ef7hIj4kLm6nOp8qRs0tUv3wXy5zAbCd'";
    let findings = engine.scan_bytes("config.txt", fixture).unwrap();
    assert!(
        findings
            .iter()
            .any(|finding| finding.rule_id == "github-pat")
    );
    assert!(
        findings
            .iter()
            .all(|finding| finding.redacted == "[REDACTED]")
    );
}

#[test]
fn generic_assignments_find_weak_literals_without_treating_references_as_secrets() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let text =
        b"db_password = 'password'\n\"client_secret\": \"ordinary literal\"\napi_key=short123\n";
    let findings = engine.scan_bytes("settings.txt", text).unwrap();
    let generic: Vec<_> = findings
        .iter()
        .filter(|finding| finding.rule_id.starts_with("generic-credential-"))
        .collect();
    assert_eq!(generic.len(), 3);
    let expected: [&[u8]; 3] = [b"password", b"ordinary literal", b"short123"];
    for (finding, expected) in generic.iter().zip(expected) {
        assert_eq!(&text[finding.start..finding.end], expected);
        assert_eq!(finding.redacted, "[REDACTED]");
    }
    let references = br#"
password = "${DATABASE_PASSWORD}"
password = "{{ secrets.database_password }}"
password = process.env.DATABASE_PASSWORD
password = "your_password_here"
password = "xxxxxxxxxxxx"
password = "redacted"
password = null
password = "env('PASSWORD')"
"#;
    assert!(
        !engine
            .scan_bytes("settings.txt", references)
            .unwrap()
            .iter()
            .any(|finding| finding.rule_id.starts_with("generic-credential-"))
    );
}

#[test]
fn configuration_errors_do_not_echo_secret_bearing_patterns_or_json_values() {
    for field in ["pattern", "path"] {
        let mut json: serde_json::Value = serde_json::from_str(RULE).unwrap();
        json["rules"][0][field] = serde_json::json!("SyntheticSensitiveConfigMarker(");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        std::fs::write(&path, json.to_string()).unwrap();
        let error = Engine::new(EngineConfig {
            builtin_rules: false,
            custom_rule_paths: vec![path],
            ..Default::default()
        })
        .err()
        .unwrap();
        assert!(!format!("{error:#}").contains("SyntheticSensitiveConfigMarker"));
        assert!(!format!("{error:?}").contains("SyntheticSensitiveConfigMarker"));
        assert!(format!("{error}").contains("synthetic.fixture"));
    }
    for field in ["allowlist", "exclude_paths"] {
        let mut json: serde_json::Value = serde_json::from_str(RULE).unwrap();
        json["rules"][0][field] = if field == "allowlist" {
            serde_json::json!([{"regexes":["SyntheticSensitiveConfigMarker("]}])
        } else {
            serde_json::json!(["SyntheticSensitiveConfigMarker("])
        };
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rules.json");
        std::fs::write(&path, json.to_string()).unwrap();
        let error = Engine::new(EngineConfig {
            builtin_rules: false,
            custom_rule_paths: vec![path],
            ..Default::default()
        })
        .err()
        .unwrap();
        assert!(!format!("{error:#?}").contains("SyntheticSensitiveConfigMarker"));
    }
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.json");
    std::fs::write(&path, r#"{"rules":[{"SyntheticSensitiveConfigMarker":1}]}"#).unwrap();
    let error = Engine::new(EngineConfig {
        builtin_rules: false,
        custom_rule_paths: vec![path],
        ..Default::default()
    })
    .err()
    .unwrap();
    assert!(!format!("{error:#?}").contains("SyntheticSensitiveConfigMarker"));
}

#[test]
fn utf16_bom_findings_map_back_to_original_source_bytes_and_columns() {
    let (_dir, engine) = custom_engine(RULE, None);
    let text = format!("emoji 😀\n  fixture_{TOKEN}\n");
    for little in [true, false] {
        let mut source = if little {
            vec![0xff, 0xfe]
        } else {
            vec![0xfe, 0xff]
        };
        source.extend(text.encode_utf16().flat_map(|unit| {
            if little {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            }
        }));
        let findings = engine.scan_bytes("utf16.txt", &source).unwrap();
        assert_eq!(findings.len(), 1);
        let finding = &findings[0];
        assert_eq!((finding.line, finding.column), (2, 20));
        assert_eq!(finding.coordinate_space, "source_bytes");
        let expected: Vec<_> = TOKEN
            .encode_utf16()
            .flat_map(|unit| {
                if little {
                    unit.to_le_bytes()
                } else {
                    unit.to_be_bytes()
                }
            })
            .collect();
        assert_eq!(&source[finding.start..finding.end], expected);
        assert_eq!(finding.end - finding.start, 48);
    }
}

#[test]
fn malformed_utf16_is_an_error_and_base64_inside_utf16_retains_source_spans() {
    let (_dir, engine) = custom_engine(RULE, None);
    for bytes in [
        &[0xff, 0xfe, 1][..],
        &[0xff, 0xfe, 0, 0xd8],
        &[0xfe, 0xff, 0xdc, 0],
    ] {
        assert!(engine.scan_bytes("broken.txt", bytes).is_err());
    }
    let encoded = "Zml4dHVyZV9BYjNkRWY3aElqOWtMbTJuT3A0cVJzNnQ=";
    let source: Vec<_> = [0xff, 0xfe]
        .into_iter()
        .chain(encoded.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let findings = engine.scan_bytes("encoded.txt", &source).unwrap();
    assert_eq!(findings.len(), 1);
    assert!(findings[0].is_base64_encoded);
    assert_eq!((findings[0].start, findings[0].end), (2, source.len()));
}

#[test]
fn replacing_a_credential_with_our_redaction_marker_is_idempotent() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let original = b"password = 'weak-passphrase'\n";
    let findings = engine.scan_bytes("settings.txt", original).unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding.rule_id.starts_with("generic-credential-"))
        .unwrap();
    let mut repaired = original[..finding.start].to_vec();
    repaired.extend_from_slice(finding.redacted.as_bytes());
    repaired.extend_from_slice(&original[finding.end..]);
    assert!(
        engine
            .scan_bytes("settings.txt", &repaired)
            .unwrap()
            .is_empty()
    );
    assert!(
        engine
            .scan_bytes("settings.txt", b"password = '[redacted]'\n")
            .unwrap()
            .is_empty()
    );
}

#[test]
fn utf16_sparse_mapping_preserves_overlapping_and_adjacent_surrogate_boundaries() {
    let rules = serde_json::json!({"rules": [
        {"id":"before","name":"Before","pattern":"(α😀)","secret_group":1},
        {"id":"after","name":"After","pattern":"(β)","secret_group":1},
        {"id":"overlap","name":"Overlap","pattern":"(😀β)","secret_group":1},
        {"id":"byte","name":"Byte within surrogate","pattern":r"(\x9F)","secret_group":1}
    ]});
    let (_dir, engine) = custom_engine(&rules.to_string(), None);
    for little in [true, false] {
        let text = "\nα😀β";
        let mut source = if little {
            vec![0xff, 0xfe]
        } else {
            vec![0xfe, 0xff]
        };
        source.extend(text.encode_utf16().flat_map(|unit| {
            if little {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            }
        }));
        let findings = engine.scan_bytes("unicode.txt", &source).unwrap();
        assert_eq!(findings.len(), 4);
        for (id, start, end, column) in [
            ("before", 4, 10, 0),
            ("after", 10, 12, 6),
            ("overlap", 6, 12, 2),
            ("byte", 6, 10, 2),
        ] {
            let finding = findings
                .iter()
                .find(|finding| finding.rule_id == id)
                .unwrap();
            assert_eq!(
                (finding.start, finding.end, finding.line, finding.column),
                (start, end, 2, column)
            );
        }
    }
}

#[test]
fn clean_utf16_does_not_require_a_source_map() {
    let (_dir, engine) = custom_engine(RULE, None);
    let source: Vec<_> = [0xff, 0xfe]
        .into_iter()
        .chain(
            "ordinary text 😀\n"
                .encode_utf16()
                .flat_map(u16::to_le_bytes),
        )
        .collect();
    assert!(engine.scan_bytes("clean.txt", &source).unwrap().is_empty());
}

#[test]
fn multiline_assignment_only_accepts_an_immediately_following_quoted_literal() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for text in [
        "service_password =\n  'pear-otter-42'\n",
        "\"auth_token\":\r\n\t\"walnut.badger.73\",\r\n",
    ] {
        let findings = engine
            .scan_bytes("continuation.txt", text.as_bytes())
            .unwrap();
        let found: Vec<_> = findings
            .iter()
            .filter(|finding| {
                finding.rule_id.starts_with("generic-credential-")
                    || finding
                        .matched_rule_ids
                        .iter()
                        .any(|id| id.starts_with("generic-credential-"))
            })
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].line, 2);
        assert!(matches!(
            &text[found[0].start..found[0].end],
            "pear-otter-42" | "walnut.badger.73"
        ));
    }
    for text in [
        "password =\n\n 'remote-literal'\n",
        "password =\n process.env.DB_PASSWORD\n",
        "password =\n nextVariable\n",
        "\"password\":\n \"next_property\": \"ordinary text\"\n",
        "password =\n \"${DB_PASSWORD}\"\n",
        "password =\n 'literal' + suffix\n",
    ] {
        assert!(
            !engine
                .scan_bytes("continuation.txt", text.as_bytes())
                .unwrap()
                .iter()
                .any(|finding| finding.rule_id.starts_with("generic-credential-")),
            "unexpected literal match"
        );
    }
}

#[test]
fn uri_passwords_have_exact_spans_across_schemes_and_encoded_characters() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for (uri, password) in [
        (
            "postgresql://reader:walnut-pony-71@db.internal:5432/app",
            "walnut-pony-71",
        ),
        (
            "postgres://writer:cedar_otter_82@[::1]/app",
            "cedar_otter_82",
        ),
        ("mysql://guest:elm.quail.53@localhost/data", "elm.quail.53"),
        (
            "https://viewer:p%40ss%3Aphrase@service.invalid/api",
            "p%40ss%3Aphrase",
        ),
        ("http://viewer:q@service.invalid/", "q"),
        (
            "redis://:maple-heron-64@cache.internal:6379/0",
            "maple-heron-64",
        ),
        (
            "rediss://default:birch.finch.95@cache.internal/1",
            "birch.finch.95",
        ),
    ] {
        let text = format!("connection = \"{uri}\"\n");
        let findings = engine
            .scan_bytes("connections.conf", text.as_bytes())
            .unwrap();
        let found: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule_id == "uri-userinfo-password")
            .collect();
        assert_eq!(found.len(), 1);
        assert_eq!(&text[found[0].start..found[0].end], password);
        assert_eq!(found[0].redacted, "[REDACTED]");
    }
}

#[test]
fn uri_userinfo_without_literal_password_is_not_a_secret() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for uri in [
        "http://service.invalid/docs",
        "https://viewer@service.invalid/",
        "mysql://guest:@localhost/db",
        "redis://:${REDIS_PASSWORD}@localhost/0",
        "postgres://user:$DB_PASSWORD@localhost/db",
        "http://viewer:process.env.PASSWORD@service.invalid/",
        "redis://:[REDACTED]@localhost/0",
        "http://service.invalid/path:unrelated@next",
        "mysql://user:{{ vault.password }}@localhost/db",
    ] {
        assert!(
            !engine
                .scan_bytes("connections.conf", uri.as_bytes())
                .unwrap()
                .iter()
                .any(|finding| finding.rule_id == "uri-userinfo-password")
        );
    }
}

#[test]
fn quoted_assignments_allow_comments_and_closing_call_parentheses() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for quote in ['\'', '"'] {
        for ending in [
            " # trailing comment",
            " // trailing comment",
            " /* trailing comment */",
            ")",
        ] {
            let text = format!("configure(password={quote}spruce-wren-26{quote}{ending}\n");
            let findings = engine.scan_bytes("source.txt", text.as_bytes()).unwrap();
            let generic: Vec<_> = findings
                .iter()
                .filter(|finding| finding.rule_id.starts_with("generic-credential-"))
                .collect();
            assert_eq!(generic.len(), 1, "quoted assignment ending was omitted");
            assert_eq!(&text[generic[0].start..generic[0].end], "spruce-wren-26");
        }
    }
}

#[test]
fn generic_token_explanation_context_does_not_hide_natural_language_passwords() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let prose = "This detector accepts literal values, but excludes descriptions that explain its matching behavior";
    let metadata = format!("\"generic-api-key\": \"{prose}\",\n");
    assert!(
        !engine
            .scan_bytes("rules.py", metadata.as_bytes())
            .unwrap()
            .iter()
            .any(|finding| finding.rule_id.starts_with("generic-credential-"))
    );
    for key in ["password", "passwd", "pwd", "secret", "client_secret"] {
        let input = format!("{key} = \"{prose}\"\n");
        assert!(
            engine
                .scan_bytes("README.md", input.as_bytes())
                .unwrap()
                .iter()
                .any(|finding| finding.rule_id.starts_with("generic-credential-"))
        );
    }
    for value in [
        "a small natural phrase",
        "one two three four five six seven eight nine ten",
        "one two, three four",
    ] {
        let input = format!("api_key = '{value}'\n");
        assert!(
            engine
                .scan_bytes("README.md", input.as_bytes())
                .unwrap()
                .iter()
                .any(|finding| finding.rule_id.starts_with("generic-credential-"))
        );
    }
}

#[test]
fn capture_selection_supports_alternatives_empty_groups_and_explicit_whole_match() {
    for (pattern, group, input, expected) in [
        (
            r"alpha_([A-Z]{4})|beta_([A-Z]{4})",
            serde_json::Value::Null,
            "beta_QWER",
            "QWER",
        ),
        (r"()([A-Z]{4})", serde_json::Value::Null, "QWER", "QWER"),
        (
            r"whole_[A-Z]{4}",
            serde_json::Value::Null,
            "whole_QWER",
            "whole_QWER",
        ),
        (
            r"whole_([A-Z]{4})",
            serde_json::json!(0),
            "whole_QWER",
            "whole_QWER",
        ),
        (
            r"whole_([A-Z]{4})",
            serde_json::json!(1),
            "whole_QWER",
            "QWER",
        ),
    ] {
        let rules = serde_json::json!({"rules":[{"id":"capture","name":"Capture","pattern":pattern,"secret_group":group}]});
        let (_dir, engine) = custom_engine(&rules.to_string(), None);
        let findings = engine.scan_bytes("a", input.as_bytes()).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(&input[findings[0].start..findings[0].end], expected);
    }
}

#[test]
fn allowlist_targets_and_boolean_groups_preserve_conjunctions() {
    let make = |group: serde_json::Value| {
        let rules = serde_json::json!({"rules":[{"id":"allow","name":"Allow","pattern":"token=([A-Za-z0-9-]+)","secret_group":1,"allowlist":[group]}]});
        custom_engine(&rules.to_string(), None)
    };
    let (_dir, engine) = make(
        serde_json::json!({"condition":"and","target":"line","paths":["\\.recipe$"],"regexes":["LICENSE"]}),
    );
    for (path, source, count) in [
        ("a.recipe", "LICENSE token=Value42", 0),
        ("a.txt", "LICENSE token=Value42", 1),
        ("a.recipe", "NORMAL token=Value42", 1),
        ("a.txt", "NORMAL token=Value42", 1),
        ("a.recipe", "LICENSE\ntoken=Value42", 1),
    ] {
        assert_eq!(
            engine.scan_bytes(path, source.as_bytes()).unwrap().len(),
            count
        );
    }
    let (_dir, engine) = make(
        serde_json::json!({"condition":"or","target":"match","paths":["\\.recipe$"],"regexes":["^token=Value"]}),
    );
    assert!(
        engine
            .scan_bytes("a.txt", b"token=Value42")
            .unwrap()
            .is_empty()
    );
    assert!(
        engine
            .scan_bytes("a.recipe", b"token=Other42")
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        engine.scan_bytes("a.txt", b"token=Other42").unwrap().len(),
        1
    );
    let (_dir, engine) = make(
        serde_json::json!({"condition":"and","target":"match","regexes":["^token="],"stopwords":["value"]}),
    );
    assert!(engine.scan_bytes("a", b"token=VaLuE42").unwrap().is_empty());
    assert_eq!(engine.scan_bytes("a", b"token=Other42").unwrap().len(), 1);
    // Stopwords must not inspect the prefix/full match when their target is match.
    let (_dir, engine) = make(serde_json::json!({"target":"match","stopwords":["token"]}));
    assert_eq!(engine.scan_bytes("a", b"token=Other42").unwrap().len(), 1);
    let (_dir, engine) = make(serde_json::json!({"target":"secret","regexes":["^token="]}));
    assert_eq!(engine.scan_bytes("a", b"token=Other42").unwrap().len(), 1);
}

#[test]
fn identity_is_separate_from_display_path_and_lexical_paths_are_stable() {
    let mut rules: serde_json::Value = serde_json::from_str(RULE).unwrap();
    rules["rules"][0]["path"] = serde_json::json!(r"\.env$");
    let (_dir, engine) = custom_engine(&rules.to_string(), None);
    let input = format!("fixture_{TOKEN}");
    let first = engine.scan_bytes("config.env", input.as_bytes()).unwrap();
    let dotted = engine.scan_bytes("./config.env", input.as_bytes()).unwrap();
    assert_eq!(first[0].fingerprint, dotted[0].fingerprint);
    assert_eq!(dotted[0].path.as_ref(), "./config.env");
    let a = engine
        .scan_bytes_with_identity("config.env", "checkout-a/config.env", input.as_bytes())
        .unwrap();
    let b = engine
        .scan_bytes_with_identity("config.env", "checkout-b/config.env", input.as_bytes())
        .unwrap();
    assert_ne!(a[0].fingerprint, b[0].fingerprint);
    let same_identity = engine
        .scan_bytes_with_identity("alternate.env", "checkout-a/config.env", input.as_bytes())
        .unwrap();
    assert_eq!(a[0].fingerprint, same_identity[0].fingerprint);
    assert_eq!(same_identity[0].path.as_ref(), "alternate.env");
    assert!(
        engine
            .scan_bytes_with_identity("excluded.txt", "config.env", input.as_bytes())
            .unwrap()
            .is_empty()
    );
}

#[test]
fn configuration_identity_tracks_actual_rules_semantics_and_key_identity() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.json");
    std::fs::write(&path, RULE).unwrap();
    let config = EngineConfig {
        builtin_rules: false,
        custom_rule_paths: vec![path.clone()],
        ..Default::default()
    };
    let first = Engine::new(config.clone()).unwrap();
    assert_eq!(first.configuration_id().len(), 64);
    assert!(!first.configuration_id().contains("fixture"));
    let formatted: serde_json::Value = serde_json::from_str(RULE).unwrap();
    std::fs::write(&path, serde_json::to_string_pretty(&formatted).unwrap()).unwrap();
    assert_eq!(
        first.configuration_id(),
        Engine::new(config.clone()).unwrap().configuration_id()
    );
    for changed in [
        EngineConfig {
            enable_base64: false,
            ..config.clone()
        },
        EngineConfig {
            min_entropy: Some(1.0),
            ..config.clone()
        },
        EngineConfig {
            min_confidence: keyspoor::rules::Confidence::High,
            ..config.clone()
        },
        EngineConfig {
            fingerprint_key: Some([17; 32]),
            ..config.clone()
        },
        EngineConfig {
            fingerprint_key: Some([18; 32]),
            ..config.clone()
        },
    ] {
        assert_ne!(
            first.configuration_id(),
            Engine::new(changed).unwrap().configuration_id()
        );
    }
    for field in ["pattern", "allowlist", "exclude_paths", "secret_group"] {
        let mut changed = formatted.clone();
        changed["rules"][0][field] = match field {
            "pattern" => serde_json::json!("fixture_([A-Za-z0-9]{23,24})"),
            "allowlist" => serde_json::json!([{"regexes":["NeverAllowThis"]}]),
            "exclude_paths" => serde_json::json!(["never-match-path"]),
            _ => serde_json::json!(0),
        };
        std::fs::write(&path, changed.to_string()).unwrap();
        assert_ne!(
            first.configuration_id(),
            Engine::new(config.clone()).unwrap().configuration_id()
        );
    }
    let mut rules = formatted["rules"].as_array().unwrap().clone();
    let mut other = rules[0].clone();
    other["id"] = serde_json::json!("a-second-rule");
    rules.push(other);
    let collection = |rules| serde_json::json!({"rules":rules});
    std::fs::write(&path, collection(rules.clone()).to_string()).unwrap();
    let ordered = Engine::new(config.clone()).unwrap();
    rules.reverse();
    std::fs::write(&path, collection(rules).to_string()).unwrap();
    assert_eq!(
        ordered.configuration_id(),
        Engine::new(config).unwrap().configuration_id()
    );
}

#[test]
fn sparse_line_mapping_handles_out_of_order_rules_crlf_binary_and_base64() {
    let (_dir, engine) = custom_engine(RULE, None);
    let encoded = b"Zml4dHVyZV9BYjNkRWY3aElqOWtMbTJuT3A0cVJzNnQ=";
    let mut source = vec![b'\n'; 16384];
    source.extend_from_slice(b"\xff\r\n  ");
    let encoded_start = source.len();
    source.extend_from_slice(encoded);
    source.extend_from_slice(b"\r\n\xff ");
    let raw_start = source.len() + 8;
    source.extend_from_slice(format!("fixture_{TOKEN}").as_bytes());
    let findings = engine.scan_bytes("data.bin", &source).unwrap();
    assert_eq!(findings.len(), 2);
    assert_eq!(
        (findings[0].start, findings[0].line, findings[0].column),
        (encoded_start, 16386, 2)
    );
    assert_eq!(
        (findings[1].start, findings[1].line, findings[1].column),
        (raw_start, 16387, 10)
    );
    assert!(findings[0].is_base64_encoded);
}

#[test]
fn airtable_tokens_are_detected_without_provider_context() {
    let engine = Engine::new(EngineConfig {
        enable_base64: false,
        ..Default::default()
    })
    .unwrap();
    // Constructed format-only fixtures; never issued credentials.
    let first = format!("patAb3dEf7hIj9kLm.{}", "0123456789abcdef".repeat(4));
    let second = format!("patN2pQ4rS6tU8vW0.{}", "f0e1d2c3b4a59687".repeat(4));
    for (source, expected) in [
        (first.clone(), vec![first.as_str()]),
        (
            format!("const left = \"{first}\"; const right = \"{second}\";\n"),
            vec![first.as_str(), second.as_str()],
        ),
        (
            format!("const left = \"{first}\"; const right = \"{first}\";\n"),
            vec![first.as_str(), first.as_str()],
        ),
    ] {
        assert!(!source.to_ascii_lowercase().contains("airtable"));
        let findings = engine
            .scan_bytes("settings.conf", source.as_bytes())
            .unwrap();
        assert_eq!(findings.len(), expected.len());
        for (finding, value) in findings.iter().zip(expected) {
            assert_eq!(finding.rule_id, "airtable-personnal-access-token");
            assert_eq!(&source[finding.start..finding.end], value);
        }
        assert!(findings.windows(2).all(|pair| pair[0].end < pair[1].start));
    }
}

#[test]
fn airtable_provider_detection_survives_generic_stopword_substrings() {
    let engine = Engine::new(EngineConfig {
        enable_base64: false,
        ..Default::default()
    })
    .unwrap();
    // `feed` is a generic-api-key stopword but valid hexadecimal token content.
    let token = format!("patAb3dEf7hIj9kLm.feed{}", "0123456789ab".repeat(5));
    let source = format!("runtime:\n  credential: \"{token}\"\n");
    let findings = engine
        .scan_bytes("settings.yaml", source.as_bytes())
        .unwrap();
    assert_eq!(findings.len(), 1);
    let finding = &findings[0];
    assert_eq!(finding.rule_id, "airtable-personnal-access-token");
    assert_eq!(&source[finding.start..finding.end], token);
    assert_eq!((finding.line, finding.column), (2, 15));
    assert!(
        !finding
            .matched_rule_ids
            .iter()
            .any(|id| id == "generic-api-key")
    );
}

#[test]
fn airtable_keyword_gate_does_not_accept_malformed_tokens() {
    let engine = Engine::new(EngineConfig {
        enable_base64: false,
        ..Default::default()
    })
    .unwrap();
    let suffix = "0123456789abcdef".repeat(4);
    for malformed in [
        format!("patAb3dEf7hIj9kL.{suffix}"),
        format!("patAb3dEf7hIj9kLmN.{suffix}"),
        format!("patAb3dEf7hIj9kLm.{}", &suffix[..63]),
        format!("patAb3dEf7hIj9kLm.{suffix}0"),
        format!("patAb3dEf7hIj9kLm.g{}", &suffix[1..]),
        format!("patAb3dEf7hIj9kLm_{suffix}"),
        format!("xpatAb3dEf7hIj9kLm.{suffix}"),
        "pat".to_owned(),
    ] {
        assert!(
            engine
                .scan_bytes("settings.conf", malformed.as_bytes())
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn restored_catalog_detectors_cover_nonfirst_capture_branches() {
    let engine = Engine::new(EngineConfig {
        enable_base64: false,
        ..Default::default()
    })
    .unwrap();
    let atlassian_first = "q7r2s8t3u9v4w5x6y1z0a1b2";
    let atlassian_second = format!("ATATT3{}cD4_EF", "aB9_xY7-zQ2=".repeat(15));
    for token in [atlassian_first, atlassian_second.as_str()] {
        let source = format!("ATLASSIAN_TOKEN='{token}'\n");
        let findings = engine
            .scan_bytes("providers.conf", source.as_bytes())
            .unwrap();
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "atlassian-api-token")
            .unwrap();
        assert_eq!(&source[finding.start..finding.end], token);
    }
    let token = "zR8kN2pV7mB3xQ6tY4hL9jF5";
    let source = format!("curl -H 'X-Api-Key: {token}' https://service.invalid\n");
    let findings = engine.scan_bytes("example.sh", source.as_bytes()).unwrap();
    let finding = findings
        .iter()
        .find(|finding| finding.rule_id == "curl-auth-header")
        .unwrap();
    assert_eq!(&source[finding.start..finding.end], token);
}

#[test]
fn restored_kubernetes_rule_preserves_full_match_allowlist() {
    let engine = Engine::new(EngineConfig {
        enable_base64: false,
        ..Default::default()
    })
    .unwrap();
    let entry = "password: Y2VkYXItb3R0ZXItNzQ=";
    for source in [
        format!("kind: Secret\ndata:\n  {entry}\n"),
        format!("data:\n  {entry}\nkind: Secret\n"),
    ] {
        let findings = engine
            .scan_bytes("manifest.yml", source.as_bytes())
            .unwrap();
        let finding = findings
            .iter()
            .find(|finding| finding.rule_id == "kubernetes-secret-yaml")
            .unwrap();
        assert_eq!(&source[finding.start..finding.end], entry);
    }
    // The pinned upstream expression requires content between the separator
    // and data. An immediately adjacent `---\ndata:` is an upstream limitation,
    // not a guarantee supplied by the target-selection implementation.
    let source = format!("kind: Secret\n---\nmetadata: {{}}\ndata:\n  {entry}\n");
    assert!(
        !engine
            .scan_bytes("manifest.yml", source.as_bytes())
            .unwrap()
            .iter()
            .any(|finding| finding.rule_id == "kubernetes-secret-yaml")
    );
}

fn overlapping_rule_engine() -> (TempDir, Engine) {
    custom_engine(
        r#"{"rules":[
        {"id":"generic-a","name":"Generic high confidence","pattern":"fixture_([A-Za-z0-9]{24})","secret_group":1,"confidence":"high"},
        {"id":"provider-z","name":"Provider medium confidence","pattern":"fixture_([A-Za-z0-9]{24})","secret_group":1,"confidence":"medium"},
        {"id":"provider-b","name":"Provider high confidence B","pattern":"fixture_([A-Za-z0-9]{24})","secret_group":1,"confidence":"high"},
        {"id":"provider-a","name":"Provider high confidence A","pattern":"fixture_([A-Za-z0-9]{24})","secret_group":1,"confidence":"high"}
    ]}"#,
        None,
    )
}

#[test]
fn exact_span_merge_prefers_specific_confident_rule_and_retains_sorted_evidence() {
    let (_dir, engine) = overlapping_rule_engine();
    let input = format!("fixture_{TOKEN}");
    let findings = engine.scan_bytes("settings", input.as_bytes()).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].rule_id, "provider-a");
    assert_eq!(
        findings[0].matched_rule_ids,
        ["generic-a", "provider-a", "provider-b", "provider-z"]
    );
    let (_single_dir, single) = custom_engine(
        r#"{"rules":[{"id":"provider-a","name":"Provider high confidence A","pattern":"fixture_([A-Za-z0-9]{24})","secret_group":1,"confidence":"high"}]}"#,
        None,
    );
    let original = single.scan_bytes("settings", input.as_bytes()).unwrap();
    assert_eq!(original[0].fingerprint, findings[0].fingerprint);
    assert!(original[0].matched_rule_ids.is_empty());
    assert!(
        !serde_json::to_string(&original)
            .unwrap()
            .contains("matched_rule_ids")
    );
    assert!(!serde_json::to_string(&findings).unwrap().contains(TOKEN));
}

#[test]
fn exact_span_merge_preserves_adjacent_equal_and_different_values_and_partial_overlaps() {
    let (_dir, engine) = overlapping_rule_engine();
    let input = format!("fixture_{TOKEN} fixture_{TOKEN} fixture_Zb3dEf7hIj9kLm2nOp4qRs6t");
    let findings = engine.scan_bytes("settings", input.as_bytes()).unwrap();
    assert_eq!(findings.len(), 3);
    assert_eq!(findings[0].fingerprint, findings[1].fingerprint);
    assert_ne!(findings[1].fingerprint, findings[2].fingerprint);
    assert!(findings.windows(2).all(|pair| pair[0].end < pair[1].start));
    let (_other_dir, other) = custom_engine(
        r#"{"rules":[
        {"id":"whole","name":"Whole value","pattern":"fixture_([A-Za-z0-9]{24})","secret_group":1},
        {"id":"part","name":"Part value","pattern":"fixture_([A-Za-z0-9]{12})","secret_group":1}
    ]}"#,
        None,
    );
    assert_eq!(
        other
            .scan_bytes("settings", format!("fixture_{TOKEN}").as_bytes())
            .unwrap()
            .len(),
        2
    );
}

#[test]
fn base64_merge_preserves_equal_values_at_distinct_decoded_positions_and_source_layers() {
    use base64::{Engine as _, engine::general_purpose};
    let (_dir, engine) = overlapping_rule_engine();
    let encoded = general_purpose::STANDARD.encode(format!("fixture_{TOKEN} fixture_{TOKEN}"));
    let input = format!("fixture_{TOKEN}\n{encoded}");
    let findings = engine.scan_bytes("settings", input.as_bytes()).unwrap();
    assert_eq!(findings.len(), 3);
    assert!(!findings[0].is_base64_encoded);
    assert!(findings[1..].iter().all(|f| f.is_base64_encoded
        && f.start == input.len() - encoded.len()
        && f.end == input.len()));
    assert_eq!(findings[1].fingerprint, findings[2].fingerprint);
    assert_eq!(findings[1].matched_rule_ids.len(), 4);
}

#[test]
fn merged_utf16_findings_retain_exact_source_coordinates() {
    let (_dir, engine) = overlapping_rule_engine();
    let input = format!("雪🦀\r\nfixture_{TOKEN}");
    let bytes: Vec<u8> = [0xff, 0xfe]
        .into_iter()
        .chain(input.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    let findings = engine.scan_bytes("settings", &bytes).unwrap();
    assert_eq!(findings.len(), 1);
    assert_eq!(
        (
            findings[0].start,
            findings[0].end,
            findings[0].line,
            findings[0].column
        ),
        (28, 76, 2, 16)
    );
    assert_eq!(findings[0].matched_rule_ids.len(), 4);
}

#[test]
fn engine_semantics_change_configuration_identity_from_previous_versions() {
    let (_dir, engine) = custom_engine(RULE, None);
    let value: serde_json::Value = serde_json::from_str(RULE).unwrap();
    let rules: Vec<keyspoor::rules::RuleSpec> =
        serde_json::from_value(value["rules"].clone()).unwrap();
    let config = EngineConfig::default();
    let serialized = serde_json::to_vec(&(
        &rules,
        config.enable_base64,
        config.min_entropy,
        config.min_confidence,
    ))
    .unwrap();
    for previous in [
        b"secret-scan/configuration/v2\0",
        b"secret-scan/configuration/v3\0",
        b"secret-scan/configuration/v4\0",
        b"secret-scan/configuration/v5\0",
    ] {
        let mut old = blake3::Hasher::new();
        old.update(previous);
        old.update(env!("CARGO_PKG_VERSION").as_bytes());
        old.update(&(serialized.len() as u64).to_le_bytes());
        old.update(&serialized);
        old.update(b"unkeyed\0");
        assert_ne!(engine.configuration_id(), old.finalize().to_hex().as_str());
    }
    // Version 6 also encoded whether each rule came from the builtin catalog.
    let actual_rules: Vec<_> = rules.iter().map(|rule| (rule, false)).collect();
    let serialized = serde_json::to_vec(&(
        &actual_rules,
        config.enable_base64,
        config.min_entropy,
        config.min_confidence,
    ))
    .unwrap();
    for previous in [
        b"secret-scan/configuration/v6\0",
        b"secret-scan/configuration/v7\0",
        b"secret-scan/configuration/v8\0",
        b"secret-scan/configuration/v9\0",
    ] {
        let mut old = blake3::Hasher::new();
        old.update(previous);
        old.update(env!("CARGO_PKG_VERSION").as_bytes());
        old.update(&(serialized.len() as u64).to_le_bytes());
        old.update(&serialized);
        old.update(b"unkeyed\0");
        assert_ne!(engine.configuration_id(), old.finalize().to_hex().as_str());
    }
}

#[test]
fn single_and_multiple_candidate_paths_have_identical_plain_base64_and_utf16_findings() {
    use base64::{Engine as _, engine::general_purpose};
    let (_single_dir, single) = custom_engine(RULE, None);
    let mut config: serde_json::Value = serde_json::from_str(RULE).unwrap();
    // An unconditional, nonmatching rule forces the general merge path without
    // changing detection evidence or primary rule selection.
    config["rules"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({
            "id": "unconditional-control", "name": "Nonmatching control",
            "pattern": "NEVER_MATCH_CONTROL", "confidence": "high"
        }));
    let (_multiple_dir, multiple) = custom_engine(&config.to_string(), None);
    let encoded = general_purpose::STANDARD.encode(format!("fixture_{TOKEN} fixture_{TOKEN}"));
    let text = format!("雪🦀\r\nfixture_{TOKEN} fixture_{TOKEN}\n{encoded}\n");
    let utf16: Vec<_> = [0xff, 0xfe]
        .into_iter()
        .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    for bytes in [text.as_bytes(), utf16.as_slice()] {
        let fast = single.scan_bytes("settings", bytes).unwrap();
        let general = multiple.scan_bytes("settings", bytes).unwrap();
        assert_eq!(fast.len(), 4);
        assert_eq!(fast, general);
    }
}

#[test]
fn fixed_offset_keyword_gate_matches_unconditional_regex() {
    let cases: &[(&str, &[&str], &str)] = &[
        (
            r"\b(pat[A-Za-z0-9]{3}\.[a-f0-9]{8})\b",
            &["pat"],
            "patAb3.1a2b3c4d",
        ),
        (r"(pat)([A-Z]{2})::([0-9]{4,})", &["pat"], "patAZ::12345"),
        (r"pat(?:AB|CD)\.[a-f0-9]{8}", &["pat"], "patCD.1a2b3c4d"),
        (r"pat[A-Z]+\.[a-f0-9]{8}", &["pat"], "patABCDE.1a2b3c4d"),
        (
            r"(?:pat|key)[A-Z]{2}\.[a-f0-9]{8}",
            &["pat", "key"],
            "keyAZ.1a2b3c4d",
        ),
        (r"(?i:pat)[A-Z]{2}\.[a-f0-9]{8}", &["pat"], "PaTAZ.1a2b3c4d"),
        (r"pat(?u:[é日])\.[a-f0-9]{8}", &["pat"], "pat日.1a2b3c4d"),
        (r"pat(?u:[éê])\.[a-f0-9]{8}", &["pat"], "paté.1a2b3c4d"),
        (
            r"(?m)^pat[A-Z]{2}\.[a-f0-9]{8}$",
            &["pat"],
            "patAZ.1a2b3c4d",
        ),
        (
            r"()\b(pat[A-Z]{2}\.[a-f0-9]{8})\b",
            &["pat", "document"],
            "patAZ.1a2b3c4d",
        ),
        (r"(aba)[A-Z]{2}\.[a-f0-9]{8}", &["aba"], "abaAZ.1a2b3c4d"),
    ];
    let mut state = 0x7139_8abc_u32;
    for (pattern, keywords, positive) in cases {
        let mut spec = serde_json::json!({"rules": [{
            "id":"candidate-differential", "name":"Synthetic candidate differential",
            "pattern":pattern, "keywords":keywords, "confidence":"high"
        }]});
        let (_guard_dir, guarded) = custom_engine(&spec.to_string(), None);
        // Removing keyword gates gives an independent full-regex oracle with
        // identical captures, filters, fingerprints and decoded-view mapping.
        spec["rules"][0]["keywords"] = serde_json::json!([]);
        let (_full_dir, full) = custom_engine(&spec.to_string(), None);
        assert!(
            !full
                .scan_bytes("fixture", positive.as_bytes())
                .unwrap()
                .is_empty()
        );
        for trial in 0..32 {
            let mut input = Vec::new();
            for _ in 0..64 {
                state = state.wrapping_mul(1664525).wrapping_add(1013904223);
                input.extend_from_slice(match state % 5 {
                    0 => b"pat",
                    1 => b"PATno_separator ",
                    2 => b"abababa",
                    3 => b"patABx.0123 ",
                    _ => b"\xff.\r\n",
                });
            }
            if trial % 3 != 0 {
                input.extend_from_slice(b"\n");
                input.extend_from_slice(positive.as_bytes());
                input.extend_from_slice(b"\n");
                input.extend_from_slice(positive.as_bytes());
            }
            if trial % 2 == 0 {
                input.extend_from_slice(b"\npat"); // Truncated last candidate.
            }
            assert_eq!(
                guarded.scan_bytes("fixture", &input).unwrap(),
                full.scan_bytes("fixture", &input).unwrap(),
                "pattern {pattern}, trial {trial}"
            );
        }
    }
}

#[test]
fn fixed_offset_keyword_gate_preserves_decoded_views_and_custom_override() {
    use base64::{Engine as _, engine::general_purpose};
    // Deliberately reuse the provider ID with an unrelated custom format.
    let mut spec = serde_json::json!({"rules": [{
        "id":"airtable-personnal-access-token", "name":"Synthetic override",
        "pattern":r"\b(custom_[A-Z0-9]{8}\.[a-f0-9]{16})\b",
        "keywords":["custom_"], "confidence":"high"
    }]});
    let (_guard_dir, guarded) = custom_engine(&spec.to_string(), None);
    spec["rules"][0]["keywords"] = serde_json::json!([]);
    let (_full_dir, full) = custom_engine(&spec.to_string(), None);
    let token = "custom_A1B2C3D4.0123456789abcdef";
    let encoded = general_purpose::STANDARD.encode(format!("{token} {token}"));
    let text = format!(
        "雪🦀\r\n{}\n{token} {token}\n{encoded}\ncustom_",
        "custom_wrong ".repeat(100)
    );
    let utf16: Vec<_> = [0xff, 0xfe]
        .into_iter()
        .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    for bytes in [text.as_bytes(), utf16.as_slice()] {
        let expected = full.scan_bytes("fixture", bytes).unwrap();
        assert_eq!(expected.len(), 4);
        assert_eq!(guarded.scan_bytes("fixture", bytes).unwrap(), expected);
    }
}

#[test]
fn fixed_offset_keyword_gate_keeps_late_airtable_matches() {
    let guarded = Engine::new(EngineConfig::default()).unwrap();
    let mut catalog: serde_json::Value =
        serde_json::from_str(include_str!("../src/builtin_rules.json")).unwrap();
    let mut rule = catalog["rules"]
        .as_array_mut()
        .unwrap()
        .iter()
        .find(|rule| rule["id"] == "airtable-personnal-access-token")
        .unwrap()
        .clone();
    rule["keywords"] = serde_json::json!([]);
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("override.json");
    std::fs::write(&path, serde_json::json!({"rules":[rule]}).to_string()).unwrap();
    let full = Engine::new(EngineConfig {
        custom_rule_paths: vec![path],
        ..Default::default()
    })
    .unwrap();
    let token = format!("patAb3dEf7hIj9kLm.{}", "0123456789abcdef".repeat(4));
    for source in [
        token.clone(),
        format!("{}\n{token}", "path pattern PATwrong ".repeat(1000)),
        format!("{token}\n{}\n{token}\npat", "path pattern ".repeat(1000)),
    ] {
        assert_eq!(
            guarded.scan_bytes("fixture", source.as_bytes()).unwrap(),
            full.scan_bytes("fixture", source.as_bytes()).unwrap()
        );
    }
}

#[test]
fn findings_share_paths_and_encoding_specific_explanations_without_changing_json() {
    use base64::{Engine as _, engine::general_purpose};
    use std::sync::Arc;

    let (_directory, engine) = custom_engine(RULE, None);
    let token = format!("fixture_{TOKEN}");
    let encoded = general_purpose::STANDARD.encode(format!("{token} {token}"));
    let text = format!("{token} {token}\n{encoded}");
    let utf16: Vec<_> = [0xff, 0xfe]
        .into_iter()
        .chain(text.encode_utf16().flat_map(u16::to_le_bytes))
        .collect();
    for (bytes, is_utf16) in [(text.as_bytes(), false), (utf16.as_slice(), true)] {
        let findings = engine.scan_bytes("settings.conf", bytes).unwrap();
        let other = engine.scan_bytes("other.conf", bytes).unwrap();
        assert_eq!(findings.len(), 4);
        assert_eq!(other.len(), 4);
        for (finding, other_finding) in findings.iter().zip(&other) {
            assert!(Arc::ptr_eq(&findings[0].path, &finding.path));
            assert!(Arc::ptr_eq(
                &finding.explanation,
                &other_finding.explanation
            ));
            assert!(!Arc::ptr_eq(&finding.path, &other_finding.path));
            assert_ne!(finding.fingerprint, other_finding.fingerprint);
            let base64 = if finding.is_base64_encoded {
                "; detected inside Base64 content"
            } else {
                ""
            };
            let utf16 = if is_utf16 {
                "; decoded UTF-16 BOM text"
            } else {
                ""
            };
            let expected = format!(
                "Matched Synthetic fixture token (high confidence){base64}; not live-validated{utf16}"
            );
            assert_eq!(finding.explanation.as_ref(), expected);
            let json = serde_json::to_value(finding).unwrap();
            assert_eq!(json["path"], "settings.conf");
            assert_eq!(json["explanation"], expected);
            assert_eq!(serde_json::from_value::<Finding>(json).unwrap(), *finding);
        }
        for encoded in [false, true] {
            let same_encoding: Vec<_> = findings
                .iter()
                .filter(|finding| finding.is_base64_encoded == encoded)
                .collect();
            assert_eq!(same_encoding.len(), 2);
            assert!(Arc::ptr_eq(
                &same_encoding[0].explanation,
                &same_encoding[1].explanation
            ));
        }
    }
}

#[test]
fn generic_assignment_context_rejects_metadata_and_prose() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for input in [
        format!("\"topic_key\": \"{TOKEN}\"\n"),
        format!("CONTEXT_TOKEN_ESTIMATOR_VERSION = \"{TOKEN}\"\n"),
        format!("alternate authority/key, {TOKEN} receipt/proof;\n"),
        format!("key, {TOKEN}\n"),
    ] {
        assert!(
            engine
                .scan_bytes("metadata.txt", input.as_bytes())
                .unwrap()
                .is_empty(),
            "non-credential context was reported"
        );
    }
}

#[test]
fn assignment_capture_does_not_treat_a_json_property_as_a_value() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let metadata = br#"{"path":"skills/linkedin-tool","sourceBlobSha1":"unused"}"#;
    assert!(
        engine
            .scan_bytes("records.jsonl", metadata)
            .unwrap()
            .is_empty()
    );
    let metadata = format!("{{\"label\":\"key\",\"{TOKEN}\":\"unused\"}}\n");
    assert!(
        engine
            .scan_bytes("records.jsonl", metadata.as_bytes())
            .unwrap()
            .is_empty()
    );
    // Credential-shaped standalone provider tokens remain findings, even as keys.
    let provider = format!("ghp_{TOKEN}Ab3dEf7hIj9k");
    let input = format!("{{\"{provider}\": \"value\"}}\n");
    assert!(
        engine
            .scan_bytes("records.json", input.as_bytes())
            .unwrap()
            .iter()
            .any(|finding| finding.rule_id == "github-pat")
    );
}

#[test]
fn unquoted_configuration_references_do_not_hide_quoted_or_dotted_literals() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let reference = b"api_key=config.effective_anthropic_key\n";
    assert!(
        engine
            .scan_bytes("reviewer.csv", reference)
            .unwrap()
            .is_empty()
    );
    for input in [
        "api_key='config.effective_anthropic_key'\n",
        "api_key=\"config.effective_anthropic_key\"\n",
        "password=spruce.wren.26\n",
        "password='spruce.wren.26'\n",
        "password=password123\n",
    ] {
        assert!(
            !engine
                .scan_bytes("settings.conf", input.as_bytes())
                .unwrap()
                .is_empty(),
            "a literal credential was lost"
        );
    }
}

#[test]
fn custom_rule_with_builtin_id_keeps_rust_matches() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("rules.json");
    std::fs::write(
        &path,
        r#"{"rules":[{"id":"generic-credential-unquoted","name":"Custom credential","pattern":"password: ([A-Za-z0-9]+)","secret_group":1,"confidence":"high"}]}"#,
    )
    .unwrap();
    for builtin_rules in [false, true] {
        let engine = Engine::new(EngineConfig {
            builtin_rules,
            custom_rule_paths: vec![path.clone()],
            ..Default::default()
        })
        .unwrap();
        for visibility in ["pub", "pub(crate)", "pub(in crate :: settings)"] {
            let input = format!("{visibility} password: SyntheticValueA93,\n");
            let findings = engine.scan_bytes("fixture.rs", input.as_bytes()).unwrap();
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id == "generic-credential-unquoted"),
                "custom rule must match with builtin_rules={builtin_rules}, visibility={visibility}"
            );
        }
    }
}

#[test]
fn rust_public_field_types_are_not_literal_credentials() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let declarations = b"struct Settings {\n    pub access_token: String,\n    pub client_secret: std::string::String,\n}\n";
    assert!(
        engine
            .scan_bytes("settings.rs", declarations)
            .unwrap()
            .is_empty()
    );
    // Scope the correction to public Rust declarations, not type-like passwords
    // in configuration, quoted literals, or another assignment on the same line.
    for (path, input) in [
        ("settings.yaml", "password: String\n"),
        ("settings.rs", "password = String;\n"),
        ("settings.rs", "let password = \"String\";\n"),
        (
            "settings.rs",
            "pub access_token: String, password=synthetic987;\n",
        ),
    ] {
        assert!(
            !engine
                .scan_bytes(path, input.as_bytes())
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn rust_restricted_visibility_field_types_are_not_literal_credentials() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for visibility in [
        "pub(crate)",
        "pub(self)",
        "pub(super)",
        "pub ( crate )",
        "pub(in crate)",
        "pub(in self)",
        "pub(in super::super)",
        "pub(in self::super)",
        "pub(in self::super::super)",
        "pub(in crate::settings)",
        "pub ( in\tcrate :: settings )",
        "pub(in crate::r#type)",
        "pub(in crate::配置)",
        "pub(in crate::_settings)",
        // Source scanning is not tied to an edition; these paths are valid in 2015.
        "pub(in settings)",
        "pub(in ::settings)",
        "pub(in::settings)",
    ] {
        let input = format!("    {visibility} access_token: String,\n");
        assert!(
            engine
                .scan_bytes("settings.rs", input.as_bytes())
                .unwrap()
                .is_empty(),
            "field type reported for {visibility}"
        );
    }
}

#[test]
fn rust_visibility_filter_preserves_credential_boundaries() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for visibility in [
        "pub()",
        "pub(foo)",
        "pub(in)",
        "pub(incrate)",
        "pub(in crate settings)",
        "pub(in crate:settings)",
        "pub(in crate::)",
        "pub(in crate :: ::settings)",
        "pub(in crate::123)",
        "pub(in crate::_)",
        "pub(crate) trailing",
    ] {
        let input = format!("{visibility} access_token: String,\n");
        assert!(
            engine
                .scan_bytes("settings.rs", input.as_bytes())
                .unwrap()
                .iter()
                .any(|finding| finding.rule_id == "generic-credential-unquoted"),
            "invalid visibility suppressed a credential: {visibility}"
        );
    }
    for (path, input, expected) in [
        ("settings.yaml", "pub(crate) password: String,\n", "String"),
        ("settings.rs", "pub(crate) password = String;\n", "String"),
        (
            "settings.rs",
            "pub(crate) password: \"String\",\n",
            "String",
        ),
        (
            "settings.rs",
            "pub(crate) access_token: String, password=synthetic987;\n",
            "synthetic987",
        ),
        (
            "settings.rs",
            "pub(in crate :: settings) access_token: String, password: synthetic987;\n",
            "synthetic987",
        ),
    ] {
        let findings = engine.scan_bytes(path, input.as_bytes()).unwrap();
        assert!(
            findings
                .iter()
                .any(|finding| &input[finding.start..finding.end] == expected),
            "literal credential lost in {input}"
        );
    }
    let provider = format!("ghp_{TOKEN}Ab3dEf7hIj9k");
    let input = format!("pub(crate) access_token: {provider},\n");
    assert!(
        engine
            .scan_bytes("settings.rs", input.as_bytes())
            .unwrap()
            .iter()
            .any(|finding| finding.rule_id == "github-pat")
    );
}

#[test]
fn generic_context_corrections_preserve_custom_names_and_quoted_tuples() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for key in [
        "SERVICE_KEY",
        "CUSTOM_SERVICE_KEY",
        "myApiKey",
        "access_token",
        "clientSecret",
        "key",
    ] {
        let input = format!("{key}=\"{TOKEN}\"\n");
        assert!(
            !engine
                .scan_bytes("settings.conf", input.as_bytes())
                .unwrap()
                .is_empty(),
            "credential field {key} was lost"
        );
    }
    for input in [
        format!("(\"key\", \"{TOKEN}\")\n"),
        "('linkedin', 'a1b2c3d4e5f6g7')\n".into(),
    ] {
        assert!(
            !engine
                .scan_bytes("settings.conf", input.as_bytes())
                .unwrap()
                .is_empty(),
            "a quoted tuple was lost"
        );
    }
    // Metadata suppression applies to the generic rule, not provider formats.
    let input = format!("\"topic_key\": \"ghp_{TOKEN}Ab3dEf7hIj9k\"\n");
    assert!(
        engine
            .scan_bytes("settings.json", input.as_bytes())
            .unwrap()
            .iter()
            .any(|finding| finding.rule_id == "github-pat")
    );
}

#[test]
fn rust_visibility_keywords_keep_credential_findings() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for visibility in [
        "pub(in fn)",
        "pub(in crate::type)",
        "pub(in Self)",
        "pub(in crate::gen)",
        "pub(in r#crate)",
        "pub(in r#self)",
    ] {
        let input = format!("{visibility} password: KspDemo_7zQ2mX9pL4vN6sR8\n");
        assert!(
            engine
                .scan_bytes("fixture.rs", input.as_bytes())
                .unwrap()
                .iter()
                .any(|f| f.rule_id == "generic-credential-unquoted"),
            "{visibility}"
        );
    }
}

#[test]
fn rust_literal_and_comment_contents_keep_credential_findings() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for (open, close) in [
        ("r#\"", "\"#"),
        ("br##\"", "\"##"),
        ("cr###\"", "\"###"),
        ("\"", "\""),
        ("/*", "*/"),
        ("/* outer /* nested */", "*/"),
    ] {
        for visibility in ["pub", "pub(crate)", "pub(in crate::settings)"] {
            let input =
                format!("{open}\n{visibility} password: KspDemo_7zQ2mX9pL4vN6sR8\n{close}\n");
            assert!(
                engine
                    .scan_bytes("fixture.rs", input.as_bytes())
                    .unwrap()
                    .iter()
                    .any(|f| f.rule_id == "generic-credential-unquoted"),
                "{open} {visibility}"
            );
        }
    }
}

#[test]
fn rust_real_fields_after_literals_still_avoid_false_positives() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let input = b"const NOTE: &str = r#\"not code: pub(crate)\"#;\n/* pub */\nstruct Config {\n    pub(crate) access_token: String,\n}\n";
    assert!(engine.scan_bytes("fixture.rs", input).unwrap().is_empty());
}

#[test]
fn rust_encoded_embedded_fields_keep_credential_findings() {
    use base64::{Engine as _, engine::general_purpose};
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let encoded =
        general_purpose::STANDARD.encode("pub(crate) password: KspDemo_7zQ2mX9pL4vN6sR8\n");
    let findings = engine.scan_bytes("fixture.rs", encoded.as_bytes()).unwrap();
    assert!(
        findings
            .iter()
            .any(|f| f.is_base64_encoded && f.rule_id == "generic-credential-unquoted")
    );
}

#[test]
fn rust_macro_configuration_keeps_credential_findings() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let source = br#"
macro_rules! config {
    ($visibility:vis password: $value:ident) => { const PASSWORD: &str = stringify!($value); };
}
config! {
    pub(crate) password: KspDemo_7zQ2mX9pL4vN6sR8
}
"#;
    let raw_named =
        b"macro_rules! r#config { () => {\n pub(crate) password: KspDemo_7zQ2mX9pL4vN6sR8\n}; }";
    for input in [source.as_slice(), raw_named.as_slice()] {
        assert!(
            engine
                .scan_bytes("fixture.rs", input)
                .unwrap()
                .iter()
                .any(|f| f.rule_id == "generic-credential-unquoted")
        );
    }
}

#[test]
fn rust_visibility_path_keyword_positions_keep_findings() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for path in [
        "crate::self",
        "crate::crate",
        "crate::super",
        "settings::super",
        "::crate",
        "::self",
        "::super",
        "$crate",
    ] {
        let source = format!(
            "struct Settings {{\n    pub(in {path}) password: KspDemo_7zQ2mX9pL4vN6sR8,\n}}\n"
        );
        assert!(
            engine
                .scan_bytes("fixture.rs", source.as_bytes())
                .unwrap()
                .iter()
                .any(|f| f.rule_id == "generic-credential-unquoted"),
            "{path}"
        );
    }
}

#[test]
fn rust_commented_visibility_fields_avoid_false_positives() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for visibility in [
        "pub(in /* rationale */ crate)",
        "pub /* public */ (crate)",
        "pub(in // rationale\ncrate)",
    ] {
        let source = format!("struct Settings {{\n    {visibility} access_token: String,\n}}\n");
        assert!(
            engine
                .scan_bytes("fixture.rs", source.as_bytes())
                .unwrap()
                .is_empty(),
            "{visibility}"
        );
    }
}

#[test]
fn rust_deeply_nested_input_does_not_require_recursive_parsing() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    let depth = 4096;
    let source = format!(
        "{}struct S {{\n pub(crate) access_token: String,\n}}\n{}",
        "mod nested {\n".repeat(depth),
        "}\n".repeat(depth)
    );
    assert!(
        engine
            .scan_bytes("generated.rs", source.as_bytes())
            .unwrap()
            .is_empty()
    );
    let source = format!(
        "config! {{{}\n pub(crate) password: KspDemo_7zQ2mX9pL4vN6sR8\n{}}}",
        "{".repeat(depth),
        "}".repeat(depth)
    );
    assert!(
        engine
            .scan_bytes("generated.rs", source.as_bytes())
            .unwrap()
            .iter()
            .any(|f| f.rule_id == "generic-credential-unquoted")
    );
}

#[test]
fn rust_boolean_negation_does_not_hide_real_fields() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for condition in ["!enabled", "!{ enabled }"] {
        let source = format!(
            "fn f(enabled: bool) {{ if {condition} {{ struct S {{\n pub(crate) access_token: String,\n}} }} }}"
        );
        assert!(
            engine
                .scan_bytes("fixture.rs", source.as_bytes())
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn rust_comments_after_visibility_keep_credential_findings() {
    let engine = Engine::new(EngineConfig::default()).unwrap();
    for source in [
        "pub // password: KspDemo_7zQ2mX9pL4vN6sR8\nstruct S;",
        "pub /* password: KspDemo_7zQ2mX9pL4vN6sR8\n*/ struct S;",
        "struct S { pub(in /* password: KspDemo_7zQ2mX9pL4vN6sR8\n*/ crate) access_token: String }",
    ] {
        assert!(
            engine
                .scan_bytes("fixture.rs", source.as_bytes())
                .unwrap()
                .iter()
                .any(|f| f.rule_id == "generic-credential-unquoted"
                    && &source[f.start..f.end] == "KspDemo_7zQ2mX9pL4vN6sR8")
        );
    }
}
