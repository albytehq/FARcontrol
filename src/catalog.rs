//! Provider/model identity catalog — spec §9.2–9.5, §11, §81 (AG-01..03, ADR-0022).
//!
//! The catalog is DATA, not code: an embedded JSON document parsed at startup.
//! Validation happens server-side only (one enforcement point, S4) — the CLI
//! forwards identity fields but never validates them itself.
//!
//! Identity is a DECLARATION: it grants no authority and implies no vendor
//! verification (AG-03, spec §9.2 "Important" note). The web UI labels it
//! "declared — not verified".

use serde_json::Value;

/// Embedded catalog data — the spec §9.2–9.4 initial catalog, verbatim.
/// `identityVersion` is 1 (spec §9.5); `clientVersion` is per-request and not
/// catalog data.
const CATALOG_JSON: &str = r#"{
  "version": 1,
  "providers": {
    "z_ai":  ["glm-5.3", "glm-5.3-flash", "glm-5.2", "glm-5.1"],
    "qwen":  ["qwen-3.8-max", "qwen-3.8-plus", "qwen-3.7-max", "qwen-3.7-plus", "qwen-3.7-turbo"]
  }
}"#;

/// Parsed catalog (fresh parse per call is fine — callers are rare; keeps the
/// module stateless and testable).
pub fn catalog() -> Value {
    serde_json::from_str(CATALOG_JSON).expect("embedded catalog is valid JSON")
}

/// Catalog version (spec §9.5 `identityVersion`).
pub fn version() -> u64 {
    catalog()["version"].as_u64().unwrap_or(1)
}

/// Validates an optional agent identity (spec §11: `agent: {provider, model}`).
///
/// Rules (ADR-0022):
/// - both fields present or both absent;
/// - exact slug match against the catalog (case-sensitive, no trimming);
/// - catalog membership bounds length implicitly (slugs are short), but the
///   explicit ≤64 cap gives a clean rejection for hostile lengths.
///
/// `Ok(None)` = no identity declared (v0.7-compatible).
/// `Err(msg)` = rejected — the message is metadata-only, never a secret.
pub fn validate(provider: Option<&str>, model: Option<&str>) -> Result<Option<(String, String)>, String> {
    let (p, m) = match (provider, model) {
        (None, None) => return Ok(None),
        (Some(p), Some(m)) => (p, m),
        (Some(_), None) => return Err("agent identity requires both provider and model (spec §11)".into()),
        (None, Some(_)) => return Err("agent identity requires both provider and model (spec §11)".into()),
    };
    if p.len() > 64 || m.len() > 64 {
        return Err("provider/model must be ≤64 characters".into());
    }
    let cat = catalog();
    let models = cat["providers"]
        .get(p)
        .and_then(|v| v.as_array())
        .ok_or_else(|| "unknown provider (see catalog: z_ai, qwen — spec §9.2)".to_string())?;
    let known = models
        .iter()
        .any(|v| v.as_str() == Some(m));
    if !known {
        return Err(format!("unknown model for provider '{p}' (spec §9.3–9.4)"));
    }
    Ok(Some((p.to_string(), m.to_string())))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_identity_is_allowed() {
        assert!(matches!(validate(None, None), Ok(None)));
    }

    #[test]
    fn valid_pairs_from_spec_catalog() {
        assert_eq!(validate(Some("z_ai"), Some("glm-5.3")).unwrap().unwrap(), ("z_ai".into(), "glm-5.3".into()));
        assert_eq!(validate(Some("z_ai"), Some("glm-5.3-flash")).unwrap().unwrap(), ("z_ai".into(), "glm-5.3-flash".into()));
        assert_eq!(validate(Some("qwen"), Some("qwen-3.7-turbo")).unwrap().unwrap(), ("qwen".into(), "qwen-3.7-turbo".into()));
        assert_eq!(validate(Some("qwen"), Some("qwen-3.8-max")).unwrap().unwrap(), ("qwen".into(), "qwen-3.8-max".into()));
    }

    #[test]
    fn both_or_none() {
        assert!(validate(Some("z_ai"), None).is_err());
        assert!(validate(None, Some("glm-5.3")).is_err());
    }

    #[test]
    fn unknown_provider_rejected() {
        assert!(validate(Some("openai"), Some("gpt-9")).is_err());
        assert!(validate(Some(""), Some("glm-5.3")).is_err());
    }

    #[test]
    fn unknown_model_rejected() {
        assert!(validate(Some("z_ai"), Some("glm-9.9")).is_err());
        // model from another provider is still unknown here
        assert!(validate(Some("z_ai"), Some("qwen-3.8-max")).is_err());
    }

    #[test]
    fn slugs_are_exact_no_case_no_trim() {
        assert!(validate(Some("Z_AI"), Some("glm-5.3")).is_err());
        assert!(validate(Some("z_ai"), Some("GLM-5.3")).is_err());
        assert!(validate(Some(" z_ai"), Some("glm-5.3")).is_err());
        assert!(validate(Some("z_ai"), Some("glm-5.3 ")).is_err());
    }

    #[test]
    fn hostile_lengths_rejected() {
        let long = "x".repeat(200);
        assert!(validate(Some(&long), Some("glm-5.3")).is_err());
        assert!(validate(Some("z_ai"), Some(&long)).is_err());
    }

    #[test]
    fn catalog_shape_matches_spec() {
        let cat = catalog();
        let providers = cat["providers"].as_object().expect("providers object");
        assert_eq!(providers.len(), 2, "spec §9.2: exactly z_ai and qwen in v1");
        assert_eq!(providers["z_ai"].as_array().unwrap().len(), 4, "§9.3: 4 GLM models");
        assert_eq!(providers["qwen"].as_array().unwrap().len(), 5, "§9.4: 5 Qwen models");
        for (p, models) in providers {
            assert!(p.chars().all(|c| c.is_ascii_lowercase() || c == '_' || c == '.'), "slug rules (Q-018)");
            for m in models.as_array().unwrap() {
                let m = m.as_str().unwrap();
                assert!(m.len() <= 64 && m.chars().all(|c| c.is_ascii_lowercase() || c == '-' || c == '.' || c.is_ascii_digit()));
            }
        }
        assert_eq!(version(), 1);
    }
}
