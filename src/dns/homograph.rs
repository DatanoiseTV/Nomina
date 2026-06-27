//! IDN homograph / lookalike-domain detection. Phishing domains imitate famous
//! brands using confusable characters from other scripts (e.g. a Cyrillic «а»
//! in `аpple.com`). On the wire these arrive as `xn--` punycode labels; we
//! decode them and flag labels that mix scripts (the classic homograph), or
//! optionally block all internationalized names.

use std::collections::HashSet;

use unicode_script::{Script, UnicodeScript};

use crate::models::HomographMode;

/// Is `qname` a suspicious lookalike under `mode`? Accepts either the decoded
/// Unicode form (hickory decodes punycode in `Name` display) or the raw `xn--`
/// form — both are normalized to Unicode before inspection.
pub fn is_suspicious(qname: &str, mode: HomographMode) -> bool {
    if mode == HomographMode::Off {
        return false;
    }
    let (unicode, _) = idna::domain_to_unicode(qname);
    match mode {
        HomographMode::Off => false,
        // Any internationalized (non-ASCII) name.
        HomographMode::AllIdn => !unicode.is_ascii(),
        // Any label mixing scripts (the classic homograph).
        HomographMode::Mixed => unicode.split('.').any(label_mixes_scripts),
    }
}

/// True if a decoded label contains alphabetic characters from more than one
/// script (ignoring script-neutral Common/Inherited code points like digits).
fn label_mixes_scripts(label: &str) -> bool {
    let mut scripts: HashSet<Script> = HashSet::new();
    for c in label.chars() {
        if !c.is_alphabetic() {
            continue;
        }
        let s = c.script();
        if matches!(s, Script::Common | Script::Inherited) {
            continue;
        }
        scripts.insert(s);
        if scripts.len() > 1 {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mixed_script_is_blocked_in_mixed_mode() {
        // "аpple" (Cyrillic а + Latin pple) — decoded form and xn-- form.
        assert!(is_suspicious("аpple.com", HomographMode::Mixed));
        assert!(is_suspicious("xn--pple-43d.com", HomographMode::Mixed));
        // "gооgle" (Latin g + Cyrillic оо + Latin gle)
        assert!(is_suspicious("gооgle.com", HomographMode::Mixed));
    }

    #[test]
    fn legitimate_single_script_idn_is_allowed_in_mixed_mode() {
        // "münchen" is pure Latin (with a diacritic) — not a homograph.
        assert!(!is_suspicious("münchen.de", HomographMode::Mixed));
        assert!(!is_suspicious("xn--mnchen-3ya.de", HomographMode::Mixed));
    }

    #[test]
    fn all_idn_mode_blocks_any_internationalized_name() {
        assert!(is_suspicious("münchen.de", HomographMode::AllIdn));
        assert!(is_suspicious("аpple.com", HomographMode::AllIdn));
        assert!(!is_suspicious("apple.com", HomographMode::AllIdn));
    }

    #[test]
    fn plain_ascii_never_blocked() {
        for mode in [
            HomographMode::Mixed,
            HomographMode::AllIdn,
            HomographMode::Off,
        ] {
            assert!(!is_suspicious("apple.com", mode));
            assert!(!is_suspicious("nas.home.lan", mode));
        }
    }
}
