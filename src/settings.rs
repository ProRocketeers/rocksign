//! User settings, stored in ~/Library/Application Support/RockSign/settings.toml.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

pub const DEFAULT_SUFFIX: &str = " (signed {n})";

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Settings {
    /// Appended to the file name when saving a signed copy. Placeholders: {n}, {total},
    /// {name}, {date}.
    #[serde(default = "default_suffix")]
    pub file_suffix: String,
    /// Whether "Add a trusted timestamp" starts checked.
    #[serde(default = "yes")]
    pub timestamp: bool,
    /// Stamp logo: "none" (the default), "rocksign" (the built-in logo), or a path to an image.
    #[serde(default = "default_logo")]
    pub logo: String,
    /// "watermark" (faded behind the text) or "header" (above the text).
    #[serde(default = "default_logo_style")]
    pub logo_style: String,
    /// Watermark opacity, 0–1.
    #[serde(default = "default_logo_opacity")]
    pub logo_opacity: f32,
    /// Watermark position: x 0 = left … 1 = right, y 0 = top … 1 = bottom.
    #[serde(default = "half")]
    pub watermark_x: f32,
    #[serde(default = "half")]
    pub watermark_y: f32,
    /// Watermark size relative to the largest that fits, 0.2–1.
    #[serde(default = "one")]
    pub watermark_size: f32,
    /// "Show in the sign panel" per certificate, by SHA-256 fingerprint. Certificates not listed
    /// are shown when they are meant for document signing.
    #[serde(default)]
    pub cert_visible: BTreeMap<String, bool>,
    /// Fingerprint of the certificate selected by default; none means automatic.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_cert: Option<String>,
    /// The welcome steps were completed or skipped. Settings files from before the welcome
    /// existed count as done; only a first start (no settings file) shows it.
    #[serde(default = "yes")]
    pub setup_done: bool,
}

fn default_logo() -> String {
    "none".into()
}

fn default_logo_style() -> String {
    "watermark".into()
}

fn default_logo_opacity() -> f32 {
    0.25
}

fn half() -> f32 {
    0.5
}

fn one() -> f32 {
    1.0
}

fn default_suffix() -> String {
    DEFAULT_SUFFIX.to_string()
}

fn yes() -> bool {
    true
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            file_suffix: default_suffix(),
            timestamp: true,
            logo: default_logo(),
            logo_style: default_logo_style(),
            logo_opacity: default_logo_opacity(),
            watermark_x: half(),
            watermark_y: half(),
            watermark_size: one(),
            cert_visible: BTreeMap::new(),
            default_cert: None,
            setup_done: false,
        }
    }
}

fn path() -> Option<PathBuf> {
    Some(dirs::config_dir()?.join("RockSign").join("settings.toml"))
}

impl Settings {
    pub fn load() -> Settings {
        let mut s: Settings = path().and_then(|p| std::fs::read_to_string(p).ok()).and_then(|t| toml::from_str(&t).ok()).unwrap_or_default();
        // "default" was the old built-in logo, which is gone: fall back to the new default.
        if s.logo == "default" {
            s.logo = default_logo();
        }
        s
    }

    pub fn save(&self) -> anyhow::Result<()> {
        let p = path().ok_or_else(|| anyhow::anyhow!("no settings folder"))?;
        if let Some(dir) = p.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(p, toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

/// Values for the file name placeholders.
pub struct NameVars<'a> {
    /// People who have signed the saved file (several stamps by one person count once).
    pub n: usize,
    /// Signature boxes in the document, when it has prepared ones.
    pub total: Option<usize>,
    pub name: &'a str,
    pub date: String,
}

enum Part {
    Text(String),
    Var(String),
}

fn parts(template: &str) -> Vec<Part> {
    let mut out = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        match rest[open..].find('}') {
            Some(close) => {
                let var = &rest[open + 1..open + close];
                if ["n", "total", "name", "date"].contains(&var) {
                    if open > 0 {
                        out.push(Part::Text(rest[..open].to_string()));
                    }
                    out.push(Part::Var(var.to_string()));
                } else {
                    out.push(Part::Text(rest[..open + close + 1].to_string()));
                }
                rest = &rest[open + close + 1..];
            }
            None => break,
        }
    }
    if !rest.is_empty() {
        out.push(Part::Text(rest.to_string()));
    }
    out
}

/// The suffix with placeholders filled in.
pub fn expand(template: &str, v: &NameVars) -> String {
    parts(template)
        .into_iter()
        .map(|p| match p {
            Part::Text(t) => t,
            Part::Var(var) => match var.as_str() {
                "n" => v.n.to_string(),
                "total" => v.total.unwrap_or(v.n).to_string(),
                "name" => v.name.to_string(),
                _ => v.date.clone(),
            },
        })
        .collect::<String>()
        .replace(['/', ':'], "-")
}

/// Whether `s` is exactly the template with some values filled in.
fn matches(s: &str, parts: &[Part]) -> bool {
    let Some((first, rest)) = parts.split_first() else { return s.is_empty() };
    match first {
        Part::Text(t) => s.strip_prefix(t.as_str()).is_some_and(|r| matches(r, rest)),
        Part::Var(var) => {
            let ok = |c: char| match var.as_str() {
                "n" | "total" => c.is_ascii_digit(),
                "date" => c.is_ascii_digit() || c == '-',
                _ => true,
            };
            for (i, c) in s.char_indices() {
                if !ok(c) {
                    break;
                }
                let end = i + c.len_utf8();
                if matches(&s[end..], rest) {
                    return true;
                }
            }
            false
        }
    }
}

/// Suggested file name for the signed copy: the original name without an earlier suffix of
/// the same form, plus the new suffix. "Contract (signed 1).pdf" → "Contract (signed 2).pdf".
pub fn suggested_name(path: &Path, template: &str, v: &NameVars) -> String {
    let stem = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_else(|| "Document".into());
    let template = if template.trim().is_empty() { DEFAULT_SUFFIX } else { template };
    let ps = parts(template);
    let cut = stem.char_indices().map(|(i, _)| i).skip(1).filter(|&i| matches(&stem[i..], &ps)).last();
    // Older RockSign names, "(signed)" and "(signed 2 of 3)", are removed too.
    let base = match cut {
        Some(i) => &stem[..i],
        None => match stem.rfind(" (signed") {
            Some(i) if stem.ends_with(')') && i > 0 => &stem[..i],
            _ => &stem,
        },
    };
    format!("{base}{}.pdf", expand(template, v))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vars(n: usize) -> NameVars<'static> {
        NameVars { n, total: None, name: "Tomáš Procházka", date: "2026-11-24".into() }
    }

    #[test]
    fn settings_roundtrip_and_old_files() {
        let mut s = Settings::default();
        s.cert_visible.insert("ab".repeat(32), false);
        s.default_cert = Some("cd".repeat(32));
        let text = toml::to_string_pretty(&s).unwrap();
        let back: Settings = toml::from_str(&text).unwrap();
        assert_eq!(back.cert_visible.get(&"ab".repeat(32)), Some(&false));
        assert_eq!(back.default_cert, s.default_cert);
        // A settings file from before these options existed still loads.
        let old: Settings = toml::from_str("file_suffix = \"_x\"\ntimestamp = false\n").unwrap();
        assert_eq!(old.file_suffix, "_x");
        assert!(old.cert_visible.is_empty() && old.default_cert.is_none() && old.logo == "none");
        // ...and doesn't bring up the welcome steps, unlike a first start.
        assert!(old.setup_done && !Settings::default().setup_done);
    }

    #[test]
    fn default_suffix_counts_up() {
        let t = DEFAULT_SUFFIX;
        assert_eq!(suggested_name(Path::new("/x/Contract.pdf"), t, &vars(1)), "Contract (signed 1).pdf");
        assert_eq!(suggested_name(Path::new("/x/Contract (signed 1).pdf"), t, &vars(2)), "Contract (signed 2).pdf");
        assert_eq!(suggested_name(Path::new("/x/Contract (signed).pdf"), t, &vars(2)), "Contract (signed 2).pdf");
    }

    #[test]
    fn custom_suffixes() {
        let t = "_podepsano_{name}_{date}";
        let first = suggested_name(Path::new("/x/Smlouva.pdf"), t, &vars(1));
        assert_eq!(first, "Smlouva_podepsano_Tomáš Procházka_2026-11-24.pdf");
        let again = suggested_name(Path::new(&format!("/x/{first}")), t, &vars(2));
        assert_eq!(again, first);
        let t = " - {n} of {total}";
        let v = NameVars { total: Some(3), ..vars(2) };
        assert_eq!(suggested_name(Path::new("/x/A - 1 of 3.pdf"), t, &v), "A - 2 of 3.pdf");
        assert_eq!(suggested_name(Path::new("/x/A.pdf"), "", &vars(1)), "A (signed 1).pdf");
        assert_eq!(suggested_name(Path::new("/x/A.pdf"), "_{unknown}", &vars(1)), "A_{unknown}.pdf");
    }
}
