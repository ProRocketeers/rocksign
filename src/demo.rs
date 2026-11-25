//! `rocksign --demo <folder>`: a window with made-up data, for screenshots.
//!
//! It opens the PDFs in the folder, lists the certificates in `<folder>/certificates/*.pem` as if
//! they were in the Keychain (they have no key, so they can't sign), trusts `<folder>/ca.pem`,
//! starts signing the first document, and never reads or writes your settings or Keychain.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use rocksign_core::Certificate;
use rocksign_core::x509::certificates_from_pem;

use crate::keychain::Identity;

static DIR: OnceLock<PathBuf> = OnceLock::new();
static SCENE_DONE: AtomicBool = AtomicBool::new(false);

pub fn start(dir: PathBuf) {
    DIR.set(dir).ok();
}

pub fn active() -> bool {
    DIR.get().is_some()
}

fn dir() -> Option<&'static Path> {
    DIR.get().map(PathBuf::as_path)
}

/// The demo PDFs, by name.
pub fn files() -> Vec<PathBuf> {
    let Some(dir) = dir() else { return Vec::new() };
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).filter(|p| p.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf"))).collect())
        .unwrap_or_default();
    files.sort();
    files
}

/// Certificates shown in place of the Keychain's.
pub fn identities() -> Result<Vec<Identity>> {
    let dir = dir().context("not in demo mode")?.join("certificates");
    let mut out = Vec::new();
    let mut paths: Vec<PathBuf> =
        std::fs::read_dir(&dir).with_context(|| format!("no {}", dir.display()))?.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for path in paths.iter().filter(|p| p.extension().is_some_and(|e| e == "pem")) {
        for cert in certificates_from_pem(&std::fs::read_to_string(path)?)? {
            out.push(Identity { cert, identity: None });
        }
    }
    out.sort_by_key(|i| (!i.is_usable(), i.cert.display_name().to_lowercase(), std::cmp::Reverse(i.cert.not_after)));
    Ok(out)
}

/// The demo CA, trusted like a real one.
pub fn anchors() -> Vec<Certificate> {
    dir().and_then(|d| std::fs::read_to_string(d.join("ca.pem")).ok()).and_then(|t| certificates_from_pem(&t).ok()).unwrap_or_default()
}

/// True once: time to set the scene (start signing the open document).
pub fn take_scene() -> bool {
    active() && !SCENE_DONE.swap(true, Ordering::Relaxed)
}
