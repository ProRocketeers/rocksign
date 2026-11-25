//! Work that runs off the UI thread: reading and checking a PDF, and signing one.

use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use chrono::Local;
use rocksign_core::cms::{self, KeyKind};
use rocksign_core::sign::{self, DEFAULT_RESERVE, SignRequest, Target};
use rocksign_core::stamp::{FontData, LogoMode, Stamp, StampText};
use rocksign_core::{Certificate, Report, analyze};
use security_framework::identity::SecIdentity;

use crate::keychain;
use crate::trust::{self, TrustOutcome};

/// DigiCert's free RFC 3161 service. Override with ROCKSIGN_TSA_URL.
pub const DEFAULT_TSA: &str = "http://timestamp.digicert.com";

pub fn tsa_url() -> String {
    std::env::var("ROCKSIGN_TSA_URL").ok().filter(|u| !u.is_empty()).unwrap_or_else(|| DEFAULT_TSA.to_string())
}

#[derive(Clone)]
pub struct Loaded {
    pub path: PathBuf,
    pub bytes: Arc<Vec<u8>>,
    pub report: Report,
    /// One per signature, same order as `report.signatures`.
    pub trust: Vec<TrustOutcome>,
}

pub fn load(path: &Path, anchors: &[Certificate]) -> Result<Loaded> {
    let bytes = std::fs::read(path).with_context(|| format!("could not read {}", path.display()))?;
    let report = analyze(&bytes)?;
    let trust = check_trust(&report, anchors);
    Ok(Loaded { path: path.to_path_buf(), bytes: Arc::new(bytes), report, trust })
}

pub fn check_trust(report: &Report, anchors: &[Certificate]) -> Vec<TrustOutcome> {
    report
        .signatures
        .iter()
        .map(|s| match &s.signer {
            Some(signer) => {
                let at = s.timestamp.as_ref().filter(|t| t.valid).map(|t| t.time);
                trust::evaluate(signer, &s.certificates, at, anchors)
            }
            None => TrustOutcome { trusted: false, problem: Some("no signer certificate".into()), chain: Vec::new(), qualified_provider: None },
        })
        .collect()
}

pub struct SignJob {
    pub input: Arc<Vec<u8>>,
    pub output: PathBuf,
    pub identity: Option<SecIdentity>,
    pub cert: Certificate,
    /// One signature per target, applied in order and saved as one file.
    pub targets: Vec<Target>,
    pub timestamp: bool,
    pub logo: Option<std::sync::Arc<rocksign_core::logo::Logo>>,
    pub logo_mode: LogoMode,
}

/// Sign once per target and write the copy. Returns the output path.
pub fn sign(job: SignJob) -> Result<PathBuf> {
    if job.targets.is_empty() {
        bail!("choose where the stamp goes first");
    }
    let mut bytes: Vec<u8> = job.input.as_ref().clone();
    for target in &job.targets {
        bytes = sign_once(&job, target.clone(), &bytes)?;
    }
    let tmp = job.output.with_extension("pdf.rocksign-tmp");
    std::fs::write(&tmp, &bytes).with_context(|| format!("could not write {}", tmp.display()))?;
    std::fs::rename(&tmp, &job.output)?;
    Ok(job.output)
}

/// Adds one signature to `input` and checks it; nothing is written.
fn sign_once(job: &SignJob, target: Target, input: &[u8]) -> Result<Vec<u8>> {
    let kind = KeyKind::of(&job.cert)?;
    let chain = trust::chain_for_signing(&job.cert);
    let fonts = stamp_fonts();
    let now = Local::now().fixed_offset();
    let name = job.cert.display_name();
    let date = stamp_date(&now);
    let req = SignRequest {
        target,
        signer_name: name.clone(),
        reason: None,
        location: None,
        time: now,
        stamp: fonts.map(|(regular, bold)| Stamp {
            text: StampText { name: name.clone(), date: date.clone(), reason: None },
            regular: FontData { data: regular, index: 0 },
            bold: bold.map(|b| FontData { data: b, index: 0 }),
            logo: job.logo.as_deref(),
            logo_mode: job.logo_mode,
        }),
        reserve: DEFAULT_RESERVE,
    };
    let prepared = sign::prepare(input, &req)?;
    let attrs = cms::signed_attributes(&prepared.digest, &job.cert);
    let key = job.identity.as_ref().context("This is a demo certificate; it can't sign.")?;
    let signature = keychain::sign(key, kind, &attrs)?;
    let token = if job.timestamp {
        Some(fetch_timestamp(&tsa_url(), &signature).context("Could not get a timestamp. Check your connection, or sign without a timestamp")?)
    } else {
        None
    };
    let der = cms::signed_data(&attrs, &signature, &job.cert, &chain, token.as_deref())?;
    let out = sign::embed(prepared, &der)?;

    // Check our own work before going on.
    let report = analyze(&out)?;
    let ours = report.signatures.last().context("the new signature is missing")?;
    if !ours.is_intact() || !ours.covers_whole_file {
        bail!("the new signature did not verify ({:?}); nothing was saved", ours.problem);
    }
    Ok(out)
}

fn fetch_timestamp(url: &str, signature: &[u8]) -> Result<Vec<u8>> {
    let nonce = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1) | 1;
    let request = cms::timestamp_request(signature, nonce);
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(20))).build().into();
    let mut resp = agent.post(url).header("Content-Type", "application/timestamp-query").send(&request[..])?;
    let body = resp.body_mut().with_config().limit(1 << 20).read_to_vec()?;
    cms::timestamp_from_response(&body, signature)
}

/// The date as printed in the stamp.
pub fn stamp_date(t: &chrono::DateTime<chrono::FixedOffset>) -> String {
    t.format("%-d %b %Y, %H:%M %:z").to_string()
}

/// Fonts for the stamp text, from macOS.
pub fn stamp_fonts() -> Option<(&'static [u8], Option<&'static [u8]>)> {
    /// Regular and (if present) bold font files.
    type FontFiles = Option<(Vec<u8>, Option<Vec<u8>>)>;
    static FONTS: OnceLock<FontFiles> = OnceLock::new();
    let fonts = FONTS.get_or_init(|| {
        let first = |paths: &[&str]| paths.iter().find_map(|p| std::fs::read(p).ok());
        let regular = first(&["/System/Library/Fonts/Supplemental/Arial.ttf", "/Library/Fonts/Arial Unicode.ttf"])?;
        let bold = first(&["/System/Library/Fonts/Supplemental/Arial Bold.ttf"]);
        Some((regular, bold))
    });
    fonts.as_ref().map(|(r, b)| (r.as_slice(), b.as_deref()))
}
