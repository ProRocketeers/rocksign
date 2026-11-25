//! Print the signature report for a PDF.
//!
//!     cargo run -p rocksign-core --example inspect -- file.pdf

use rocksign_core::{Integrity, analyze};

fn main() -> anyhow::Result<()> {
    let path = std::env::args().nth(1).expect("usage: inspect <file.pdf>");
    let bytes = std::fs::read(&path)?;
    let report = analyze(&bytes)?;
    println!("{path}: {} pages, {} signature fields", report.pages.len(), report.fields.len());
    if let Some(b) = &report.signing_blocker {
        println!("  cannot sign: {b}");
    }
    for f in report.empty_fields() {
        println!("  empty field {:?} on page {:?}", f.name, f.page.map(|p| p + 1));
    }
    for (i, s) in report.signatures.iter().enumerate() {
        println!("\n#{} {} — field {:?}, {:?}, {}", i + 1, s.signer_name(), s.field, s.kind, s.sub_filter);
        let integrity = match &s.integrity {
            Integrity::Intact => "intact".to_string(),
            Integrity::Altered => "ALTERED".to_string(),
            Integrity::Malformed(e) => format!("MALFORMED: {e}"),
        };
        println!("  integrity: {integrity}; signature valid: {}; {}", s.signature_valid, s.algorithm);
        if let Some(p) = &s.problem {
            println!("  problem: {p}");
        }
        if let Some(c) = &s.signer {
            println!("  signer: {}  (issuer: {})", c.subject, c.issuer);
            println!("  cert valid {} – {}, {}", c.not_before, c.not_after, c.key_description());
        }
        println!("  certificates in signature: {}", s.certificates.len());
        println!("  claimed time: {:?}", s.claimed_time);
        if let Some(t) = &s.timestamp {
            println!("  timestamp: {} by {:?} valid={} {:?}", t.time, t.authority.as_ref().map(|a| a.display_name()), t.valid, t.problem);
        }
        println!("  covers whole file: {}; later changes: {:?} {:?}", s.covers_whole_file, s.later.level, s.later.notes);
        if let (Some(p), Some(r)) = (s.page, s.rect) {
            println!("  stamp on page {} at {:?}", p + 1, r);
        }
    }
    Ok(())
}
