//! End-to-end: sign the fixture PDFs as three people in turn, then check what the validator
//! reports, including after tampering.

use rocksign_core::cms::{self, KeyKind};
use rocksign_core::sign::{self, DEFAULT_RESERVE, SignRequest, Target};
use rocksign_core::stamp::{FontData, LogoMode, Stamp, StampText};
use rocksign_core::x509::{Certificate, certificates_from_pem};
use rocksign_core::{ChangeLevel, Integrity, analyze};

const FIX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/");

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{FIX}{name}")).unwrap()
}

fn cert(name: &str) -> Certificate {
    certificates_from_pem(&String::from_utf8(fixture(name)).unwrap()).unwrap().remove(0)
}

fn sign_as(pdf: &[u8], who: &str, target: Target) -> Vec<u8> {
    let signer = cert(&format!("{who}.pem"));
    let key_pem = String::from_utf8(fixture(&format!("{who}.key"))).unwrap();
    let font = std::fs::read("/System/Library/Fonts/Supplemental/Arial.ttf").ok();
    let now = chrono::Local::now().fixed_offset();
    let req = SignRequest {
        target,
        signer_name: signer.display_name(),
        reason: None,
        location: None,
        time: now,
        stamp: font.as_deref().map(|data| Stamp {
            text: StampText { name: signer.display_name(), date: "24 Nov 2026, 12:00 +01:00".into(), reason: None },
            regular: FontData { data, index: 0 },
            bold: None,
            logo: None,
            logo_mode: LogoMode::Header,
        }),
        reserve: DEFAULT_RESERVE,
    };
    let prepared = sign::prepare(pdf, &req).unwrap();
    let attrs = cms::signed_attributes(&prepared.digest, &signer);
    let signature = match KeyKind::of(&signer).unwrap() {
        KeyKind::Rsa => {
            use rsa::pkcs8::DecodePrivateKey;
            use sha2::Digest;
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(&key_pem).unwrap();
            key.sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &sha2::Sha256::digest(&attrs)).unwrap()
        }
        KeyKind::Ec => {
            use p256::ecdsa::signature::Signer;
            use p256::pkcs8::DecodePrivateKey;
            let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&key_pem).unwrap();
            let sig: p256::ecdsa::Signature = key.sign(&attrs);
            sig.to_der().as_bytes().to_vec()
        }
    };
    let ca = cert("ca.pem");
    let der = cms::signed_data(&attrs, &signature, &signer, &[ca], None).unwrap();
    sign::embed(prepared, &der).unwrap()
}

fn new_field(page: usize, x: f32) -> Target {
    Target::NewField { page, rect: [x, 60.0, x + 180.0, 120.0] }
}

#[test]
fn three_signers_in_turn() {
    for base in ["plain.pdf", "xrefstream.pdf", "rotated.pdf"] {
        let original = fixture(base);
        let s1 = sign_as(&original, "alice", new_field(0, 40.0));
        let s2 = sign_as(&s1, "bob", new_field(0, 230.0));
        let s3 = sign_as(&s2, "alice", Target::Invisible);
        assert!(s3.starts_with(&s2) && s2.starts_with(&s1) && s1.starts_with(&original), "{base}: must only append");

        let report = analyze(&s3).unwrap();
        assert_eq!(report.signatures.len(), 3, "{base}");
        for (i, s) in report.signatures.iter().enumerate() {
            assert!(s.is_intact(), "{base} #{i}: {:?} {:?}", s.integrity, s.problem);
            let expect = if i == 2 { ChangeLevel::None } else { ChangeLevel::Signing };
            assert_eq!(s.later.level, expect, "{base} #{i}: {:?}", s.later.notes);
        }
        assert_eq!(report.signatures[1].signer_name(), "Bob Dvořák");
        assert_eq!(report.signatures[0].signer.as_ref().unwrap().issuer.display_name(), "RockSign Test Root CA");
    }
}

/// One person stamps pages 2 and 4 in one go (one signature each), then the next person signs.
#[test]
fn one_person_signs_several_pages() {
    let original = fixture("four_pages.pdf");
    let s1 = sign_as(&original, "alice", new_field(1, 40.0));
    let s2 = sign_as(&s1, "alice", new_field(3, 300.0));
    let s3 = sign_as(&s2, "bob", new_field(3, 40.0));
    assert!(s3.starts_with(&s2) && s2.starts_with(&s1) && s1.starts_with(&original));

    let report = analyze(&s3).unwrap();
    assert_eq!(report.signatures.len(), 3);
    let pages: Vec<_> = report.signatures.iter().map(|s| s.page).collect();
    assert_eq!(pages, [Some(1), Some(3), Some(3)]);
    for (i, s) in report.signatures.iter().enumerate() {
        assert!(s.is_intact() && s.signature_valid, "#{i}: {:?} {:?}", s.integrity, s.problem);
        let expect = if i == 2 { ChangeLevel::None } else { ChangeLevel::Signing };
        assert_eq!(s.later.level, expect, "#{i}: {:?}", s.later.notes);
    }
    let names: Vec<_> = report.signatures.iter().map(|s| s.signer_name()).collect();
    assert_eq!(names, ["Alice Nováková", "Alice Nováková", "Bob Dvořák"]);
}

#[test]
fn tampering_is_detected() {
    let signed = sign_as(&fixture("plain.pdf"), "alice", new_field(0, 40.0));
    let report = analyze(&signed).unwrap();
    let br_end = report.signatures[0].revision_end;
    // Flip a byte inside the signed part (in the original page content).
    let mut bad = signed.clone();
    bad[400] ^= 0x01;
    assert!(bad.len() == br_end);
    let report = analyze(&bad).unwrap();
    assert_eq!(report.signatures[0].integrity, Integrity::Altered);
}

#[test]
fn prepared_boxes_for_each_person() {
    use rocksign_core::sign::{EmptyField, add_empty_fields};
    let font = std::fs::read("/System/Library/Fonts/Supplemental/Arial.ttf").ok();
    let font = font.as_deref().map(|data| FontData { data, index: 0 });
    let boxes = ["Alice", "Bob", "Carol"]
        .iter()
        .enumerate()
        .map(|(i, who)| EmptyField { page: 0, rect: [40.0 + i as f32 * 180.0, 60.0, 200.0 + i as f32 * 180.0, 110.0], label: who.to_string() })
        .collect::<Vec<_>>();
    let prepared = add_empty_fields(&fixture("plain.pdf"), &boxes, font).unwrap();
    let r = analyze(&prepared).unwrap();
    assert_eq!(r.empty_fields().count(), 3);

    let s1 = sign_as(&prepared, "alice", Target::Field { name: "Alice".into() });
    let s2 = sign_as(&s1, "bob", Target::Field { name: "Bob".into() });
    let r = analyze(&s2).unwrap();
    assert_eq!(r.signatures.len(), 2);
    assert_eq!(r.empty_fields().map(|f| f.name.as_str()).collect::<Vec<_>>(), ["Carol"]);
    assert!(r.signatures.iter().all(|s| s.is_intact()));
    assert_eq!(r.signatures[0].later.level, ChangeLevel::Signing, "{:?}", r.signatures[0].later.notes);
    assert!(r.signatures[0].rect.is_some());
}
