//! Sign a PDF with a key from a PEM file. For tests only; the app signs with the Keychain.
//!
//!     cargo run -p rocksign-core --example sign_soft -- in.pdf out.pdf key.pem cert.pem \
//!         [--chain ca.pem] [--page 1 --rect x0,y0,x1,y1 | --field NAME | --invisible] [--tsa URL] [--reason TEXT]

use anyhow::{Result, bail};
use rocksign_core::cms::{self, KeyKind};
use rocksign_core::sign::{self, DEFAULT_RESERVE, SignRequest, Target};
use rocksign_core::stamp::{FontData, LogoMode, Stamp, StampText};
use rocksign_core::x509::certificates_from_pem as pem_certs;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 4 {
        bail!("usage: sign_soft in.pdf out.pdf key.pem cert.pem [options]");
    }
    let opt = |name: &str| args.iter().position(|a| a == name).and_then(|i| args.get(i + 1)).cloned();
    let input = std::fs::read(&args[0])?;
    let key_pem = std::fs::read_to_string(&args[2])?;
    let cert = pem_certs(&std::fs::read_to_string(&args[3])?)?.remove(0);
    let chain = match opt("--chain") {
        Some(p) => pem_certs(&std::fs::read_to_string(p)?)?,
        None => Vec::new(),
    };

    let target = if args.iter().any(|a| a == "--invisible") {
        Target::Invisible
    } else if let Some(name) = opt("--field") {
        Target::Field { name }
    } else {
        let page: usize = opt("--page").unwrap_or("1".into()).parse()?;
        let r: Vec<f32> = opt("--rect").unwrap_or("50,50,250,110".into()).split(',').map(|v| v.parse().unwrap()).collect();
        Target::NewField { page: page - 1, rect: [r[0], r[1], r[2], r[3]] }
    };

    let font = std::fs::read("/System/Library/Fonts/Supplemental/Arial.ttf")?;
    let bold = std::fs::read("/System/Library/Fonts/Supplemental/Arial Bold.ttf")?;
    let logo = if args.iter().any(|a| a == "--logo") { Some(rocksign_core::logo::Logo::rocksign()?) } else { None };
    let now = chrono::Local::now().fixed_offset();
    let name = cert.display_name();
    let reason = opt("--reason");
    let req = SignRequest {
        target,
        signer_name: name.clone(),
        reason: reason.clone(),
        location: None,
        time: now,
        stamp: Some(Stamp {
            text: StampText { name: name.clone(), date: now.format("%Y-%m-%d %H:%M:%S %:z").to_string(), reason: reason.clone() },
            regular: FontData { data: &font, index: 0 },
            bold: Some(FontData { data: &bold, index: 0 }),
            logo: logo.as_ref(),
            logo_mode: if args.iter().any(|a| a == "--watermark") {
                LogoMode::Watermark(rocksign_core::stamp::Watermark::centered(0.25))
            } else {
                LogoMode::Header
            },
        }),
        reserve: DEFAULT_RESERVE,
    };

    let prepared = sign::prepare(&input, &req)?;
    let attrs = cms::signed_attributes(&prepared.digest, &cert);
    let signature = match KeyKind::of(&cert)? {
        KeyKind::Rsa => {
            use rsa::pkcs8::DecodePrivateKey;
            use sha2::Digest;
            let key = rsa::RsaPrivateKey::from_pkcs8_pem(&key_pem)?;
            key.sign(rsa::Pkcs1v15Sign::new::<sha2::Sha256>(), &sha2::Sha256::digest(&attrs))?
        }
        KeyKind::Ec => {
            use p256::ecdsa::signature::Signer;
            use p256::pkcs8::DecodePrivateKey;
            let key = p256::ecdsa::SigningKey::from_pkcs8_pem(&key_pem)?;
            let sig: p256::ecdsa::Signature = key.sign(&attrs);
            sig.to_der().as_bytes().to_vec()
        }
    };
    let token = match opt("--tsa") {
        Some(url) => {
            let request = cms::timestamp_request(&signature, rand_nonce());
            let mut resp = ureq::post(&url).header("Content-Type", "application/timestamp-query").send(&request[..])?;
            let body = resp.body_mut().read_to_vec()?;
            Some(cms::timestamp_from_response(&body, &signature)?)
        }
        None => None,
    };
    let der = cms::signed_data(&attrs, &signature, &cert, &chain, token.as_deref())?;
    let out = sign::embed(prepared, &der)?;
    std::fs::write(&args[1], out)?;
    println!("signed {} as {name} → {}", args[0], args[1]);
    Ok(())
}

fn rand_nonce() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos() as u64).unwrap_or(1) | 1
}
