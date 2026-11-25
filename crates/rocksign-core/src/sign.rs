//! Signing in two steps, so the private key can live anywhere (Keychain, smart card, a server):
//!
//! 1. [`prepare`] appends the signature field, its stamp and an empty /Contents placeholder,
//!    and returns the SHA-256 digest of every byte except that placeholder.
//! 2. The caller builds the CMS signature over the digest (see [`crate::cms`]) and calls
//!    [`embed`] to write it into the placeholder.

use anyhow::{Context, Result, bail};
use chrono::{DateTime, FixedOffset};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream};
use sha2::{Digest, Sha256};

use crate::logo::Logo;
use crate::pdf::{self, Pdf, encode_text, format_date};
use crate::stamp::{self, Stamp};
use crate::writer::{Update, format_real, hex, write_object};

/// Bytes reserved for the CMS signature: room for a 4096-bit key, a certificate chain and a
/// timestamp token with its own chain.
pub const DEFAULT_RESERVE: usize = 32 * 1024;

/// Annotation flags: Print + Locked.
const WIDGET_FLAGS: i64 = 4 | 128;

#[derive(Clone, Debug)]
pub enum Target {
    /// A new signature field on page `page` (0-based) at `rect` in user space.
    NewField { page: usize, rect: [f32; 4] },
    /// An existing, empty signature field (for example one prepared for this person).
    Field { name: String },
    /// No stamp on the page.
    Invisible,
}

pub struct SignRequest<'a> {
    pub target: Target,
    /// Shown in signature panels (/Name).
    pub signer_name: String,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub time: DateTime<FixedOffset>,
    /// The visible stamp; None draws an empty box.
    pub stamp: Option<Stamp<'a>>,
    pub reserve: usize,
}

pub struct Prepared {
    pub bytes: Vec<u8>,
    /// Byte offsets of the /Contents hex string, angle brackets included.
    pub contents: (usize, usize),
    /// SHA-256 over everything except /Contents; this is what the signature covers.
    pub digest: [u8; 32],
    pub field_name: String,
}

/// Why a document cannot be signed, checked before asking for the key.
pub fn signing_blocker(pdf: &Pdf) -> Option<String> {
    if pdf.encrypted {
        return Some("This PDF is password-protected. Signing encrypted PDFs isn't supported yet.".into());
    }
    if pdf.doc.xref_recovery.is_some() {
        return Some("This PDF's internal structure is damaged, so a signature added to it might not verify elsewhere.".into());
    }
    if pdf.certification == Some(1) {
        return Some("This document was certified with no further changes allowed. A new signature would break that certification.".into());
    }
    None
}

pub fn prepare(original: &[u8], req: &SignRequest) -> Result<Prepared> {
    let pdf = Pdf::parse(original)?;
    if let Some(why) = signing_blocker(&pdf) {
        bail!(why);
    }
    let doc = &pdf.doc;
    let mut upd = Update::new(original, doc);
    let sig_id = upd.alloc();

    let field_name = match &req.target {
        Target::NewField { page, rect } => {
            let geom = pdf.pages.get(*page).context("that page does not exist")?;
            let name = unique_name(&pdf);
            let ap = appearance(&mut upd, geom.rotate, *rect, stamp_content(req))?;
            add_widgets(&mut upd, doc, &[NewWidget { name: &name, sig: Some(sig_id), page_id: geom.id, rect: *rect, ap }])?;
            name
        }
        Target::Invisible => {
            let geom = pdf.pages.first().context("the PDF has no pages")?;
            let name = unique_name(&pdf);
            let ap = empty_appearance(&mut upd);
            add_widgets(&mut upd, doc, &[NewWidget { name: &name, sig: Some(sig_id), page_id: geom.id, rect: [0.0; 4], ap }])?;
            name
        }
        Target::Field { name } => {
            let field = pdf.fields.iter().find(|f| &f.name == name).with_context(|| format!("there is no field \"{name}\""))?;
            if field.sig.is_some() {
                bail!("\"{name}\" is already signed");
            }
            let field_id = field.field_id.context("this signature field cannot be updated")?;
            let widget_id = field.widget_id.unwrap_or(field_id);
            let rect = field.rect.unwrap_or([0.0; 4]);
            let rotate = field.page.and_then(|p| pdf.pages.get(p)).map(|g| g.rotate).unwrap_or(0);
            let ap = if field.is_visible() { appearance(&mut upd, rotate, rect, stamp_content(req))? } else { empty_appearance(&mut upd) };

            let mut fd = doc.get_object(field_id)?.as_dict()?.clone();
            fd.set("V", Object::Reference(sig_id));
            if widget_id == field_id {
                fd.set("AP", ap_dict(ap));
                upd.set(field_id, &Object::Dictionary(fd));
            } else {
                upd.set(field_id, &Object::Dictionary(fd));
                let mut wd = doc.get_object(widget_id)?.as_dict()?.clone();
                wd.set("AP", ap_dict(ap));
                upd.set(widget_id, &Object::Dictionary(wd));
            }
            let flags = pdf::catalog(doc)
                .and_then(|c| pdf::dict(doc, c.get(b"AcroForm").ok()))
                .and_then(|f| f.get(b"SigFlags").ok())
                .and_then(|f| f.as_i64().ok())
                .unwrap_or(0);
            if flags & 3 != 3 {
                update_acroform(&mut upd, doc, &[])?;
            }
            name.clone()
        }
    };

    // The signature dictionary, written by hand so the placeholders' positions are known.
    let mut body = Vec::new();
    body.extend_from_slice(b"<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /M ");
    write_object(&mut body, &Object::string_literal(format_date(&req.time)));
    body.extend_from_slice(b" /Name ");
    write_object(&mut body, &encode_text(&req.signer_name));
    if let Some(r) = req.reason.as_deref().filter(|r| !r.trim().is_empty()) {
        body.extend_from_slice(b" /Reason ");
        write_object(&mut body, &encode_text(r));
    }
    if let Some(l) = req.location.as_deref().filter(|l| !l.trim().is_empty()) {
        body.extend_from_slice(b" /Location ");
        write_object(&mut body, &encode_text(l));
    }
    body.extend_from_slice(b" /ByteRange [0 ");
    let range_pos = body.len();
    body.extend_from_slice(b"0000000000 0000000000 0000000000]");
    body.extend_from_slice(b" /Contents ");
    let contents_pos = body.len();
    body.push(b'<');
    body.resize(body.len() + req.reserve * 2, b'0');
    body.push(b'>');
    body.extend_from_slice(b" >>");
    upd.set_raw(sig_id, body);

    let written = upd.write(doc)?;
    let mut bytes = written.bytes;
    let base = written.body_offsets[&sig_id];
    let c0 = base + contents_pos;
    let c1 = c0 + req.reserve * 2 + 2;
    let range = [c0, c1, bytes.len() - c1];
    for (i, v) in range.iter().enumerate() {
        let slot = base + range_pos + i * 11;
        let text = format!("{v:<10}");
        if text.len() > 10 {
            bail!("the PDF is too large to sign");
        }
        bytes[slot..slot + 10].copy_from_slice(text.as_bytes());
    }
    let mut h = Sha256::new();
    h.update(&bytes[..c0]);
    h.update(&bytes[c1..]);
    Ok(Prepared { bytes, contents: (c0, c1), digest: h.finalize().into(), field_name })
}

/// Write the CMS signature into the placeholder.
pub fn embed(prepared: Prepared, cms: &[u8]) -> Result<Vec<u8>> {
    let (c0, c1) = prepared.contents;
    let hex = hex(cms);
    if hex.len() > c1 - c0 - 2 {
        bail!("the signature ({} bytes) is larger than the space reserved for it", cms.len());
    }
    let mut bytes = prepared.bytes;
    bytes[c0 + 1..c0 + 1 + hex.len()].copy_from_slice(hex.as_bytes());
    Ok(bytes)
}

fn unique_name(pdf: &Pdf) -> String {
    (1..).map(|n| format!("Signature{n}")).find(|n| !pdf.fields.iter().any(|f| f.name == *n)).expect("an unused name")
}

fn ap_dict(ap: ObjectId) -> Object {
    let mut d = Dictionary::new();
    d.set("N", Object::Reference(ap));
    Object::Dictionary(d)
}

struct NewWidget<'n> {
    name: &'n str,
    sig: Option<ObjectId>,
    page_id: ObjectId,
    rect: [f32; 4],
    ap: ObjectId,
}

/// Create signature fields (merged field + widget) and attach them to their pages and the form.
fn add_widgets(upd: &mut Update, doc: &Document, widgets: &[NewWidget]) -> Result<()> {
    let mut by_page: Vec<(ObjectId, Vec<ObjectId>)> = Vec::new();
    let mut fields = Vec::new();
    for nw in widgets {
        let widget_id = upd.alloc();
        let mut w = Dictionary::new();
        w.set("Type", Object::Name(b"Annot".to_vec()));
        w.set("Subtype", Object::Name(b"Widget".to_vec()));
        w.set("FT", Object::Name(b"Sig".to_vec()));
        w.set("T", encode_text(nw.name));
        if let Some(sig) = nw.sig {
            w.set("V", Object::Reference(sig));
        }
        w.set("F", Object::Integer(WIDGET_FLAGS));
        w.set("Rect", Object::Array(nw.rect.iter().map(|v| Object::Real(*v)).collect()));
        w.set("P", Object::Reference(nw.page_id));
        w.set("AP", ap_dict(nw.ap));
        upd.set(widget_id, &Object::Dictionary(w));
        fields.push(widget_id);
        match by_page.iter_mut().find(|(p, _)| *p == nw.page_id) {
            Some((_, list)) => list.push(widget_id),
            None => by_page.push((nw.page_id, vec![widget_id])),
        }
    }

    for (page_id, new) in by_page {
        let refs = new.into_iter().map(Object::Reference);
        let mut page = doc.get_object(page_id)?.as_dict()?.clone();
        match page.get(b"Annots") {
            Ok(Object::Reference(arr_id)) => {
                let arr_id = *arr_id;
                let mut arr = pdf::array(doc, Some(&Object::Reference(arr_id))).to_vec();
                arr.extend(refs);
                upd.set(arr_id, &Object::Array(arr));
            }
            Ok(Object::Array(a)) => {
                let mut a = a.clone();
                a.extend(refs);
                page.set("Annots", Object::Array(a));
                upd.set(page_id, &Object::Dictionary(page));
            }
            _ => {
                page.set("Annots", Object::Array(refs.collect()));
                upd.set(page_id, &Object::Dictionary(page));
            }
        }
    }
    update_acroform(upd, doc, &fields)
}

/// Register a new field in the form (creating the form if needed) and set SigFlags.
fn update_acroform(upd: &mut Update, doc: &Document, new_fields: &[ObjectId]) -> Result<()> {
    let root_id = doc.trailer.get(b"Root")?.as_reference().context("the PDF has no catalog")?;
    let mut catalog = doc.get_object(root_id)?.as_dict()?.clone();

    let modify = |form: &mut Dictionary, upd: &mut Update| -> Result<()> {
        if !new_fields.is_empty() {
            let refs = new_fields.iter().map(|f| Object::Reference(*f));
            match form.get(b"Fields") {
                Ok(Object::Reference(fid)) => {
                    let fid = *fid;
                    let mut arr = pdf::array(doc, Some(&Object::Reference(fid))).to_vec();
                    arr.extend(refs);
                    upd.set(fid, &Object::Array(arr));
                }
                Ok(Object::Array(a)) => {
                    let mut a = a.clone();
                    a.extend(refs);
                    form.set("Fields", Object::Array(a));
                }
                _ => form.set("Fields", Object::Array(refs.collect())),
            }
        }
        form.set("SigFlags", Object::Integer(3));
        Ok(())
    };

    match catalog.get(b"AcroForm") {
        Ok(Object::Reference(form_id)) => {
            let form_id = *form_id;
            let mut form = doc.get_object(form_id)?.as_dict()?.clone();
            modify(&mut form, upd)?;
            upd.set(form_id, &Object::Dictionary(form));
        }
        Ok(Object::Dictionary(form)) => {
            let mut form = form.clone();
            modify(&mut form, upd)?;
            catalog.set("AcroForm", Object::Dictionary(form));
            upd.set(root_id, &Object::Dictionary(catalog));
        }
        _ => {
            let form_id = upd.alloc();
            let mut form = Dictionary::new();
            modify(&mut form, upd)?;
            upd.set(form_id, &Object::Dictionary(form));
            catalog.set("AcroForm", Object::Reference(form_id));
            upd.set(root_id, &Object::Dictionary(catalog));
        }
    }
    Ok(())
}

/// What a painter drew: content, the logo it draws as `/Logo`, and that logo's opacity.
type Painted<'p> = (Vec<u8>, Option<&'p Logo>, Option<f32>);
type Painter<'p> = Box<dyn Fn(f32, f32) -> Result<Painted<'p>> + 'p>;

fn stamp_content<'p>(req: &'p SignRequest) -> Painter<'p> {
    Box::new(move |w, h| match &req.stamp {
        Some(s) => {
            let d = stamp::draw(w, h, s)?;
            Ok((d.content, if d.uses_logo { s.logo } else { None }, d.logo_opacity))
        }
        None => Ok((Vec::new(), None, None)),
    })
}

/// A form XObject the size of `rect`, painted by `paint(width, height)` in view orientation.
/// On rotated pages the drawing is counter-rotated inside the stream (rather than with /Matrix,
/// which PDFKit ignores) so it reads upright as shown.
fn appearance(upd: &mut Update, rotate: u16, rect: [f32; 4], paint: Painter) -> Result<ObjectId> {
    let (rw, rh) = (rect[2] - rect[0], rect[3] - rect[1]);
    let (w, h) = if rotate % 180 == 90 { (rh, rw) } else { (rw, rh) };
    let (painted, logo, opacity) = paint(w, h)?;
    let cm = match rotate {
        90 => Some(format!("0 1 -1 0 {} 0 cm", format_real(rw))),
        180 => Some(format!("-1 0 0 -1 {} {} cm", format_real(rw), format_real(rh))),
        270 => Some(format!("0 -1 1 0 0 {} cm", format_real(rh))),
        _ => None,
    };
    let content = match cm {
        Some(cm) if !painted.is_empty() => [format!("q {cm}\n").into_bytes(), painted, b"Q\n".to_vec()].concat(),
        _ => painted,
    };
    let mut d = Dictionary::new();
    d.set("Type", Object::Name(b"XObject".to_vec()));
    d.set("Subtype", Object::Name(b"Form".to_vec()));
    d.set("BBox", Object::Array(vec![0.into(), 0.into(), Object::Real(rw), Object::Real(rh)]));
    let mut resources = Dictionary::new();
    if let Some(logo) = logo {
        let (mut image, mask) = logo.pdf_streams()?;
        let mask_id = upd.alloc();
        upd.set(mask_id, &Object::Stream(mask));
        image.dict.set("SMask", Object::Reference(mask_id));
        let image_id = upd.alloc();
        upd.set(image_id, &Object::Stream(image));
        let mut xobjects = Dictionary::new();
        xobjects.set("Logo", Object::Reference(image_id));
        resources.set("XObject", Object::Dictionary(xobjects));
    }
    if let Some(alpha) = opacity {
        let mut gs = Dictionary::new();
        gs.set("Type", Object::Name(b"ExtGState".to_vec()));
        gs.set("ca", Object::Real(alpha));
        gs.set("CA", Object::Real(alpha));
        let mut states = Dictionary::new();
        states.set("GSLogo", Object::Dictionary(gs));
        resources.set("ExtGState", Object::Dictionary(states));
    }
    d.set("Resources", Object::Dictionary(resources));
    let id = upd.alloc();
    upd.set(id, &Object::Stream(Stream::new(d, content)));
    Ok(id)
}

fn empty_appearance(upd: &mut Update) -> ObjectId {
    let mut d = Dictionary::new();
    d.set("Type", Object::Name(b"XObject".to_vec()));
    d.set("Subtype", Object::Name(b"Form".to_vec()));
    d.set("BBox", Object::Array(vec![0.into(), 0.into(), 0.into(), 0.into()]));
    let id = upd.alloc();
    upd.set(id, &Object::Stream(Stream::new(d, Vec::new())));
    id
}

/// An empty signature box to be signed later, e.g. one per person who has to sign.
pub struct EmptyField {
    pub page: usize,
    /// User-space rectangle.
    pub rect: [f32; 4],
    /// Who should sign here; becomes the field name and is printed in the box.
    pub label: String,
}

/// Add empty signature fields as one new revision.
pub fn add_empty_fields(original: &[u8], fields: &[EmptyField], font: Option<stamp::FontData>) -> Result<Vec<u8>> {
    let pdf = Pdf::parse(original)?;
    if let Some(why) = signing_blocker(&pdf) {
        bail!(why);
    }
    let doc = &pdf.doc;
    let mut upd = Update::new(original, doc);
    let mut names: Vec<String> = pdf.fields.iter().map(|f| f.name.clone()).collect();
    let mut widgets = Vec::new();
    for f in fields {
        let geom = pdf.pages.get(f.page).context("that page does not exist")?;
        let base = f.label.trim().replace('.', " ");
        let base = if base.is_empty() { "Signature".to_string() } else { base };
        let name = std::iter::once(base.clone()).chain((2..).map(|n| format!("{base} {n}"))).find(|n| !names.contains(n)).expect("an unused name");
        names.push(name.clone());
        let label = f.label.clone();
        let paint: Painter = Box::new(move |w, h| Ok((empty_box(w, h, &label, font)?, None, None)));
        let ap = appearance(&mut upd, geom.rotate, f.rect, paint)?;
        widgets.push((name, geom.id, f.rect, ap));
    }
    let list: Vec<NewWidget> =
        widgets.iter().map(|(name, page_id, rect, ap)| NewWidget { name, sig: None, page_id: *page_id, rect: *rect, ap: *ap }).collect();
    add_widgets(&mut upd, doc, &list)?;
    Ok(upd.write(doc)?.bytes)
}

/// A light frame with "Sign here" and the person's name.
fn empty_box(w: f32, h: f32, label: &str, font: Option<stamp::FontData>) -> Result<Vec<u8>> {
    let mut out = format!("q 0.55 0.6 0.75 RG 0.75 w 0.5 0.5 {} {} re S Q\n", w - 1.0, h - 1.0).into_bytes();
    if let Some(font) = font {
        let fonts = stamp::Fonts::parse(font, None)?;
        let lines = [stamp::StampLine::plain("Sign here", 0.8, false, 0.5), stamp::StampLine::plain(label, 1.1, false, 0.35)];
        out.extend(stamp::draw_lines(w, h, &lines, &fonts));
    }
    Ok(out)
}
