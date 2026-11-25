//! Checking every signature in a PDF: is the signed part untouched, does the signature verify,
//! who signed, when (timestamp), and what changed in the file after each signature.

use std::collections::HashSet;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, FixedOffset, Utc};
use lopdf::{Dictionary, Document, Object, ObjectId};

use crate::cms::{self, SignedData};
use crate::crypto::HashAlg;
use crate::pdf::{self, PageGeom, Pdf, SigField};
use crate::writer::serialize;
use crate::x509::Certificate;

#[derive(Clone, Debug, PartialEq)]
pub enum Integrity {
    /// The signed bytes hash to the value inside the signature.
    Intact,
    /// The signed bytes were changed after signing.
    Altered,
    /// The signature could not be checked at all.
    Malformed(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChangeLevel {
    None,
    /// Only signatures (and their validation data) were added.
    Signing,
    /// Document information or XMP metadata changed.
    Metadata,
    /// Form fields were filled in.
    FormFill,
    /// Comments or other annotations were added, changed or removed.
    Annotations,
    /// Page content, resources or structure changed.
    Content,
}

#[derive(Clone, Debug)]
pub struct LaterChanges {
    pub level: ChangeLevel,
    pub notes: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum SigKind {
    Approval,
    /// Certification signature with its DocMDP permission level.
    Certification(u8),
    /// RFC 3161 document timestamp.
    DocTimestamp,
}

#[derive(Clone, Debug)]
pub struct TimestampReport {
    pub time: DateTime<Utc>,
    pub authority: Option<Certificate>,
    pub certificates: Vec<Certificate>,
    pub valid: bool,
    pub problem: Option<String>,
}

#[derive(Clone, Debug)]
pub struct SignatureReport {
    pub field: String,
    pub page: Option<usize>,
    pub rect: Option<[f32; 4]>,
    pub kind: SigKind,
    pub sub_filter: String,
    pub signer: Option<Certificate>,
    /// Every certificate in the signature (to build the chain for trust checks).
    pub certificates: Vec<Certificate>,
    /// /M: the signer's computer clock, not proof of time.
    pub claimed_time: Option<DateTime<FixedOffset>>,
    pub timestamp: Option<TimestampReport>,
    pub name: Option<String>,
    pub reason: Option<String>,
    pub location: Option<String>,
    pub contact: Option<String>,
    pub integrity: Integrity,
    pub signature_valid: bool,
    pub problem: Option<String>,
    pub algorithm: String,
    /// End of the revision this signature covers.
    pub revision_end: usize,
    pub covers_whole_file: bool,
    pub later: LaterChanges,
}

impl SignatureReport {
    /// Signed bytes untouched and the signature verifies.
    pub fn is_intact(&self) -> bool {
        self.integrity == Integrity::Intact && self.signature_valid
    }

    pub fn signer_name(&self) -> String {
        self.signer.as_ref().map(|c| c.display_name()).or_else(|| self.name.clone()).unwrap_or_else(|| "Unknown signer".into())
    }

    /// Best known signing time: the timestamp if valid, else the signer's clock.
    pub fn time(&self) -> Option<DateTime<Utc>> {
        self.timestamp.as_ref().filter(|t| t.valid).map(|t| t.time).or_else(|| self.claimed_time.map(|t| t.with_timezone(&Utc)))
    }
}

#[derive(Clone, Debug)]
pub struct FieldInfo {
    pub name: String,
    pub page: Option<usize>,
    pub rect: Option<[f32; 4]>,
    pub signed: bool,
    pub visible: bool,
}

#[derive(Clone, Debug)]
pub struct Report {
    pub pages: Vec<PageGeom>,
    pub fields: Vec<FieldInfo>,
    /// In signing order.
    pub signatures: Vec<SignatureReport>,
    pub encrypted: bool,
    pub certification: Option<u8>,
    /// Why signing is not possible, if it isn't.
    pub signing_blocker: Option<String>,
}

impl Report {
    pub fn empty_fields(&self) -> impl Iterator<Item = &FieldInfo> {
        self.fields.iter().filter(|f| !f.signed)
    }
}

pub fn analyze(bytes: &[u8]) -> Result<Report> {
    let pdf = Pdf::parse(bytes)?;
    let mut signatures: Vec<SignatureReport> =
        pdf.fields.iter().filter_map(|f| f.sig.as_ref().map(|sig| check_signature(bytes, &pdf, f, sig))).collect();
    signatures.sort_by_key(|s| s.revision_end);
    let fields = pdf
        .fields
        .iter()
        .filter(|f| f.field_id.is_some())
        .map(|f| FieldInfo { name: f.name.clone(), page: f.page, rect: f.rect, signed: f.sig.is_some(), visible: f.is_visible() })
        .collect();
    Ok(Report {
        signing_blocker: crate::sign::signing_blocker(&pdf),
        pages: pdf.pages,
        fields,
        signatures,
        encrypted: pdf.encrypted,
        certification: pdf.certification,
    })
}

fn opt_text(doc: &Document, d: &Dictionary, key: &[u8]) -> Option<String> {
    d.get(key).ok().and_then(|o| pdf::text(doc, o)).filter(|s| !s.trim().is_empty())
}

fn check_signature(bytes: &[u8], pdf: &Pdf, field: &SigField, sig: &Dictionary) -> SignatureReport {
    let doc = &pdf.doc;
    let sub_filter = pdf::name(sig.get(b"SubFilter").ok()).map(|n| String::from_utf8_lossy(n).into_owned()).unwrap_or_default();
    let is_doc_ts = pdf::name(sig.get(b"Type").ok()) == Some(b"DocTimeStamp") || sub_filter == "ETSI.RFC3161";
    let kind =
        if is_doc_ts { SigKind::DocTimestamp } else { pdf::docmdp_permission(doc, sig).map(SigKind::Certification).unwrap_or(SigKind::Approval) };
    let mut r = SignatureReport {
        field: field.name.clone(),
        page: field.page,
        rect: field.rect.filter(|_| field.is_visible()),
        kind,
        sub_filter: sub_filter.clone(),
        signer: None,
        certificates: Vec::new(),
        claimed_time: opt_text(doc, sig, b"M").and_then(|m| pdf::parse_date(&m)),
        timestamp: None,
        name: opt_text(doc, sig, b"Name"),
        reason: opt_text(doc, sig, b"Reason"),
        location: opt_text(doc, sig, b"Location"),
        contact: opt_text(doc, sig, b"ContactInfo"),
        integrity: Integrity::Malformed(String::new()),
        signature_valid: false,
        problem: None,
        algorithm: String::new(),
        revision_end: 0,
        covers_whole_file: false,
        later: LaterChanges { level: ChangeLevel::None, notes: Vec::new() },
    };

    let ranges = match byte_range(bytes, sig) {
        Ok(v) => v,
        Err(e) => {
            r.integrity = Integrity::Malformed(e.to_string());
            r.problem = Some(e.to_string());
            return r;
        }
    };
    let [a, b, c, d] = ranges;
    r.revision_end = c + d;
    r.covers_whole_file = bytes[c + d..].iter().all(|x| x.is_ascii_whitespace() || *x == 0);
    let signed = [&bytes[a..a + b], &bytes[c..c + d]];
    let contents = pdf::contents(sig).unwrap_or_default();

    if let Err(e) = check_cms(&mut r, &sub_filter, is_doc_ts, &contents, &signed) {
        r.integrity = Integrity::Malformed(e.to_string());
        r.problem = Some(e.to_string());
    }

    if !r.covers_whole_file {
        r.later = later_changes(&bytes[..c + d], doc);
    }
    r
}

/// /ByteRange as [start1, len1, start2, len2], checked to exclude exactly the /Contents string.
fn byte_range(bytes: &[u8], sig: &Dictionary) -> Result<[usize; 4]> {
    let arr = match sig.get(b"ByteRange") {
        Ok(Object::Array(a)) => a,
        _ => bail!("the signature has no byte range"),
    };
    let v: Vec<i64> = arr.iter().filter_map(|o| o.as_i64().ok()).collect();
    if v.len() != 4 || v.iter().any(|x| *x < 0) {
        bail!("the signature's byte range is malformed");
    }
    let [a, b, c, d] = [v[0] as usize, v[1] as usize, v[2] as usize, v[3] as usize];
    let ok = a == 0 && b < c && c.checked_add(d).is_some_and(|end| end <= bytes.len());
    if !ok {
        bail!("the signature's byte range does not fit the file");
    }
    // The gap must be exactly the /Contents hex string.
    let gap = &bytes[b..c];
    let well_formed = gap.first() == Some(&b'<')
        && gap.last() == Some(&b'>')
        && gap[1..gap.len() - 1].iter().all(|x| x.is_ascii_hexdigit() || x.is_ascii_whitespace());
    if !well_formed {
        bail!("the signature's byte range does not match its contents");
    }
    Ok([a, b, c, d])
}

fn check_cms(r: &mut SignatureReport, sub_filter: &str, is_doc_ts: bool, contents: &[u8], signed: &[&[u8]; 2]) -> Result<()> {
    if is_doc_ts {
        let info = cms::parse_timestamp_token(contents)?;
        r.integrity = if info.covers(signed) { Integrity::Intact } else { Integrity::Altered };
        r.signature_valid = info.check.signature_valid;
        r.problem = info.check.problem.clone();
        r.algorithm = info.check.algorithm.clone();
        r.signer = info.check.certificate.clone();
        r.certificates = info.certificates.clone();
        r.timestamp = Some(TimestampReport {
            time: info.time,
            authority: info.check.certificate.clone(),
            certificates: info.certificates.clone(),
            valid: info.is_valid(),
            problem: info.check.problem.clone(),
        });
        return Ok(());
    }
    let sd: SignedData = cms::parse_signed_data(contents)?;
    let signer = sd.signers.first().context("the signature has no signer")?;
    let digest = signer.digest()?;
    let check = match sub_filter {
        "adbe.pkcs7.detached" | "ETSI.CAdES.detached" | "" => {
            let content_digest = digest.digest(signed);
            cms::check_signer(&sd, signer, &content_digest)
        }
        "adbe.pkcs7.sha1" => {
            // The signed content is the SHA-1 digest of the byte range.
            let inner = sd.econtent.as_deref().context("the signature has no content")?;
            let mut check = cms::check_signer(&sd, signer, &digest.digest(&[inner]));
            if inner != HashAlg::Sha1.digest(signed) {
                check.digest_matches = false;
                check.problem.get_or_insert_with(|| "the signed digest does not match the document".into());
            }
            check
        }
        other => bail!("unsupported signature format ({other})"),
    };
    r.integrity = if check.digest_matches { Integrity::Intact } else { Integrity::Altered };
    r.signature_valid = check.signature_valid;
    r.problem = check.problem.clone();
    r.algorithm = check.algorithm.clone();
    r.signer = check.certificate.clone();
    r.certificates = sd.certificates.clone();

    if let Some(token) = cms::signature_timestamp(signer)? {
        r.timestamp = Some(match cms::parse_timestamp_token(token) {
            Ok(info) => {
                let covers = info.covers(&[signer.signature]);
                TimestampReport {
                    time: info.time,
                    authority: info.check.certificate.clone(),
                    certificates: info.certificates.clone(),
                    valid: covers && info.is_valid(),
                    problem: if covers { info.check.problem.clone() } else { Some("the timestamp is for a different signature".into()) },
                }
            }
            Err(e) => TimestampReport {
                time: DateTime::<Utc>::MIN_UTC,
                authority: None,
                certificates: Vec::new(),
                valid: false,
                problem: Some(e.to_string()),
            },
        });
    }
    Ok(())
}

// --- what changed after a signature -----------------------------------------

/// Compare the signed revision with the current file.
fn later_changes(signed_revision: &[u8], current: &Document) -> LaterChanges {
    let old = match Document::load_mem(signed_revision) {
        Ok(d) => d,
        Err(e) => {
            return LaterChanges {
                level: ChangeLevel::Content,
                notes: vec![format!("The signed version could not be read back for comparison ({e}).")],
            };
        }
    };
    let mut out = Diff { old: &old, new: current, level: ChangeLevel::None, notes: Vec::new(), roles: Roles::of(current) };
    let old_root = old.trailer.get(b"Root").ok().and_then(|r| r.as_reference().ok());
    if old_root != out.roles.root {
        out.add(ChangeLevel::Content, "The document catalog was replaced.".into());
    }
    for (id, new_obj) in &current.objects {
        let Some(old_obj) = old.objects.get(id) else { continue };
        if serialize(old_obj) != serialize(new_obj) {
            out.modified(*id, old_obj, new_obj);
        }
    }
    for (id, old_obj) in &old.objects {
        if !current.objects.contains_key(id) && !is_structural_stream(old_obj) {
            out.add(ChangeLevel::Content, format!("Object {} was removed.", id.0));
        }
    }
    if out.level == ChangeLevel::None {
        // New revisions that only add unreferenced objects (or rewrite identical ones).
        out.level = ChangeLevel::Signing;
    }
    LaterChanges { level: out.level, notes: out.notes }
}

fn is_structural_stream(obj: &Object) -> bool {
    matches!(obj, Object::Stream(s) if matches!(pdf::name(s.dict.get(b"Type").ok()), Some(b"XRef" | b"ObjStm")))
}

/// Roles of objects in the current document, to judge changes to them.
struct Roles {
    root: Option<ObjectId>,
    info: Option<ObjectId>,
    acroform: Option<ObjectId>,
    fields_array: Option<ObjectId>,
    dss: Option<ObjectId>,
    metadata: Option<ObjectId>,
    /// Page objects and indirect /Annots arrays, with their page number (1-based).
    pages: Vec<(ObjectId, usize)>,
    annots_arrays: Vec<(ObjectId, usize)>,
}

impl Roles {
    fn of(doc: &Document) -> Roles {
        let r = |o: Option<&Object>| o.and_then(|o| o.as_reference().ok());
        let root = r(doc.trailer.get(b"Root").ok());
        let catalog = pdf::catalog(doc);
        let acroform = catalog.and_then(|c| r(c.get(b"AcroForm").ok()));
        let fields_array = catalog.and_then(|c| pdf::dict(doc, c.get(b"AcroForm").ok())).and_then(|f| r(f.get(b"Fields").ok()));
        let mut pages = Vec::new();
        let mut annots_arrays = Vec::new();
        for (n, id) in doc.get_pages() {
            pages.push((id, n as usize));
            if let Some(Object::Dictionary(p)) = doc.objects.get(&id)
                && let Some(a) = r(p.get(b"Annots").ok())
            {
                annots_arrays.push((a, n as usize));
            }
        }
        Roles {
            root,
            info: r(doc.trailer.get(b"Info").ok()),
            acroform,
            fields_array,
            dss: catalog.and_then(|c| r(c.get(b"DSS").ok())),
            metadata: catalog.and_then(|c| r(c.get(b"Metadata").ok())),
            pages,
            annots_arrays,
        }
    }
}

struct Diff<'a> {
    old: &'a Document,
    new: &'a Document,
    level: ChangeLevel,
    notes: Vec<String>,
    roles: Roles,
}

/// Catalog entries signing tools touch: the form, validation data, and the PDF version or
/// developer extensions (pyHanko and Acrobat raise them when signing).
const SIGNING_CATALOG_KEYS: &[&[u8]] = &[b"AcroForm", b"DSS", b"Extensions", b"Version"];
const SIGNING_FORM_KEYS: &[&[u8]] = &[b"Fields", b"SigFlags", b"DR", b"DA", b"NeedAppearances"];

impl Diff<'_> {
    fn add(&mut self, level: ChangeLevel, note: String) {
        self.level = self.level.max(level);
        if level > ChangeLevel::Signing && !self.notes.contains(&note) {
            self.notes.push(note);
        }
    }

    fn modified(&mut self, id: ObjectId, old_obj: &Object, new_obj: &Object) {
        if is_structural_stream(new_obj) || is_structural_stream(old_obj) {
            return;
        }
        if Some(id) == self.roles.info {
            return self.add(ChangeLevel::Metadata, "Document information (title, author…) was updated.".into());
        }
        if Some(id) == self.roles.metadata {
            return self.add(ChangeLevel::Metadata, "Document metadata was updated.".into());
        }
        if Some(id) == self.roles.dss {
            return self.add(ChangeLevel::Signing, String::new());
        }
        if let Some(&(_, page)) = self.roles.annots_arrays.iter().find(|(a, _)| *a == id) {
            return self.annots(page, Some(old_obj), Some(new_obj));
        }
        if Some(id) == self.roles.fields_array {
            return self.fields(Some(old_obj), Some(new_obj));
        }
        let (Some(od), Some(nd)) = (as_dict(old_obj), as_dict(new_obj)) else {
            if self.is_old_appearance(id) {
                return self.add(ChangeLevel::FormFill, "A form field's appearance was changed.".into());
            }
            return self.add(ChangeLevel::Content, format!("Object {} (page content or resources) was changed.", id.0));
        };
        let changed = changed_keys(od, nd);

        if Some(id) == self.roles.root {
            if changed.iter().all(|k| SIGNING_CATALOG_KEYS.contains(&k.as_slice())) {
                if changed.iter().any(|k| k == b"AcroForm") {
                    self.form(od.get(b"AcroForm").ok(), nd.get(b"AcroForm").ok());
                }
                return self.add(ChangeLevel::Signing, String::new());
            }
            if changed.iter().all(|k| SIGNING_CATALOG_KEYS.contains(&k.as_slice()) || k == b"Metadata") {
                return self.add(ChangeLevel::Metadata, "Document metadata was updated.".into());
            }
            return self.add(ChangeLevel::Content, format!("The document catalog changed ({}).", key_list(&changed)));
        }
        if Some(id) == self.roles.acroform {
            return self.form(Some(old_obj), Some(new_obj));
        }
        if let Some(&(_, page)) = self.roles.pages.iter().find(|(p, _)| *p == id) {
            if changed.iter().all(|k| k == b"Annots") {
                return self.annots(page, od.get(b"Annots").ok(), nd.get(b"Annots").ok());
            }
            return self.add(ChangeLevel::Content, format!("Page {page} was changed ({}).", key_list(&changed)));
        }
        if is_sig_field(self.new, nd) || is_sig_field(self.old, od) {
            let was_signed = od.has(b"V");
            if was_signed && changed.iter().any(|k| k == b"V") {
                return self.add(ChangeLevel::Content, "An existing signature was replaced.".into());
            }
            if changed.iter().all(|k| [&b"V"[..], b"AP", b"F", b"Lock", b"SV"].contains(&k.as_slice())) {
                return self.add(ChangeLevel::Signing, String::new());
            }
            return self.add(ChangeLevel::Annotations, "A signature field was changed.".into());
        }
        if matches!(pdf::name(od.get(b"Type").ok()), Some(b"Sig" | b"DocTimeStamp")) {
            return self.add(ChangeLevel::Content, "An existing signature was modified.".into());
        }
        if od.has(b"FT") || is_form_field(self.old, od) {
            let label = od.get(b"T").ok().and_then(|t| pdf::text(self.old, t)).unwrap_or_else(|| "a form field".into());
            return self.add(ChangeLevel::FormFill, format!("Form field \"{label}\" was filled in or changed."));
        }
        if pdf::name(od.get(b"Type").ok()) == Some(b"Annot") || od.has(b"Subtype") && od.has(b"Rect") {
            return self.add(ChangeLevel::Annotations, "An annotation was changed.".into());
        }
        if self.is_old_appearance(id) {
            return self.add(ChangeLevel::FormFill, "A form field's appearance was changed.".into());
        }
        self.add(ChangeLevel::Content, format!("Object {} was changed.", id.0));
    }

    fn form(&mut self, old: Option<&Object>, new: Option<&Object>) {
        let od = old.and_then(|o| pdf::dict(self.old, Some(o)));
        let nd = new.and_then(|o| pdf::dict(self.new, Some(o)));
        let empty = Dictionary::new();
        let (od, nd) = (od.unwrap_or(&empty), nd.unwrap_or(&empty));
        let changed = changed_keys(od, nd);
        if !changed.iter().all(|k| SIGNING_FORM_KEYS.contains(&k.as_slice())) {
            return self.add(ChangeLevel::FormFill, format!("The form settings changed ({}).", key_list(&changed)));
        }
        if changed.iter().any(|k| k == b"Fields") {
            self.fields(od.get(b"Fields").ok(), nd.get(b"Fields").ok());
        }
        self.add(ChangeLevel::Signing, String::new());
    }

    fn fields(&mut self, old: Option<&Object>, new: Option<&Object>) {
        let old_list = pdf::array(self.old, old).to_vec();
        let new_list = pdf::array(self.new, new).to_vec();
        if old_list.iter().any(|f| !new_list.contains(f)) {
            return self.add(ChangeLevel::Content, "A form field was removed.".into());
        }
        for f in new_list.iter().filter(|f| !old_list.contains(f)) {
            match pdf::dict(self.new, Some(f)) {
                Some(d) if is_sig_field(self.new, d) => self.add(ChangeLevel::Signing, String::new()),
                _ => self.add(ChangeLevel::FormFill, "A form field was added.".into()),
            }
        }
    }

    fn annots(&mut self, page: usize, old: Option<&Object>, new: Option<&Object>) {
        let old_list = pdf::array(self.old, old).to_vec();
        let new_list = pdf::array(self.new, new).to_vec();
        for a in old_list.iter().filter(|a| !new_list.contains(a)) {
            match pdf::dict(self.old, Some(a)) {
                Some(d) if is_sig_field(self.old, d) => self.add(ChangeLevel::Content, format!("A signature was removed from page {page}.")),
                _ => self.add(ChangeLevel::Annotations, format!("An annotation was removed from page {page}.")),
            }
        }
        for a in new_list.iter().filter(|a| !old_list.contains(a)) {
            let Some(d) = pdf::dict(self.new, Some(a)) else { continue };
            let subtype = pdf::name(d.get(b"Subtype").ok()).map(|s| String::from_utf8_lossy(s).into_owned()).unwrap_or_default();
            if subtype == "Widget" && is_sig_field(self.new, d) {
                self.add(ChangeLevel::Signing, String::new());
            } else if subtype == "Widget" {
                self.add(ChangeLevel::FormFill, format!("A form field was added on page {page}."));
            } else if subtype == "Link" {
                self.add(ChangeLevel::Annotations, format!("A link was added on page {page}."));
            } else {
                let what = match subtype.as_str() {
                    "Text" | "FreeText" => "A comment",
                    "Highlight" | "Underline" | "StrikeOut" | "Squiggly" => "A text markup",
                    "Stamp" => "A stamp",
                    "Ink" => "A drawing",
                    _ => "An annotation",
                };
                self.add(ChangeLevel::Annotations, format!("{what} was added on page {page}."));
            }
        }
    }

    /// Whether `id` was the appearance stream of a form field in the signed version.
    fn is_old_appearance(&self, id: ObjectId) -> bool {
        let target = Object::Reference(id);
        self.old.objects.values().any(|o| {
            let Some(d) = as_dict(o) else { return false };
            if pdf::name(d.get(b"Subtype").ok()) != Some(b"Widget") {
                return false;
            }
            let Some(ap) = pdf::dict(self.old, d.get(b"AP").ok()) else { return false };
            ap.iter().any(|(_, v)| *v == target || pdf::dict(self.old, Some(v)).is_some_and(|states| states.iter().any(|(_, s)| *s == target)))
        })
    }
}

fn as_dict(o: &Object) -> Option<&Dictionary> {
    match o {
        Object::Dictionary(d) => Some(d),
        _ => None,
    }
}

fn changed_keys(a: &Dictionary, b: &Dictionary) -> Vec<Vec<u8>> {
    let mut keys: HashSet<&[u8]> = a.iter().map(|(k, _)| k.as_slice()).collect();
    keys.extend(b.iter().map(|(k, _)| k.as_slice()));
    let mut out: Vec<Vec<u8>> =
        keys.into_iter().filter(|k| a.get(k).ok().map(serialize) != b.get(k).ok().map(serialize)).map(|k| k.to_vec()).collect();
    out.sort();
    out
}

fn key_list(keys: &[Vec<u8>]) -> String {
    keys.iter().map(|k| String::from_utf8_lossy(k).into_owned()).collect::<Vec<_>>().join(", ")
}

fn is_sig_field(doc: &Document, d: &Dictionary) -> bool {
    field_type(doc, d).as_deref() == Some(b"Sig")
}

fn is_form_field(doc: &Document, d: &Dictionary) -> bool {
    field_type(doc, d).is_some()
}

fn field_type(doc: &Document, d: &Dictionary) -> Option<Vec<u8>> {
    let mut cur = Some(d);
    for _ in 0..32 {
        let c = cur?;
        if let Some(ft) = pdf::name(c.get(b"FT").ok()) {
            return Some(ft.to_vec());
        }
        cur = pdf::dict(doc, c.get(b"Parent").ok());
    }
    None
}
