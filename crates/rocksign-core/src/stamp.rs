//! The visible signature stamp. Text is drawn as glyph outlines taken from a TrueType/OpenType
//! font, so the PDF needs no embedded font and any language's letters work (č, ř, ů…).
//!
//! The layout adapts to the box: a roomy box gets "Digitally signed by / name / date", a low
//! box gets two lines or a single line, so the name stays readable at any size.

use anyhow::{Context, Result};
use ttf_parser::{Face, GlyphId, OutlineBuilder};

use crate::logo::Logo;
use crate::writer::format_real;

/// Font data (file bytes and face index inside a collection).
#[derive(Clone, Copy)]
pub struct FontData<'a> {
    pub data: &'a [u8],
    pub index: u32,
}

pub struct Fonts<'a> {
    pub regular: Face<'a>,
    pub bold: Option<Face<'a>>,
}

impl<'a> Fonts<'a> {
    pub fn parse(regular: FontData<'a>, bold: Option<FontData<'a>>) -> Result<Self> {
        Ok(Fonts {
            regular: Face::parse(regular.data, regular.index).context("stamp font")?,
            bold: bold.map(|b| Face::parse(b.data, b.index)).transpose().context("stamp bold font")?,
        })
    }

    fn face(&self, bold: bool) -> &Face<'a> {
        if bold { self.bold.as_ref().unwrap_or(&self.regular) } else { &self.regular }
    }

    /// Ascent and descent as a fraction of the font size.
    pub fn metrics(&self) -> (f32, f32) {
        let f = &self.regular;
        let upem = f.units_per_em() as f32;
        (f.ascender() as f32 / upem, -(f.descender() as f32) / upem)
    }

    /// Width of `text` at font size 1.
    pub fn width(&self, text: &str, bold: bool) -> f32 {
        let face = self.face(bold);
        let upem = face.units_per_em() as f32;
        text.chars().map(|c| face.glyph_hor_advance(glyph(face, c)).unwrap_or(0) as f32 / upem).sum()
    }
}

fn glyph(face: &Face, c: char) -> GlyphId {
    face.glyph_index(c).or_else(|| face.glyph_index('?')).unwrap_or(GlyphId(0))
}

#[derive(Clone, Debug, PartialEq)]
pub struct Segment {
    pub text: String,
    pub bold: bool,
    /// 0 = black, 1 = white.
    pub gray: f32,
}

#[derive(Clone, Debug, PartialEq)]
pub struct StampLine {
    pub segments: Vec<Segment>,
    /// Relative size; the layout scales all lines together to fit the box.
    pub size: f32,
}

impl StampLine {
    pub fn plain(text: impl Into<String>, size: f32, bold: bool, gray: f32) -> Self {
        StampLine { segments: vec![Segment { text: text.into(), bold, gray }], size }
    }

    fn width(&self, fonts: &Fonts) -> f32 {
        self.segments.iter().map(|s| fonts.width(&s.text, s.bold)).sum()
    }
}

/// What the stamp says.
#[derive(Clone, Debug)]
pub struct StampText {
    pub name: String,
    pub date: String,
    pub reason: Option<String>,
}

pub struct Stamp<'a> {
    pub text: StampText,
    pub regular: FontData<'a>,
    pub bold: Option<FontData<'a>>,
    pub logo: Option<&'a Logo>,
    pub logo_mode: LogoMode,
}

/// How the logo is shown.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum LogoMode {
    /// Above (or beside) the text, at full strength; left out when the box is too small.
    Header,
    /// Faded behind the text, like Acrobat's signature appearances.
    Watermark(Watermark),
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Watermark {
    /// 0–1.
    pub opacity: f32,
    /// Horizontal position: 0 = left, 0.5 = center, 1 = right.
    pub x: f32,
    /// Vertical position: 0 = top, 0.5 = middle, 1 = bottom.
    pub y: f32,
    /// Size relative to the largest logo that fits the box, 0.2–1.
    pub scale: f32,
}

impl Watermark {
    /// Centered, as large as fits.
    pub fn centered(opacity: f32) -> Self {
        Watermark { opacity, x: 0.5, y: 0.5, scale: 1.0 }
    }
}

/// What [`draw`] produced.
pub struct Drawn {
    pub content: Vec<u8>,
    /// The content draws the logo as `/Logo`.
    pub uses_logo: bool,
    /// The content uses the graphics state `/GSLogo` with this opacity.
    pub logo_opacity: Option<f32>,
}

/// A line ready to draw, in points from the box's bottom-left corner.
#[derive(Clone, Debug)]
pub struct PlacedLine {
    pub segments: Vec<Segment>,
    /// Font size in points.
    pub size: f32,
    pub x: f32,
    pub baseline: f32,
}

#[derive(Clone, Debug)]
pub struct Layout {
    pub lines: Vec<PlacedLine>,
    /// Where the logo goes [x, y, w, h], when there is room for it.
    pub logo: Option<[f32; 4]>,
    /// Logo opacity below 1.0 (watermark).
    pub logo_opacity: Option<f32>,
}

const LINE_GAP: f32 = 1.22;
const MUTED: f32 = 0.35;
/// The name must be at least this big (points) before a layout with less text is chosen.
const MIN_NAME: f32 = 9.0;
const MIN_SMALL: f32 = 6.5;
/// A logo smaller than this (points high) is left out.
const MIN_LOGO: f32 = 10.0;
/// Height of a logo row above the text, relative to the base font size.
const LOGO_ROW: f32 = 1.7;
const LOGO_ROW_GAP: f32 = 0.45;

#[derive(Clone, Copy, PartialEq)]
enum LogoPlace {
    None,
    /// A wide logo in its own row above the text.
    Top,
    /// A squarish logo left of the text.
    Left,
}

struct Variant {
    logo: LogoPlace,
    lines: Vec<StampLine>,
}

/// Text layouts, most informative first.
fn text_variants(t: &StampText) -> Vec<Vec<StampLine>> {
    let small = |s: String| StampLine::plain(s, 0.8, false, MUTED);
    let name = StampLine::plain(t.name.clone(), 1.3, true, 0.0);
    let full = vec![small("Digitally signed by".into()), name.clone(), small(t.date.clone())];
    let mut out = Vec::new();
    if let Some(r) = t.reason.as_deref().filter(|r| !r.trim().is_empty()) {
        let mut with_reason = full.clone();
        with_reason.push(small(format!("Reason: {r}")));
        out.push(with_reason);
    }
    out.push(full);
    out.push(vec![name, small(format!("Digitally signed {}", t.date))]);
    out.push(vec![StampLine {
        segments: vec![
            Segment { text: t.name.clone(), bold: true, gray: 0.0 },
            Segment { text: format!("  ·  {}", t.date), bold: false, gray: MUTED },
        ],
        size: 1.0,
    }]);
    out.push(vec![StampLine::plain(t.name.clone(), 1.0, true, 0.0)]);
    out
}

fn variants(t: &StampText, logo_aspect: Option<f32>) -> Vec<Variant> {
    let texts = text_variants(t);
    let mut out = Vec::new();
    if let Some(aspect) = logo_aspect {
        let place = if aspect >= 2.0 { LogoPlace::Top } else { LogoPlace::Left };
        let rich = texts.len().saturating_sub(2);
        out.extend(texts.iter().take(rich).cloned().map(|lines| Variant { logo: place, lines }));
    }
    out.extend(texts.into_iter().map(|lines| Variant { logo: LogoPlace::None, lines }));
    out
}

#[derive(Clone, Copy)]
struct Frame {
    pad: f32,
    text_x: f32,
    avail_w: f32,
    avail_h: f32,
}

fn frame(w: f32, h: f32, left: f32) -> Frame {
    let pad = (w.min(h) * 0.08).clamp(1.5, 8.0);
    let text_x = pad + left + pad.max(3.0);
    Frame { pad, text_x, avail_w: (w - text_x - pad).max(1.0), avail_h: (h - 2.0 * pad).max(1.0) }
}

/// Font size for relative size 1.0 so every line (and a top logo row) fits.
fn fit(lines: &[StampLine], fonts: &Fonts, fr: &Frame, cap: f32, logo_row: Option<f32>) -> f32 {
    let mut total: f32 = lines.iter().map(|l| l.size * LINE_GAP).sum();
    let mut base = cap;
    if let Some(aspect) = logo_row {
        total += LOGO_ROW + LOGO_ROW_GAP;
        base = base.min(fr.avail_w / (LOGO_ROW * aspect));
    }
    if total > 0.0 {
        base = base.min(fr.avail_h / total);
    }
    for l in lines {
        let width = l.width(fonts);
        if width > 0.0 {
            base = base.min(fr.avail_w / (width * l.size));
        }
    }
    base
}

/// Lines from `top` downwards, vertically centered as a block of height `block`.
fn place(lines: &[StampLine], base: f32, fonts: &Fonts, x: f32, mut top: f32) -> Vec<PlacedLine> {
    let (asc, desc) = fonts.metrics();
    lines
        .iter()
        .map(|l| {
            let size = l.size * base;
            let line_h = size * LINE_GAP;
            let baseline = top - (line_h - (asc + desc) * size) / 2.0 - asc * size;
            top -= line_h;
            PlacedLine { segments: l.segments.clone(), size, x, baseline }
        })
        .collect()
}

fn block_height(lines: &[StampLine], base: f32) -> f32 {
    lines.iter().map(|l| l.size * base * LINE_GAP).sum()
}

/// One candidate layout and how readable it is: (layout, name size, smallest size, logo height).
fn try_variant(v: &Variant, w: f32, h: f32, fonts: &Fonts, aspect: f32) -> (Layout, f32, f32, f32) {
    let (lines, logo, logo_h, base) = match v.logo {
        LogoPlace::None => {
            let fr = frame(w, h, 0.0);
            let base = fit(&v.lines, fonts, &fr, 11.0, None);
            let block = block_height(&v.lines, base);
            (place(&v.lines, base, fonts, fr.text_x, (h + block) / 2.0), None, 0.0, base)
        }
        LogoPlace::Top => {
            let fr = frame(w, h, 0.0);
            let base = fit(&v.lines, fonts, &fr, 11.0, Some(aspect));
            let logo_h = LOGO_ROW * base;
            let block = logo_h + LOGO_ROW_GAP * base + block_height(&v.lines, base);
            let top = (h + block) / 2.0;
            let logo = [fr.text_x, top - logo_h, logo_h * aspect, logo_h];
            (place(&v.lines, base, fonts, fr.text_x, top - logo_h - LOGO_ROW_GAP * base), Some(logo), logo_h, base)
        }
        LogoPlace::Left => {
            let inner = frame(w, h, 0.0);
            let logo_h = inner.avail_h.min(w * 0.3 / aspect);
            let logo_w = logo_h * aspect;
            let fr = frame(w, h, logo_w);
            let base = fit(&v.lines, fonts, &fr, 11.0, None);
            let block = block_height(&v.lines, base);
            let logo = [inner.pad, (h - logo_h) / 2.0, logo_w, logo_h];
            (place(&v.lines, base, fonts, fr.text_x, (h + block) / 2.0), Some(logo), logo_h, base)
        }
    };
    let name_size = base * v.lines.iter().filter(|l| l.segments.iter().any(|s| s.bold)).map(|l| l.size).fold(0.0, f32::max);
    let min_size = base * v.lines.iter().map(|l| l.size).fold(f32::MAX, f32::min);
    (Layout { lines, logo, logo_opacity: None }, name_size, min_size, logo_h)
}

/// Choose the richest layout that keeps the name (and logo) readable in a `w` × `h` box.
/// `logo` is the logo's aspect ratio (width / height) and how to show it.
pub fn layout(w: f32, h: f32, text: &StampText, fonts: &Fonts, logo: Option<(f32, LogoMode)>) -> Layout {
    match logo {
        Some((aspect, LogoMode::Watermark(wm))) => {
            let mut l = text_layout(w, h, text, fonts, None);
            l.logo = watermark_rect(w, h, aspect, &wm);
            l.logo_opacity = (wm.opacity < 0.999).then_some(wm.opacity.clamp(0.02, 1.0));
            l
        }
        Some((aspect, LogoMode::Header)) => text_layout(w, h, text, fonts, Some(aspect)),
        None => text_layout(w, h, text, fonts, None),
    }
}

/// The logo inside the box (with a small margin), scaled and positioned as chosen.
fn watermark_rect(w: f32, h: f32, aspect: f32, wm: &Watermark) -> Option<[f32; 4]> {
    let (mx, my) = (w * 0.04, h * 0.07);
    let (aw, ah) = (w - 2.0 * mx, h - 2.0 * my);
    let lw = aw.min(ah * aspect) * wm.scale.clamp(0.2, 1.0);
    let lh = lw / aspect;
    let x = mx + (aw - lw) * wm.x.clamp(0.0, 1.0);
    // y counts from the bottom in PDF space; 0 means top in the settings.
    let y = my + (ah - lh) * (1.0 - wm.y.clamp(0.0, 1.0));
    (lh >= 5.0).then_some([x, y, lw, lh])
}

fn text_layout(w: f32, h: f32, text: &StampText, fonts: &Fonts, logo_aspect: Option<f32>) -> Layout {
    let mut best: Option<(f32, Layout)> = None;
    for v in variants(text, logo_aspect) {
        let (layout, name_size, min_size, logo_h) = try_variant(&v, w, h, fonts, logo_aspect.unwrap_or(1.0));
        let logo_ok = v.logo == LogoPlace::None || logo_h >= MIN_LOGO;
        if name_size >= MIN_NAME && min_size >= MIN_SMALL && logo_ok {
            return layout;
        }
        if v.logo == LogoPlace::None && best.as_ref().is_none_or(|(s, _)| name_size > *s) {
            best = Some((name_size, layout));
        }
    }
    best.map(|b| b.1).unwrap_or(Layout { lines: Vec::new(), logo: None, logo_opacity: None })
}

/// Content stream for the stamp in a `w` × `h` box (origin bottom-left). The logo, when shown,
/// is drawn with the XObject name `/Logo` (and the graphics state `/GSLogo` for its opacity).
pub fn draw(w: f32, h: f32, stamp: &Stamp) -> Result<Drawn> {
    let fonts = Fonts::parse(stamp.regular, stamp.bold)?;
    let layout = layout(w, h, &stamp.text, &fonts, stamp.logo.map(|l| (l.aspect(), stamp.logo_mode)));
    Ok(Drawn { uses_logo: layout.logo.is_some(), logo_opacity: layout.logo.and(layout.logo_opacity), content: paint(&layout, &fonts) })
}

/// Content stream for fixed lines, scaled to fit.
pub fn draw_lines(w: f32, h: f32, lines: &[StampLine], fonts: &Fonts) -> Vec<u8> {
    let fr = frame(w, h, 0.0);
    let base = fit(lines, fonts, &fr, 11.0, None);
    let block = block_height(lines, base);
    let lines = place(lines, base, fonts, fr.text_x, (h + block) / 2.0);
    paint(&Layout { lines, logo: None, logo_opacity: None }, fonts)
}

fn paint(layout: &Layout, fonts: &Fonts) -> Vec<u8> {
    let mut out = String::new();
    // The logo first, so a watermark sits behind everything else.
    if let Some([x, y, w, h]) = layout.logo {
        let gs = if layout.logo_opacity.is_some() { "/GSLogo gs " } else { "" };
        out.push_str(&format!("q {gs}{} 0 0 {} {} {} cm /Logo Do Q\n", f(w), f(h), f(x), f(y)));
    }
    for line in &layout.lines {
        let mut pen = line.x;
        for seg in &line.segments {
            let face = fonts.face(seg.bold);
            let scale = line.size / face.units_per_em() as f32;
            out.push_str(&format!("q {} g\n", format_real(seg.gray)));
            for ch in seg.text.chars() {
                let gid = glyph(face, ch);
                let mut sink = PathSink { out: &mut out, x: pen, y: line.baseline, scale, last: (0.0, 0.0) };
                if face.outline_glyph(gid, &mut sink).is_some() {
                    out.push_str("f\n");
                }
                pen += face.glyph_hor_advance(gid).unwrap_or(0) as f32 * scale;
            }
            out.push_str("Q\n");
        }
    }
    out.into_bytes()
}

fn f(v: f32) -> String {
    let s = format!("{v:.2}");
    let s = s.trim_end_matches('0').trim_end_matches('.');
    if s.is_empty() || s == "-0" { "0".into() } else { s.into() }
}

struct PathSink<'a> {
    out: &'a mut String,
    x: f32,
    y: f32,
    scale: f32,
    /// Current point in font units (for converting quadratic curves).
    last: (f32, f32),
}

impl PathSink<'_> {
    fn pt(&self, x: f32, y: f32) -> String {
        format!("{} {}", f(self.x + x * self.scale), f(self.y + y * self.scale))
    }
}

impl OutlineBuilder for PathSink<'_> {
    fn move_to(&mut self, x: f32, y: f32) {
        let p = self.pt(x, y);
        self.out.push_str(&format!("{p} m\n"));
        self.last = (x, y);
    }

    fn line_to(&mut self, x: f32, y: f32) {
        let p = self.pt(x, y);
        self.out.push_str(&format!("{p} l\n"));
        self.last = (x, y);
    }

    fn quad_to(&mut self, x1: f32, y1: f32, x: f32, y: f32) {
        let (x0, y0) = self.last;
        let c1 = (x0 + 2.0 / 3.0 * (x1 - x0), y0 + 2.0 / 3.0 * (y1 - y0));
        let c2 = (x + 2.0 / 3.0 * (x1 - x), y + 2.0 / 3.0 * (y1 - y));
        let s = format!("{} {} {} c\n", self.pt(c1.0, c1.1), self.pt(c2.0, c2.1), self.pt(x, y));
        self.out.push_str(&s);
        self.last = (x, y);
    }

    fn curve_to(&mut self, x1: f32, y1: f32, x2: f32, y2: f32, x: f32, y: f32) {
        let s = format!("{} {} {} c\n", self.pt(x1, y1), self.pt(x2, y2), self.pt(x, y));
        self.out.push_str(&s);
        self.last = (x, y);
    }

    fn close(&mut self) {
        self.out.push_str("h\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_adapts_to_box_height() {
        let Ok(data) = std::fs::read("/System/Library/Fonts/Supplemental/Arial.ttf") else { return };
        let fonts = Fonts::parse(FontData { data: &data, index: 0 }, None).unwrap();
        let text = StampText { name: "Tomáš Procházka".into(), date: "24 Nov 2026, 12:30 +01:00".into(), reason: None };
        let lines = |w, h| layout(w, h, &text, &fonts, None).lines.len();
        let header = |aspect| Some((aspect, LogoMode::Header));
        assert_eq!(lines(200.0, 70.0), 3, "roomy box: full stamp");
        assert_eq!(lines(220.0, 32.0), 2, "low box: two lines");
        assert_eq!(lines(260.0, 16.0), 1, "very low box: one line");
        // The name stays readable when the box gets lower.
        let name_size = |h: f32| layout(240.0, h, &text, &fonts, None).lines.iter().find(|l| l.segments[0].bold).unwrap().size;
        assert!(name_size(18.0) >= 8.0, "{}", name_size(18.0));

        // A wide logo sits above the text when there's room and is dropped in low boxes.
        let with_logo = |w, h| layout(w, h, &text, &fonts, header(5.0));
        assert!(with_logo(200.0, 90.0).logo.is_some());
        assert!(with_logo(220.0, 32.0).logo.is_none());
        assert_eq!(with_logo(220.0, 32.0).lines.len(), 2);
        // A square logo goes to the left.
        let l = layout(220.0, 70.0, &text, &fonts, header(1.0));
        let logo = l.logo.unwrap();
        assert!(l.lines.iter().all(|line| line.x > logo[0] + logo[2]));

        // A watermark sits behind the full text layout, even in low boxes.
        let wm = |w, h| layout(w, h, &text, &fonts, Some((5.0, LogoMode::Watermark(Watermark::centered(0.25)))));
        assert_eq!(wm(200.0, 90.0).lines.len(), 3);
        assert!(wm(200.0, 90.0).logo.is_some() && wm(200.0, 90.0).logo_opacity == Some(0.25));
        assert!(wm(220.0, 32.0).logo.is_some());
        // Smaller and at the bottom: below the box's middle, left of center when asked.
        let low = Watermark { opacity: 0.3, x: 0.0, y: 1.0, scale: 0.5 };
        let r = layout(200.0, 90.0, &text, &fonts, Some((5.0, LogoMode::Watermark(low)))).logo.unwrap();
        assert!(r[1] + r[3] < 45.0 && r[0] < 20.0, "{r:?}");
    }
}
