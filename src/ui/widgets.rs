//! Small building blocks: buttons, badges, the signature verdict, the stamp preview.

use std::sync::Arc;

use chrono::{DateTime, Local, Utc};
use gpui::{Div, FontWeight, Hsla, RenderImage, SharedString, Stateful, div, img, prelude::*, px};
use rocksign_core::stamp::{self, FontData, Fonts, LogoMode, StampText};
use rocksign_core::{ChangeLevel, Integrity, SignatureReport};

use crate::jobs;
use crate::theme::Theme;
use crate::trust::TrustOutcome;

#[derive(Clone, Copy, PartialEq)]
pub enum Level {
    Ok,
    Warn,
    Bad,
}

impl Level {
    pub fn color(self, t: &Theme) -> Hsla {
        match self {
            Level::Ok => t.ok,
            Level::Warn => t.warn,
            Level::Bad => t.bad,
        }
    }

    pub fn icon(self) -> &'static str {
        match self {
            Level::Ok => "✓",
            Level::Warn => "!",
            Level::Bad => "✕",
        }
    }
}

pub struct Verdict {
    pub level: Level,
    pub title: String,
}

pub fn verdict(sig: &SignatureReport, trust: Option<&TrustOutcome>) -> Verdict {
    let v = |level, title: &str| Verdict { level, title: title.to_string() };
    match &sig.integrity {
        Integrity::Malformed(_) => return v(Level::Bad, "This signature can't be checked"),
        Integrity::Altered => return v(Level::Bad, "The document was changed after it was signed"),
        Integrity::Intact => {}
    }
    if !sig.signature_valid {
        return v(Level::Bad, "The signature is not valid");
    }
    if sig.later.level == ChangeLevel::Content {
        return v(Level::Bad, "Content was changed after this signature");
    }
    if sig.later.level >= ChangeLevel::FormFill {
        return v(Level::Warn, "Valid, but the document was edited after signing");
    }
    if !trust.is_some_and(|t| t.trusted) {
        return v(Level::Warn, "Unchanged, but the signer's certificate isn't trusted on this Mac");
    }
    if sig.covers_whole_file {
        v(Level::Ok, "Valid — the document is unchanged since this signature")
    } else {
        v(Level::Ok, "Valid — only signatures were added after it")
    }
}

pub fn local(t: DateTime<Utc>) -> String {
    t.with_timezone(&Local).format("%-d %b %Y, %H:%M").to_string()
}

pub fn button(id: impl Into<SharedString>, label: impl Into<SharedString>, theme: &Theme) -> Stateful<Div> {
    let hover = theme.hover;
    div()
        .id(id.into())
        .px_2p5()
        .py(px(4.0))
        .rounded(px(6.0))
        .border_1()
        .border_color(theme.border)
        .bg(theme.surface)
        .text_size(px(12.5))
        .cursor_pointer()
        .hover(move |s| s.bg(hover))
        .child(label.into())
}

pub fn primary_button(id: impl Into<SharedString>, label: impl Into<SharedString>, enabled: bool, theme: &Theme) -> Stateful<Div> {
    let accent = theme.accent;
    div()
        .id(id.into())
        .px_3()
        .py(px(5.0))
        .rounded(px(6.0))
        .bg(if enabled { accent } else { theme.faint.opacity(0.4) })
        .text_color(theme.accent_text)
        .text_size(px(12.5))
        .font_weight(FontWeight::MEDIUM)
        .when(enabled, |d| d.cursor_pointer().hover(move |s| s.bg(accent.opacity(0.85))))
        .child(label.into())
}

pub fn section_label(text: &str, theme: &Theme) -> Div {
    div().text_size(px(10.5)).font_weight(FontWeight::SEMIBOLD).text_color(theme.faint).child(text.to_uppercase())
}

pub fn status_badge(level: Level, theme: &Theme, size: f32) -> Div {
    div()
        .flex_none()
        .size(px(size))
        .rounded(px(size / 2.0))
        .bg(level.color(theme))
        .flex()
        .items_center()
        .justify_center()
        .text_color(gpui::white())
        .text_size(px(size * 0.62))
        .font_weight(FontWeight::BOLD)
        .child(level.icon())
}

/// A square check box, filled when checked.
pub fn check_box(checked: bool, color: Hsla, theme: &Theme) -> Div {
    div()
        .flex_none()
        .size(px(15.0))
        .rounded(px(4.0))
        .border_1()
        .border_color(if checked { color } else { theme.faint })
        .bg(if checked { color } else { theme.surface })
        .flex()
        .items_center()
        .justify_center()
        .text_size(px(10.5))
        .font_weight(FontWeight::BOLD)
        .text_color(gpui::white())
        .when(checked, |d| d.child("✓"))
}

pub fn checkbox(id: &'static str, checked: bool, label: &str, theme: &Theme) -> Stateful<Div> {
    div()
        .id(id)
        .flex()
        .items_center()
        .gap_2()
        .cursor_pointer()
        .child(check_box(checked, theme.accent, theme))
        .child(div().text_size(px(12.5)).child(label.to_string()))
}

pub fn radio(id: impl Into<SharedString>, selected: bool, label: impl Into<SharedString>, theme: &Theme) -> Stateful<Div> {
    div()
        .id(id.into())
        .flex()
        .items_center()
        .gap_2()
        .cursor_pointer()
        .child(
            div()
                .size(px(13.0))
                .rounded(px(7.0))
                .border_1()
                .border_color(if selected { theme.accent } else { theme.faint })
                .when(selected, |d| d.border(px(4.0))),
        )
        .child(div().text_size(px(12.5)).child(label.into()))
}

/// The stamp as it will look in the PDF: same fonts, logo and adaptive layout as the signer.
pub struct StampPreview<'a> {
    /// Box position and size on screen, in pixels.
    pub screen: [f32; 4],
    /// Box size in points.
    pub size_pt: [f32; 2],
    pub name: String,
    pub zoom: f32,
    /// The logo bitmap, its aspect ratio and how it is shown.
    pub logo: Option<(Arc<RenderImage>, f32, LogoMode)>,
    pub theme: &'a Theme,
    /// Draw the blue placement outline (on the page) or just the stamp (in Settings).
    pub framed: bool,
}

impl StampPreview<'_> {
    pub fn render(self) -> Div {
        let [x, y, w, h] = self.screen;
        let zoom = self.zoom;
        let framed = self.framed;
        let mut boxed =
            div().absolute().left(px(x)).top(px(y)).w(px(w)).h(px(h)).when(framed, |d| d.bg(self.theme.accent.opacity(0.07))).overflow_hidden();
        let fonts = jobs::stamp_fonts()
            .and_then(|(regular, bold)| Fonts::parse(FontData { data: regular, index: 0 }, bold.map(|b| FontData { data: b, index: 0 })).ok());
        if let Some(fonts) = fonts {
            let text = StampText { name: self.name, date: jobs::stamp_date(&Local::now().fixed_offset()), reason: None };
            let [bw, bh] = self.size_pt;
            let layout = stamp::layout(bw, bh, &text, &fonts, self.logo.as_ref().map(|l| (l.1, l.2)));
            let (asc, desc) = fonts.metrics();
            // The logo first: as a watermark it sits behind everything.
            if let (Some([lx, ly, lw, lh]), Some((image, ..))) = (layout.logo, &self.logo) {
                boxed = boxed.child(
                    img(image.clone())
                        .absolute()
                        .left(px(lx * zoom))
                        .top(px((bh - ly - lh) * zoom))
                        .w(px(lw * zoom))
                        .h(px(lh * zoom))
                        .opacity(layout.logo_opacity.unwrap_or(1.0)),
                );
            }
            for line in layout.lines {
                let line_h = (asc + desc) * line.size * zoom;
                let mut row = div()
                    .absolute()
                    .left(px(line.x * zoom))
                    .top(px((bh - line.baseline - asc * line.size) * zoom))
                    .h(px(line_h))
                    .flex()
                    .whitespace_nowrap()
                    .font_family("Arial")
                    .text_size(px(line.size * zoom))
                    .line_height(px(line_h));
                for seg in line.segments {
                    row = row.child(
                        div().text_color(gpui::hsla(0.0, 0.0, seg.gray, 1.0)).when(seg.bold, |d| d.font_weight(FontWeight::BOLD)).child(seg.text),
                    );
                }
                boxed = boxed.child(row);
            }
        }
        // The outline sits on top so it doesn't shift the content.
        boxed.when(framed, |d| d.child(div().absolute().top_0().left_0().size_full().rounded(px(3.0)).border_2().border_color(self.theme.accent)))
    }
}
