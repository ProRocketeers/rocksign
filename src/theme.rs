use gpui::{Hsla, WindowAppearance, rgb};

/// Colors, following the system light/dark setting (same palette family as Rockal).
#[derive(Clone, Copy)]
pub struct Theme {
    pub bg: Hsla,
    pub sidebar: Hsla,
    pub surface: Hsla,
    pub border: Hsla,
    pub text: Hsla,
    pub muted: Hsla,
    pub faint: Hsla,
    pub accent: Hsla,
    pub accent_text: Hsla,
    pub hover: Hsla,
    /// Behind the pages.
    pub canvas: Hsla,
    pub ok: Hsla,
    pub warn: Hsla,
    pub bad: Hsla,
}

fn c(hex: u32) -> Hsla {
    rgb(hex).into()
}

impl Theme {
    pub fn light() -> Self {
        Theme {
            bg: c(0xffffff),
            sidebar: c(0xf7f6f3),
            surface: c(0xffffff),
            border: c(0xe5e2dc),
            text: c(0x1f1e1c),
            muted: c(0x6d6a64),
            faint: c(0xa6a29a),
            accent: c(0x3d63dd),
            accent_text: c(0xffffff),
            hover: c(0x1f1e1c).opacity(0.05),
            canvas: c(0xe9e7e2),
            ok: c(0x1e8a4c),
            warn: c(0xb26b00),
            bad: c(0xd13438),
        }
    }

    pub fn dark() -> Self {
        Theme {
            bg: c(0x151517),
            sidebar: c(0x1b1b1e),
            surface: c(0x202024),
            border: c(0x2a2a2f),
            text: c(0xebebef),
            muted: c(0x9b9ba4),
            faint: c(0x5f5f68),
            accent: c(0x7c9bff),
            accent_text: c(0x0e0e10),
            hover: c(0xffffff).opacity(0.05),
            canvas: c(0x0e0e10),
            ok: c(0x3fbf74),
            warn: c(0xe0a33a),
            bad: c(0xff6369),
        }
    }

    pub fn for_appearance(appearance: WindowAppearance) -> Self {
        match appearance {
            WindowAppearance::Dark | WindowAppearance::VibrantDark => Self::dark(),
            _ => Self::light(),
        }
    }
}
