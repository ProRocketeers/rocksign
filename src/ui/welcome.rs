//! The welcome on first start: pick certificates, name signed copies, optionally add a logo.
//! It edits a settings draft like the Settings window and is saved at the end. Shown once (the
//! `setup_done` setting); RockSign → Set Up RockSign… brings it back.

use gpui::{AnyElement, Context, Div, Focusable, FontWeight, SharedString, Window, div, img, prelude::*, px};
use rocksign_core::logo::Logo;

use super::widgets::*;
use super::*;
use crate::theme::Theme;

const STEPS: [(WelcomeStep, &str); 3] =
    [(WelcomeStep::Certificates, "Certificates"), (WelcomeStep::FileName, "File names"), (WelcomeStep::Ready, "Ready")];

impl RockSignView {
    pub(super) fn open_welcome(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.draft.is_some() {
            return;
        }
        let suffix = self.settings.file_suffix.clone();
        self.suffix_input.update(cx, |input, cx| input.set_text(&suffix, cx));
        self.settings_scroll.set_offset(gpui::point(px(0.0), px(0.0)));
        self.welcome_art = Logo::rocksign().ok().map(|l| logo_image(&l));
        self.draft = Some(Draft {
            settings: self.settings.clone(),
            tab: SettingsTab::General,
            welcome: Some(WelcomeStep::Certificates),
            logo: self.logo.clone(),
            logo_image: self.logo_image.clone(),
        });
        window.focus(&self.focus);
        cx.notify();
    }

    fn welcome_go(&mut self, step: WelcomeStep, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(d) = &mut self.draft {
            d.welcome = Some(step);
        }
        self.settings_scroll.set_offset(gpui::point(px(0.0), px(0.0)));
        // Ready to type on the file name step.
        if step == WelcomeStep::FileName {
            window.focus(&self.suffix_input.focus_handle(cx));
        } else {
            window.focus(&self.focus);
        }
        cx.notify();
    }

    pub(super) fn welcome_next(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        match self.draft.as_ref().and_then(|d| d.welcome) {
            Some(WelcomeStep::Certificates) => self.welcome_go(WelcomeStep::FileName, window, cx),
            Some(WelcomeStep::FileName) => self.welcome_go(WelcomeStep::Ready, window, cx),
            Some(WelcomeStep::Ready) => self.finish_welcome(false, window, cx),
            None => {}
        }
    }

    fn welcome_back(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        match self.draft.as_ref().and_then(|d| d.welcome) {
            Some(WelcomeStep::FileName) => self.welcome_go(WelcomeStep::Certificates, window, cx),
            Some(WelcomeStep::Ready) => self.welcome_go(WelcomeStep::FileName, window, cx),
            _ => {}
        }
    }

    /// Keep what was chosen and don't show the welcome again. With `logo`, continue in
    /// Settings → Stamp.
    fn finish_welcome(&mut self, logo: bool, window: &mut Window, cx: &mut Context<Self>) {
        let Some(mut d) = self.draft.take() else { return };
        d.settings.setup_done = true;
        self.apply_draft(d, cx);
        self.close_welcome_art();
        window.focus(&self.focus);
        if logo {
            self.open_settings(window, cx);
            if let Some(d) = &mut self.draft {
                d.tab = SettingsTab::Stamp;
            }
        } else if self.files.is_empty() {
            self.show_toast(Level::Ok, "You're all set. Open a PDF to sign (⌘O), or drop one on the window.".into(), cx);
        }
        cx.notify();
    }

    /// Close without changing anything, and don't show the welcome again.
    pub(super) fn skip_welcome(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(d) = self.draft.take() {
            self.release_logo_image(d.logo_image);
        }
        self.close_welcome_art();
        if !self.settings.setup_done {
            self.settings.setup_done = true;
            self.save_settings(cx);
        }
        window.focus(&self.focus);
        cx.notify();
    }

    fn close_welcome_art(&mut self) {
        if let Some(art) = self.welcome_art.take() {
            self.stale_images.push(art);
        }
    }

    // --- drawing ---------------------------------------------------------------

    pub(super) fn render_welcome(&mut self, step: WelcomeStep, theme: &Theme, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let index = STEPS.iter().position(|(s, _)| *s == step).unwrap_or(0);
        let bar = self.scrollbar("welcome-scroll", &self.settings_scroll.clone(), Axis::Y, theme, cx);
        let content = match step {
            WelcomeStep::Certificates => self.welcome_certificates(theme, cx),
            WelcomeStep::FileName => self.welcome_file_name(theme, window, cx),
            WelcomeStep::Ready => self.welcome_ready(theme),
        };

        // Header: the rocket, a greeting and where you are.
        let mut steps = div().flex().items_center().gap_2();
        for (i, (_, title)) in STEPS.iter().enumerate() {
            let (done, current) = (i < index, i == index);
            if i > 0 {
                steps = steps.child(div().w(px(18.0)).h(px(1.0)).bg(theme.border));
            }
            steps = steps.child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(6.0))
                    .child(
                        div()
                            .size(px(20.0))
                            .rounded(px(10.0))
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_size(px(11.0))
                            .font_weight(FontWeight::BOLD)
                            .when(current, |d| d.bg(theme.accent).text_color(theme.accent_text))
                            .when(done, |d| d.bg(theme.accent.opacity(0.15)).text_color(theme.accent))
                            .when(!done && !current, |d| d.border_1().border_color(theme.border).text_color(theme.muted))
                            .child(if done { "✓".to_string() } else { (i + 1).to_string() }),
                    )
                    .child(
                        div()
                            .text_size(px(12.0))
                            .when(current, |d| d.font_weight(FontWeight::SEMIBOLD))
                            .text_color(if current { theme.text } else { theme.muted })
                            .child(*title),
                    ),
            );
        }
        let header = div()
            .px_6()
            .pt_5()
            .pb_4()
            .flex()
            .flex_col()
            .gap_4()
            .border_b_1()
            .border_color(theme.border)
            .child(
                div().flex().items_center().gap_3().children(self.welcome_art.clone().map(|art| img(art).w(px(44.0)).h(px(40.0)))).child(
                    div()
                        .flex()
                        .flex_col()
                        .child(div().text_size(px(17.0)).font_weight(FontWeight::SEMIBOLD).child("Welcome to RockSign"))
                        .child(div().text_size(px(12.5)).text_color(theme.muted).child("Three quick steps, then you're ready to sign.")),
                ),
            )
            .child(steps);

        // Footer: skip on the left, back / next on the right.
        let last = step == WelcomeStep::Ready;
        let mut right = div().flex().items_center().gap_2();
        if index > 0 {
            right = right.child(button("welcome-back", "Back", theme).on_click(cx.listener(|this, _, window, cx| this.welcome_back(window, cx))));
        }
        if last {
            right = right
                .child(
                    button("welcome-logo", "Add a logo…", theme).on_click(cx.listener(|this, _, window, cx| this.finish_welcome(true, window, cx))),
                )
                .child(
                    primary_button("welcome-finish", "Start using RockSign", true, theme)
                        .on_click(cx.listener(|this, _, window, cx| this.finish_welcome(false, window, cx))),
                );
        } else {
            right = right.child(
                primary_button("welcome-next", "Next", true, theme).on_click(cx.listener(|this, _, window, cx| this.welcome_next(window, cx))),
            );
        }
        let footer = div()
            .px_6()
            .py_3()
            .flex()
            .items_center()
            .justify_between()
            .border_t_1()
            .border_color(theme.border)
            .child(
                div()
                    .id("welcome-skip")
                    .text_size(px(12.0))
                    .text_color(theme.muted)
                    .cursor_pointer()
                    .hover(|s| s.text_color(theme.text))
                    .when(!last, |d| d.child("Skip setup"))
                    .on_click(cx.listener(|this, _, window, cx| this.skip_welcome(window, cx))),
            )
            .child(right);

        let card = div()
            .id("welcome-card")
            .w(px(660.0))
            .h(px(580.0))
            .rounded(px(12.0))
            .bg(theme.surface)
            .border_1()
            .border_color(theme.border)
            .shadow_lg()
            .overflow_hidden()
            .flex()
            .flex_col()
            .on_mouse_down(gpui::MouseButton::Left, |_, _, cx| cx.stop_propagation())
            .child(header)
            .child(
                div()
                    .relative()
                    .flex_1()
                    .min_h_0()
                    .child(
                        div()
                            .id("welcome-content")
                            .size_full()
                            .overflow_y_scroll()
                            .track_scroll(&self.settings_scroll)
                            .on_scroll_wheel(cx.listener(|_, _, _, cx| cx.notify()))
                            .child(div().w(px(660.0)).px_6().py_5().child(content)),
                    )
                    .children(bar),
            )
            .child(footer);

        div()
            .id("welcome-backdrop")
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            .occlude()
            .bg(gpui::black().opacity(0.45))
            .flex()
            .items_center()
            .justify_center()
            .child(card)
            .into_any_element()
    }

    fn welcome_intro(title: &str, text: &str, theme: &Theme) -> Div {
        div()
            .flex()
            .flex_col()
            .gap_1()
            .child(div().text_size(px(15.0)).font_weight(FontWeight::SEMIBOLD).child(title.to_string()))
            .child(div().text_size(px(12.5)).text_color(theme.muted).child(text.to_string()))
    }

    fn welcome_certificates(&mut self, theme: &Theme, cx: &mut Context<Self>) -> AnyElement {
        let list = self.settings_certificates(theme, cx);
        div()
            .flex()
            .flex_col()
            .gap_5()
            .child(Self::welcome_intro(
                "Which certificates should RockSign offer?",
                "RockSign signs with the certificates in your Mac's Keychain. Untick the ones you don't sign documents with, and choose which one is selected first. You can change this later in Settings.",
                theme,
            ))
            .child(list)
            .into_any_element()
    }

    fn welcome_file_name(&mut self, theme: &Theme, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let suffix = self.suffix_section(theme, window, cx);
        div()
            .flex()
            .flex_col()
            .gap_5()
            .child(Self::welcome_intro(
                "How should signed copies be named?",
                "RockSign never changes the PDF you open. It saves a signed copy next to it, with this added to the name, so everyone can tell the versions apart.",
                theme,
            ))
            .child(suffix)
            .into_any_element()
    }

    fn welcome_ready(&mut self, theme: &Theme) -> AnyElement {
        let tip = |key: &str, text: &str| {
            div()
                .flex()
                .items_start()
                .gap_3()
                .child(
                    div()
                        .flex_none()
                        .min_w(px(34.0))
                        .px_1()
                        .py(px(1.0))
                        .rounded(px(4.0))
                        .border_1()
                        .border_color(theme.border)
                        .bg(theme.sidebar)
                        .flex()
                        .justify_center()
                        .text_size(px(11.5))
                        .text_color(theme.muted)
                        .child(key.to_string()),
                )
                .child(div().flex_1().text_size(px(12.5)).child(text.to_string()))
        };
        let name = SharedString::from(self.default_signer_name());
        div()
            .flex()
            .flex_col()
            .gap_5()
            .child(Self::welcome_intro("You're ready to sign", "How a document goes around:", theme))
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_3()
                    .child(tip("⌘O", "Open the PDFs you need to sign, or drop them on the window. The list on the left ticks off the ones you've signed."))
                    .child(tip("⌘S", "Click Sign this document, then click or drag where your stamp goes. Need it on several pages? Click each one."))
                    .child(tip("✉", "Send the signed copy to the next person. They see your signature as valid, add theirs and pass it on.")),
            )
            .child(
                div()
                    .p_3()
                    .rounded(px(8.0))
                    .bg(theme.sidebar)
                    .flex()
                    .flex_col()
                    .gap_1()
                    .child(div().text_size(px(12.5)).font_weight(FontWeight::MEDIUM).child("A logo on your stamp?"))
                    .child(div().text_size(px(12.0)).text_color(theme.muted).child(format!(
                        "Your stamp shows “{name}” and the date. You can add the RockSign rocket or your company's logo, faded behind the text like a watermark. Choose Add a logo…, or do it any time in Settings → Stamp."
                    ))),
            )
            .into_any_element()
    }
}
