//! The Settings window: three tabs (General, Stamp, Certificates). Edits go to a draft and are
//! applied and stored only on Save.

use std::path::Path;
use std::sync::Arc;

use chrono::{Local, Utc};
use gpui::{AnyElement, Context, Focusable, FontWeight, MouseButton, PathPromptOptions, RenderImage, SharedString, Window, div, prelude::*, px};

use super::widgets::*;
use super::*;
use crate::settings::{self, Settings};
use crate::theme::Theme;

impl RockSignView {
    pub(super) fn open_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if self.draft.is_some() {
            return;
        }
        let suffix = self.settings.file_suffix.clone();
        self.suffix_input.update(cx, |input, cx| input.set_text(&suffix, cx));
        self.settings_scroll.set_offset(gpui::point(px(0.0), px(0.0)));
        self.draft = Some(Draft {
            settings: self.settings.clone(),
            tab: SettingsTab::General,
            welcome: None,
            logo: self.logo.clone(),
            logo_image: self.logo_image.clone(),
        });
        window.focus(&self.focus);
        cx.notify();
    }

    fn settings_dirty(&self) -> bool {
        self.draft.as_ref().is_some_and(|d| d.settings != self.settings)
    }

    /// Close without applying anything.
    pub(super) fn discard_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        if let Some(d) = self.draft.take() {
            self.release_logo_image(d.logo_image);
        }
        window.focus(&self.focus);
        cx.notify();
    }

    /// Apply and store the draft, then close.
    pub(super) fn save_settings_draft(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(d) = self.draft.take() else { return };
        if self.apply_draft(d, cx) {
            self.show_toast(Level::Ok, "Settings saved.".into(), cx);
        }
        window.focus(&self.focus);
        cx.notify();
    }

    /// Make a draft the current settings and store them. False when nothing changed.
    pub(super) fn apply_draft(&mut self, d: Draft, cx: &mut Context<Self>) -> bool {
        if d.settings == self.settings {
            self.release_logo_image(d.logo_image);
            return false;
        }
        if let Some(old) = self.logo_image.take()
            && !d.logo_image.as_ref().is_some_and(|new| Arc::ptr_eq(new, &old))
        {
            self.stale_images.push(old);
        }
        self.logo = d.logo;
        self.logo_image = d.logo_image;
        self.settings = d.settings;
        self.reselect_identity();
        self.save_settings(cx);
        true
    }

    /// Free a draft's logo bitmap unless the main window uses it too.
    pub(super) fn release_logo_image(&mut self, image: Option<Arc<RenderImage>>) {
        if let Some(image) = image
            && !self.logo_image.as_ref().is_some_and(|current| Arc::ptr_eq(current, &image))
        {
            self.stale_images.push(image);
        }
    }

    fn edit_draft(&mut self, cx: &mut Context<Self>, f: impl FnOnce(&mut Settings)) {
        if let Some(d) = &mut self.draft {
            f(&mut d.settings);
        }
        cx.notify();
    }

    fn draft_set_logo(&mut self, choice: String, cx: &mut Context<Self>) {
        let logo = make_logo(&choice);
        let image = logo.as_deref().map(logo_image);
        let old = self.draft.as_mut().and_then(|d| {
            d.settings.logo = choice;
            d.logo = logo;
            std::mem::replace(&mut d.logo_image, image)
        });
        self.release_logo_image(old);
        cx.notify();
    }

    fn choose_logo(&mut self, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions { files: true, directories: false, multiple: false, prompt: Some("Use as Logo".into()) });
        cx.spawn(async move |this, cx| {
            let Ok(Ok(Some(paths))) = rx.await else { return };
            let Some(path) = paths.into_iter().next() else { return };
            let result = (|| -> anyhow::Result<String> {
                let bytes = std::fs::read(&path)?;
                rocksign_core::logo::Logo::from_bytes(&bytes)?;
                // Keep our own copy, so moving the original doesn't break the stamp. A new name
                // each time, so Cancel leaves the saved logo untouched.
                let ext = path.extension().map(|e| e.to_string_lossy().to_lowercase()).unwrap_or_else(|| "png".into());
                let dir = dirs::config_dir().ok_or_else(|| anyhow::anyhow!("no settings folder"))?.join("RockSign");
                std::fs::create_dir_all(&dir)?;
                let dest = dir.join(format!("logo-{}.{ext}", Utc::now().timestamp()));
                std::fs::write(&dest, bytes)?;
                Ok(dest.to_string_lossy().into_owned())
            })();
            this.update(cx, |this, cx| match result {
                Ok(dest) => this.draft_set_logo(dest, cx),
                Err(e) => this.show_toast(Level::Bad, format!("That image can't be used as a logo: {e:#}"), cx),
            })
            .ok();
        })
        .detach();
    }

    // --- drawing ---------------------------------------------------------------

    pub(super) fn render_settings(&mut self, theme: &Theme, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        if let Some(step) = self.draft.as_ref().and_then(|d| d.welcome) {
            return self.render_welcome(step, theme, window, cx);
        }
        let Some(tab) = self.draft.as_ref().map(|d| d.tab) else { return div().into_any_element() };
        let dirty = self.settings_dirty();
        let settings_bar = self.scrollbar("settings-scroll", &self.settings_scroll.clone(), Axis::Y, theme, cx);
        let content = match tab {
            SettingsTab::General => self.settings_general(theme, window, cx),
            SettingsTab::Stamp => self.settings_stamp(theme, cx),
            SettingsTab::Certificates => self.settings_certificates(theme, cx),
        };

        let mut nav = div().w(px(180.0)).flex_none().p_2().flex().flex_col().gap_1().border_r_1().border_color(theme.border).bg(theme.sidebar);
        for (t, title, sub) in [
            (SettingsTab::General, "General", "File names, timestamp"),
            (SettingsTab::Stamp, "Stamp", "Logo and how it looks"),
            (SettingsTab::Certificates, "Certificates", "Which ones, and the default"),
        ] {
            let selected = t == tab;
            nav = nav.child(
                div()
                    .id(SharedString::from(format!("settings-tab-{title}")))
                    .px_3()
                    .py_2()
                    .rounded(px(6.0))
                    .cursor_pointer()
                    .when(selected, |d| d.bg(theme.accent.opacity(0.12)))
                    .when(!selected, |d| d.hover(|s| s.bg(theme.hover)))
                    .on_click(cx.listener(move |this, _, window, cx| {
                        if let Some(d) = &mut this.draft {
                            d.tab = t;
                        }
                        this.settings_scroll.set_offset(gpui::point(px(0.0), px(0.0)));
                        window.focus(&this.focus);
                        cx.notify();
                    }))
                    .child(div().text_size(px(13.0)).font_weight(FontWeight::MEDIUM).when(selected, |d| d.text_color(theme.accent)).child(title))
                    .child(div().text_size(px(11.0)).text_color(theme.muted).child(sub)),
            );
        }

        let card = div()
            .id("settings-card")
            .w(px(780.0))
            .h(px(560.0))
            .rounded(px(12.0))
            .bg(theme.surface)
            .border_1()
            .border_color(theme.border)
            .shadow_lg()
            .overflow_hidden()
            .flex()
            .flex_col()
            .on_mouse_down(MouseButton::Left, |_, _, cx| cx.stop_propagation())
            .child(
                div()
                    .px_5()
                    .py_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_b_1()
                    .border_color(theme.border)
                    .child(div().text_size(px(15.0)).font_weight(FontWeight::SEMIBOLD).child("Settings"))
                    .child(
                        div()
                            .id("settings-close")
                            .size(px(26.0))
                            .rounded(px(13.0))
                            .flex()
                            .items_center()
                            .justify_center()
                            .text_size(px(16.0))
                            .text_color(theme.muted)
                            .cursor_pointer()
                            .hover(|s| s.bg(theme.hover).text_color(theme.text))
                            .child("✕")
                            .on_click(cx.listener(|this, _, window, cx| this.discard_settings(window, cx))),
                    ),
            )
            .child(
                div().flex_1().min_h_0().flex().flex_row().child(nav).child(
                    div()
                        .relative()
                        .flex_1()
                        .min_w_0()
                        .h_full()
                        .child(
                            div()
                                .id("settings-content")
                                .size_full()
                                .overflow_y_scroll()
                                .track_scroll(&self.settings_scroll)
                                .on_scroll_wheel(cx.listener(|_, _, _, cx| cx.notify()))
                                .child(div().w(px(598.0)).p_5().child(content)),
                        )
                        .children(settings_bar),
                ),
            )
            .child(
                div()
                    .px_5()
                    .py_3()
                    .flex()
                    .items_center()
                    .justify_between()
                    .border_t_1()
                    .border_color(theme.border)
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .text_size(px(12.0))
                            .when(dirty, |d| {
                                d.text_color(theme.warn).child(div().size(px(7.0)).rounded(px(4.0)).bg(theme.warn)).child("Unsaved changes")
                            })
                            .when(!dirty, |d| d.text_color(theme.faint).child("No changes")),
                    )
                    .child(
                        div()
                            .flex()
                            .items_center()
                            .gap_2()
                            .child(
                                button("settings-cancel", "Cancel", theme)
                                    .on_click(cx.listener(|this, _, window, cx| this.discard_settings(window, cx))),
                            )
                            .child(
                                primary_button("settings-save", "Save", dirty, theme)
                                    .when(dirty, |d| d.on_click(cx.listener(|this, _, window, cx| this.save_settings_draft(window, cx)))),
                            ),
                    ),
            );

        div()
            .id("settings-backdrop")
            .absolute()
            .top_0()
            .left_0()
            .size_full()
            // Scrolling and clicks stop here instead of reaching the document behind.
            .occlude()
            .bg(gpui::black().opacity(0.35))
            .flex()
            .items_center()
            .justify_center()
            // Clicking outside closes only when nothing would be lost.
            .on_mouse_down(
                MouseButton::Left,
                cx.listener(|this, _, window, cx| {
                    if !this.settings_dirty() {
                        this.discard_settings(window, cx);
                    }
                }),
            )
            .child(card)
            .into_any_element()
    }

    fn settings_general(&mut self, theme: &Theme, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let Some(ts) = self.draft.as_ref().map(|d| d.settings.timestamp) else { return div().into_any_element() };
        let suffix = self.suffix_section(theme, window, cx);
        div()
            .flex()
            .flex_col()
            .gap_6()
            .child(suffix)
            .child(
                div()
                    .flex()
                    .flex_col()
                    .gap_2()
                    .child(section_label("Timestamp", theme))
                    .child(checkbox("default-timestamp", ts, "Add a trusted timestamp by default", theme).on_click(cx.listener(
                        move |this, _, _, cx| {
                            this.edit_draft(cx, |s| s.timestamp = !ts);
                        },
                    )))
                    .child(
                        div()
                            .text_size(px(11.5))
                            .text_color(theme.muted)
                            .child("A timestamp from DigiCert's free service proves when you signed. Only a fingerprint of your signature is sent."),
                    ),
            )
            .into_any_element()
    }

    /// The suffix for signed copies: text field, placeholders, a worked example. Also a welcome step.
    pub(super) fn suffix_section(&mut self, theme: &Theme, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let Some(d) = &self.draft else { return div().into_any_element() };
        let focused = self.suffix_input.focus_handle(cx).is_focused(window);
        let name = self.default_signer_name();
        let today = Local::now().format("%Y-%m-%d").to_string();
        let template = d.settings.file_suffix.clone();
        let vars = |n| settings::NameVars { n, total: None, name: &name, date: today.clone() };
        let first = settings::suggested_name(Path::new("Contract.pdf"), &template, &vars(1));
        let second = settings::suggested_name(Path::new(&first), &template, &vars(2));
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(section_label("File name for signed copies", theme))
            .child(
                div()
                    .px_2()
                    .py(px(5.0))
                    .rounded(px(6.0))
                    .border_1()
                    .border_color(if focused { theme.accent } else { theme.border })
                    .bg(theme.bg)
                    .text_size(px(13.0))
                    .line_height(px(19.0))
                    .child(self.suffix_input.clone()),
            )
            .child(div().text_size(px(11.5)).text_color(theme.muted).child(
                "Added after the original name. Placeholders: {n} how many people have signed, {total} signature boxes, {name} your name, {date} today.",
            ))
            .child(
                div()
                    .mt_1()
                    .p_2()
                    .rounded(px(6.0))
                    .bg(theme.sidebar)
                    .flex()
                    .flex_col()
                    .gap(px(3.0))
                    .text_size(px(12.0))
                    .child(div().text_size(px(10.5)).text_color(theme.faint).child("EXAMPLE"))
                    .child(format!("Contract.pdf → {first}"))
                    .child(format!("{first} → {second}")),
            )
            .child(div().flex().child(
                div().id("reset-suffix").text_size(px(11.5)).text_color(theme.accent).cursor_pointer().child("Reset to default").on_click(
                    cx.listener(|this, _, _, cx| {
                        this.suffix_input.update(cx, |input, cx| input.set_text(settings::DEFAULT_SUFFIX, cx));
                        this.edit_draft(cx, |s| s.file_suffix = settings::DEFAULT_SUFFIX.to_string());
                    }),
                ),
            ))
            .into_any_element()
    }

    fn settings_stamp(&mut self, theme: &Theme, cx: &mut Context<Self>) -> AnyElement {
        let Some(d) = &self.draft else { return div().into_any_element() };
        let choice = d.settings.logo.clone();
        let custom = !matches!(choice.as_str(), "rocksign" | "default" | "none" | "");
        let has_logo = d.logo.is_some();
        let watermark = d.settings.logo_style != "header";
        let opacity = d.settings.logo_opacity;
        let mode = logo_mode_of(&d.settings);
        let logo = match (&d.logo_image, &d.logo) {
            (Some(image), Some(l)) => Some((image.clone(), l.aspect(), mode)),
            _ => None,
        };
        let name = self.default_signer_name();

        let mut section = div().flex().flex_col().gap_6();

        // Logo choice
        section = section.child(
            div()
                .flex()
                .flex_col()
                .gap_2()
                .child(section_label("Logo", theme))
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap_4()
                        .child(
                            radio("logo-none", matches!(choice.as_str(), "none" | "default" | ""), "None", theme)
                                .on_click(cx.listener(|this, _, _, cx| this.draft_set_logo("none".into(), cx))),
                        )
                        .child(
                            radio("logo-rocksign", choice == "rocksign", "RockSign", theme)
                                .on_click(cx.listener(|this, _, _, cx| this.draft_set_logo("rocksign".into(), cx))),
                        )
                        .when(custom, |d| d.child(radio("logo-custom", true, "Your image", theme)))
                        .child(button("logo-choose", "Choose image…", theme).on_click(cx.listener(|this, _, _, cx| this.choose_logo(cx)))),
                )
                .child(div().text_size(px(11.5)).text_color(theme.muted).child("PNG, JPEG or SVG. Transparent backgrounds look best.")),
        );

        if has_logo {
            let mut placement = div().flex().flex_col().gap_2().child(section_label("Placement", theme)).child(
                div()
                    .flex()
                    .items_center()
                    .gap_4()
                    .child(radio("logo-watermark", watermark, "Watermark behind the text", theme).on_click(cx.listener(|this, _, _, cx| {
                        this.edit_draft(cx, |s| s.logo_style = "watermark".into());
                    })))
                    .child(radio("logo-header", !watermark, "Above the text", theme).on_click(cx.listener(|this, _, _, cx| {
                        this.edit_draft(cx, |s| s.logo_style = "header".into());
                    }))),
            );
            if watermark {
                let mut row =
                    div().flex().items_center().gap_1().child(div().w(px(64.0)).text_size(px(12.0)).text_color(theme.muted).child("Opacity"));
                for pct in [10u32, 15, 25, 40, 60, 100] {
                    let selected = (opacity * 100.0).round() as u32 == pct;
                    let accent = theme.accent;
                    row = row.child(
                        div()
                            .id(SharedString::from(format!("opacity-{pct}")))
                            .px_2()
                            .py(px(3.0))
                            .rounded(px(5.0))
                            .border_1()
                            .border_color(if selected { accent } else { theme.border })
                            .when(selected, |d| d.bg(accent.opacity(0.12)).text_color(accent))
                            .text_size(px(12.0))
                            .cursor_pointer()
                            .hover(|s| s.bg(theme.hover))
                            .child(format!("{pct}%"))
                            .on_click(cx.listener(move |this, _, _, cx| this.edit_draft(cx, |s| s.logo_opacity = pct as f32 / 100.0))),
                    );
                }
                placement = placement.child(row);

                // Position: a 3×3 grid of spots in the box.
                let (wx, wy) = (d.settings.watermark_x, d.settings.watermark_y);
                let mut grid = div().flex().flex_col().gap(px(3.0)).p(px(4.0)).rounded(px(5.0)).border_1().border_color(theme.border);
                for (row_i, y) in [0.0f32, 0.5, 1.0].into_iter().enumerate() {
                    let mut cells = div().flex().gap(px(3.0));
                    for (col_i, x) in [0.0f32, 0.5, 1.0].into_iter().enumerate() {
                        let selected = (wx - x).abs() < 0.01 && (wy - y).abs() < 0.01;
                        let accent = theme.accent;
                        cells = cells.child(
                            div()
                                .id(SharedString::from(format!("wm-pos-{row_i}-{col_i}")))
                                .w(px(26.0))
                                .h(px(14.0))
                                .rounded(px(3.0))
                                .border_1()
                                .border_color(if selected { accent } else { theme.border })
                                .bg(if selected { accent } else { theme.surface })
                                .cursor_pointer()
                                .hover(move |s| s.border_color(accent))
                                .on_click(cx.listener(move |this, _, _, cx| {
                                    this.edit_draft(cx, |s| {
                                        s.watermark_x = x;
                                        s.watermark_y = y;
                                    })
                                })),
                        );
                    }
                    grid = grid.child(cells);
                }
                let vertical = match wy {
                    y if y < 0.25 => "top",
                    y if y > 0.75 => "bottom",
                    _ => "middle",
                };
                let horizontal = match wx {
                    x if x < 0.25 => "left",
                    x if x > 0.75 => "right",
                    _ => "center",
                };
                placement = placement.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_1()
                        .child(div().w(px(64.0)).text_size(px(12.0)).text_color(theme.muted).child("Position"))
                        .child(grid)
                        .child(div().ml_2().text_size(px(11.5)).text_color(theme.muted).child(if (wx, wy) == (0.5, 0.5) {
                            "centered".to_string()
                        } else {
                            format!("{vertical} {horizontal}")
                        })),
                );

                // Size: smaller logos leave room to move, e.g. under the name.
                let size = d.settings.watermark_size;
                let mut sizes =
                    div().flex().items_center().gap_1().child(div().w(px(64.0)).text_size(px(12.0)).text_color(theme.muted).child("Size"));
                for pct in [40u32, 60, 80, 100] {
                    let selected = (size * 100.0).round() as u32 == pct;
                    let accent = theme.accent;
                    sizes = sizes.child(
                        div()
                            .id(SharedString::from(format!("wm-size-{pct}")))
                            .px_2()
                            .py(px(3.0))
                            .rounded(px(5.0))
                            .border_1()
                            .border_color(if selected { accent } else { theme.border })
                            .when(selected, |d| d.bg(accent.opacity(0.12)).text_color(accent))
                            .text_size(px(12.0))
                            .cursor_pointer()
                            .hover(|s| s.bg(theme.hover))
                            .child(format!("{pct}%"))
                            .on_click(cx.listener(move |this, _, _, cx| this.edit_draft(cx, |s| s.watermark_size = pct as f32 / 100.0))),
                    );
                }
                placement = placement.child(sizes);
            }
            placement = placement.child(div().text_size(px(11.5)).text_color(theme.muted).child(if watermark {
                "Faded behind the text, like Acrobat's signature appearances. At full size it fills the box; make it smaller to move it, e.g. to the bottom under the name."
            } else {
                "Shown above the text when the box has room; left out in low boxes so the name stays readable."
            }));
            section = section.child(placement);
        }

        // Preview: a roomy and a low box, drawn exactly as they will be signed.
        let zoom = 1.25;
        let preview = |id: &'static str, label: &'static str, size: [f32; 2]| {
            let (w, h) = (size[0] * zoom, size[1] * zoom);
            div().flex().flex_col().gap_1().child(div().text_size(px(11.0)).text_color(theme.faint).child(label)).child(
                div().id(id).relative().w(px(w)).h(px(h)).bg(gpui::white()).border_1().border_color(theme.border).rounded(px(4.0)).child(
                    StampPreview { screen: [0.0, 0.0, w, h], size_pt: size, name: name.clone(), zoom, logo: logo.clone(), theme, framed: false }
                        .render(),
                ),
            )
        };
        section = section.child(div().flex().flex_col().gap_2().child(section_label("Preview", theme)).child(
            div().flex().items_start().gap_4().child(preview("preview-roomy", "Standard box", [190.0, 72.0])).child(preview(
                "preview-low",
                "Low box",
                [190.0, 26.0],
            )),
        ));
        section.into_any_element()
    }

    pub(super) fn settings_certificates(&mut self, theme: &Theme, cx: &mut Context<Self>) -> AnyElement {
        let Some(d) = &self.draft else { return div().into_any_element() };
        let draft = &d.settings;
        let mut section =
            div().flex().flex_col().gap_2().child(div().flex().items_center().justify_between().child(section_label("Certificates", theme)).child(
                div().id("reload-certs").text_size(px(11.5)).text_color(theme.accent).cursor_pointer().child("Reload from Keychain").on_click(
                    cx.listener(|this, _, _, cx| {
                        this.identities = None;
                        this.load_identities(cx);
                        cx.notify();
                    }),
                ),
            ));
        let list = match &self.identities {
            None => return section.child(div().text_size(px(12.0)).text_color(theme.muted).child("Reading your Keychain…")).into_any_element(),
            Some(Err(e)) => return section.child(div().text_size(px(12.0)).text_color(theme.bad).child(e.clone())).into_any_element(),
            Some(Ok(list)) if list.is_empty() => {
                return section
                    .child(
                        div()
                            .p_3()
                            .rounded(px(8.0))
                            .bg(theme.sidebar)
                            .flex()
                            .flex_col()
                            .gap_2()
                            .child(div().text_size(px(12.5)).font_weight(FontWeight::MEDIUM).child("No signing certificates in your Keychain yet"))
                            .child(div().text_size(px(12.0)).text_color(theme.muted).child(
                                "To add yours, double-click your certificate file (.p12 or .pfx) and enter its password. macOS keeps it in your login keychain. Then click Check again.",
                            ))
                            .child(
                                div()
                                    .text_size(px(12.0))
                                    .text_color(theme.muted)
                                    .child("Without one, RockSign still opens PDFs and checks their signatures."),
                            )
                            .child(div().flex().child(button("check-again", "Check again", theme).on_click(cx.listener(|this, _, _, cx| {
                                this.identities = None;
                                this.load_identities(cx);
                                cx.notify();
                            })))),
                    )
                    .into_any_element();
            }
            Some(Ok(list)) => list,
        };
        section = section
            .child(
                div()
                    .text_size(px(11.5))
                    .text_color(theme.muted)
                    .child("Show decides which certificates appear when you sign. Default is the one selected when you start signing."),
            )
            .child(
                radio("default-auto", draft.default_cert.is_none(), "Automatic default: the valid certificate that lasts longest", theme)
                    .on_click(cx.listener(|this, _, _, cx| this.edit_draft(cx, |s| s.default_cert = None))),
            );
        for (i, id) in list.iter().enumerate() {
            let key = cert_key(&id.cert);
            let visible = cert_visible_in(draft, id);
            let is_default = draft.default_cert.as_deref() == Some(key.as_str());
            let usable = id.is_usable();
            let expired = !id.cert.is_valid_at(Utc::now());
            let mut sub = format!(
                "{} · {} {}",
                id.cert.issuer.display_name(),
                if expired { "expired" } else { "valid until" },
                id.cert.not_after.format("%-d %b %Y")
            );
            if !id.cert.fits_document_signing() {
                sub.push_str(" · not meant for document signing");
            }
            let show_key = key.clone();
            let default_key = key.clone();
            section = section.child(
                div()
                    .flex()
                    .items_start()
                    .gap_3()
                    .py_2()
                    .border_t_1()
                    .border_color(theme.border)
                    .child(
                        div()
                            .id(SharedString::from(format!("cert-show-{i}")))
                            .mt(px(3.0))
                            .flex()
                            .items_center()
                            .gap_1()
                            .cursor_pointer()
                            .child(check_box(visible, theme.accent, theme))
                            .child(div().text_size(px(11.5)).text_color(theme.muted).child("Show"))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                let key = show_key.clone();
                                this.edit_draft(cx, |s| {
                                    s.cert_visible.insert(key.clone(), !visible);
                                    if visible && s.default_cert.as_ref() == Some(&key) {
                                        s.default_cert = None;
                                    }
                                });
                            })),
                    )
                    .child(div().mt(px(2.0)).w(px(72.0)).when(usable, |d| {
                        d.child(radio(format!("cert-default-{i}"), is_default, "Default", theme).on_click(cx.listener(move |this, _, _, cx| {
                            let key = default_key.clone();
                            this.edit_draft(cx, |s| {
                                s.cert_visible.insert(key.clone(), true);
                                s.default_cert = Some(key);
                            });
                        })))
                    }))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .when(!visible, |d| d.opacity(0.55))
                            .child(div().text_size(px(12.5)).font_weight(FontWeight::MEDIUM).child(id.cert.display_name()))
                            .child(div().text_size(px(11.5)).text_color(if expired { theme.bad } else { theme.muted }).child(sub)),
                    ),
            );
        }
        section.into_any_element()
    }

    /// Name for examples and previews: the default certificate's holder.
    pub(super) fn default_signer_name(&self) -> String {
        match (&self.identities, self.default_identity()) {
            (Some(Ok(list)), Some(i)) => list[i].cert.display_name(),
            _ => "Your Name".into(),
        }
    }
}
