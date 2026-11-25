//! Drawing the main window.

use chrono::Utc;
use gpui::{
    AnyElement, ClickEvent, Context, CursorStyle, ExternalPaths, FontWeight, IntoElement, MouseButton, MouseDownEvent, Render, SharedString, Window,
    div, img, prelude::*, px,
};
use rocksign_core::verify::SigKind;
use rocksign_core::{ChangeLevel, SignatureReport};

use super::widgets::*;
use super::*;
use crate::theme::Theme;
use crate::trust::TrustOutcome;

impl Render for RockSignView {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let theme = Theme::for_appearance(window.appearance());
        for image in self.stale_images.drain(..) {
            let _ = window.drop_image(image);
        }
        // Scrollbars use the sizes from the last layout; if those changed, draw once more.
        let handles = [&self.scroll, &self.files_scroll, &self.sidebar_scroll, &self.settings_scroll];
        let now = handles.map(|h| (f32::from(h.bounds().size.height), f32::from(h.max_offset().height) + f32::from(h.max_offset().width)));
        if now != self.scroll_seen {
            self.scroll_seen = now;
            window.request_animation_frame();
        }
        let viewer = self.render_viewer(&theme, window, cx);
        let files = self.render_files(&theme, cx);
        let sidebar = self.render_sidebar(&theme, cx);
        let titlebar = self.render_titlebar(&theme, cx);
        let settings = self.draft.is_some().then(|| self.render_settings(&theme, window, cx));
        let toast = self.toast.as_ref().map(|t| {
            div()
                .id("toast")
                .absolute()
                .bottom(px(18.0))
                .left(px(18.0))
                .w(px(480.0))
                .flex()
                .items_start()
                .gap_2()
                .px_3()
                .py_2()
                .rounded(px(8.0))
                .bg(theme.surface)
                .border_1()
                .border_color(t.level.color(&theme).opacity(0.6))
                .shadow_lg()
                .cursor_pointer()
                .child(status_badge(t.level, &theme, 16.0))
                .child(div().flex_1().min_w_0().overflow_hidden().text_size(px(12.5)).child(t.text.clone()))
                .on_click(cx.listener(|this, _, _, cx| {
                    this.toast = None;
                    cx.notify();
                }))
        });

        div()
            .key_context("RockSign")
            .track_focus(&self.focus)
            // While Settings is open, keys and menu commands don't reach the document behind it.
            .when(self.draft.is_none(), |d| {
                d.on_action(cx.listener(Self::on_open))
                    .on_action(cx.listener(Self::on_start_signing))
                    .on_action(cx.listener(Self::on_zoom_in))
                    .on_action(cx.listener(Self::on_zoom_out))
                    .on_action(cx.listener(Self::on_zoom_fit))
                    .on_action(cx.listener(Self::on_page_down))
                    .on_action(cx.listener(Self::on_page_up))
                    .on_action(cx.listener(Self::on_line_down))
                    .on_action(cx.listener(Self::on_line_up))
                    .on_action(cx.listener(Self::on_first_page))
                    .on_action(cx.listener(Self::on_last_page))
                    .on_action(cx.listener(Self::on_next_page))
                    .on_action(cx.listener(Self::on_prev_page))
                    .on_action(cx.listener(Self::on_next_file))
                    .on_action(cx.listener(Self::on_prev_file))
                    .on_action(cx.listener(Self::on_remove_file))
                    .on_action(cx.listener(Self::on_clear_signed))
                    .on_action(cx.listener(Self::on_clear_all))
                    .on_action(cx.listener(Self::on_show_welcome))
            })
            .on_action(cx.listener(Self::on_toggle_settings))
            .on_action(cx.listener(Self::on_escape))
            .on_action(cx.listener(Self::on_close_window))
            .on_mouse_move(cx.listener(Self::root_mouse_move))
            .on_mouse_up(MouseButton::Left, cx.listener(|this, _, _, cx| this.finish_drag(cx)))
            .on_mouse_up_out(MouseButton::Left, cx.listener(|this, _, _, cx| this.finish_drag(cx)))
            .relative()
            .size_full()
            .flex()
            .flex_col()
            .bg(theme.bg)
            .text_color(theme.text)
            .text_sm()
            .child(titlebar)
            .child(div().flex_1().min_h_0().flex().flex_row().child(files).child(viewer).child(sidebar))
            .children(toast)
            .children(settings)
    }
}

impl RockSignView {
    fn render_titlebar(&mut self, theme: &Theme, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let title = self.doc.as_ref().and_then(|d| d.path.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| "RockSign".into());
        div()
            .id("titlebar")
            .h(px(TITLEBAR_H))
            .flex_none()
            .flex()
            .items_center()
            .gap_2()
            .pl(px(84.0))
            .pr_3()
            .border_b_1()
            .border_color(theme.border)
            .bg(theme.sidebar)
            .on_click(|ev: &ClickEvent, window, _| {
                if ev.click_count() == 2 {
                    window.titlebar_double_click();
                }
            })
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .justify_center()
                    .text_size(px(12.5))
                    .font_weight(FontWeight::MEDIUM)
                    .text_color(theme.muted)
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .child(title),
            )
            .child(button("settings", "Settings", theme).on_click(cx.listener(|this, _, window, cx| this.open_settings(window, cx))))
    }

    fn render_files(&mut self, theme: &Theme, cx: &mut Context<Self>) -> AnyElement {
        let content = self.render_files_content(theme, cx);
        let bar = self.scrollbar("files-scroll", &self.files_scroll.clone(), Axis::Y, theme, cx);
        div()
            .relative()
            .w(px(FILES_W))
            .h_full()
            .flex_none()
            .border_r_1()
            .border_color(theme.border)
            .bg(theme.sidebar)
            .child(content)
            .children(bar)
            .into_any_element()
    }

    fn render_files_content(&mut self, theme: &Theme, cx: &mut Context<Self>) -> AnyElement {
        let done = self.files.iter().filter(|f| matches!(&f.status, FileStatus::Ready(l) if self.signed_by_me(l))).count();
        let mut list = div().flex().flex_col();
        for (i, f) in self.files.iter().enumerate() {
            let name = f.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            let (checked, color, sub, sub_color) = match &f.status {
                FileStatus::Loading => (false, theme.faint, "Opening…".to_string(), theme.muted),
                FileStatus::Failed(_) => (false, theme.bad, "Can't open this file".to_string(), theme.bad),
                FileStatus::Ready(l) => {
                    let mine = self.signed_by_me(l);
                    let n = l.report.signatures.len();
                    let total = l.report.fields.len().max(n);
                    let count = if total > n {
                        format!("{n} of {total} signed")
                    } else if n == 1 {
                        "1 signature".to_string()
                    } else {
                        format!("{n} signatures")
                    };
                    if self.verdict_level(l) == Some(Level::Bad) {
                        (mine, theme.bad, "Signature problem — check it".to_string(), theme.bad)
                    } else if mine {
                        (true, theme.ok, format!("Signed by you · {count}"), theme.muted)
                    } else if n == 0 {
                        (false, theme.ok, "Not signed yet".to_string(), theme.muted)
                    } else {
                        (false, theme.ok, format!("{count} · waiting for you"), theme.muted)
                    }
                }
            };
            let selected = self.current == Some(i);
            let group = SharedString::from(format!("file-row-{i}"));
            list = list.child(
                div()
                    .id(SharedString::from(format!("file-{i}")))
                    .group(group.clone())
                    .px_3()
                    .py(px(7.0))
                    .flex()
                    .items_start()
                    .gap_2()
                    .cursor_pointer()
                    .when(selected, |d| d.bg(theme.accent.opacity(0.12)))
                    .when(!selected, |d| d.hover(|s| s.bg(theme.hover)))
                    .on_click(cx.listener(move |this, _, _, cx| this.select_file(i, cx)))
                    .child(check_box(checked, color, theme).mt(px(2.0)))
                    .child(
                        div()
                            .flex_1()
                            .min_w_0()
                            .flex()
                            .flex_col()
                            .child(div().text_size(px(12.5)).font_weight(FontWeight::MEDIUM).truncate().child(name))
                            .child(div().text_size(px(11.5)).text_color(sub_color).truncate().child(sub)),
                    )
                    .child(
                        div()
                            .id(SharedString::from(format!("close-file-{i}")))
                            .px_1()
                            .rounded(px(4.0))
                            .text_color(theme.faint)
                            .opacity(0.0)
                            .group_hover(group, |s| s.opacity(1.0))
                            .hover(|s| s.text_color(theme.text))
                            .child("×")
                            .on_click(cx.listener(move |this, _, _, cx| {
                                cx.stop_propagation();
                                this.remove_file(i, cx);
                            })),
                    ),
            );
        }
        let hover = theme.hover;
        let open_button = div()
            .id("open-big")
            .w_full()
            .py(px(10.0))
            .rounded(px(8.0))
            .border_1()
            .border_color(theme.border)
            .bg(theme.surface)
            .flex()
            .items_center()
            .justify_center()
            .gap_2()
            .cursor_pointer()
            .shadow_sm()
            .hover(move |s| s.bg(hover))
            .on_click(cx.listener(|this, _, _, cx| this.prompt_open(cx)))
            .child(div().text_size(px(14.0)).font_weight(FontWeight::SEMIBOLD).child("Open PDFs…"))
            .child(div().text_size(px(11.5)).text_color(theme.muted).child("⌘O"));
        let column = div()
            .w(px(FILES_W))
            .flex()
            .flex_col()
            .child(div().px_3().pt_4().pb_1().child(open_button))
            .child(
                div()
                    .px_3()
                    .pt_3()
                    .pb_2()
                    .flex()
                    .items_center()
                    .justify_between()
                    .child(section_label("Documents", theme))
                    .when(!self.files.is_empty(), |d| {
                        d.child(div().text_size(px(11.5)).text_color(theme.muted).child(format!("{done} of {} signed by you", self.files.len())))
                    }),
            )
            .when(self.files.is_empty(), |d| {
                d.child(
                    div()
                        .px_3()
                        .text_size(px(12.0))
                        .text_color(theme.muted)
                        .child("No documents yet. Open some, or drop PDFs on the window — several at once is fine."),
                )
            })
            .child(list)
            .when(!self.files.is_empty(), |d| {
                let all = self.files.len();
                d.child(
                    div()
                        .px_3()
                        .pt_3()
                        .pb_4()
                        .flex()
                        .gap_2()
                        .when(done > 0 && done < all, |d| {
                            d.child(
                                button("clear-signed", format!("Clear signed ({done})"), theme)
                                    .on_click(cx.listener(|this, _, _, cx| this.clear_signed(cx))),
                            )
                        })
                        .child(
                            button("clear-all", if all == 1 { "Clear list".to_string() } else { format!("Clear all ({all})") }, theme)
                                .on_click(cx.listener(|this, _, _, cx| this.clear_all(cx))),
                        ),
                )
            });
        div()
            .id("files")
            .size_full()
            .overflow_y_scroll()
            .track_scroll(&self.files_scroll)
            .on_scroll_wheel(cx.listener(|_, _, _, cx| cx.notify()))
            .child(column)
            .into_any_element()
    }

    fn render_viewer(&mut self, theme: &Theme, window: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let (vw, vh) = self.viewport();

        if self.doc.is_none() {
            let (message, show_open) = match self.current.and_then(|i| self.files.get(i)).map(|f| &f.status) {
                Some(FileStatus::Loading) => ("Opening…".to_string(), false),
                Some(FileStatus::Failed(e)) => (format!("This file can't be opened. {e}"), false),
                _ => ("Open PDFs or drop them here — several at once is fine.".to_string(), true),
            };
            self.slots.clear();
            return div()
                .id("viewer")
                .flex_1()
                .h_full()
                .bg(theme.canvas)
                .flex()
                .flex_col()
                .items_center()
                .justify_center()
                .gap_3()
                .px_6()
                .on_drop(cx.listener(|this, paths: &ExternalPaths, _, cx| this.open_paths(paths.paths().to_vec(), cx)))
                .drag_over::<ExternalPaths>(|s, _, _, _| s.opacity(0.85))
                .child(div().text_color(theme.muted).child(message))
                .when(show_open, |d| {
                    d.child(primary_button("open-empty", "Open PDFs…", true, theme).on_click(cx.listener(|this, _, _, cx| this.prompt_open(cx))))
                })
                .into_any_element();
        }

        if self.fit_pending {
            if vw > 0.0 {
                self.zoom = self.fit_zoom(vw);
                self.fit_pending = false;
            } else {
                window.request_animation_frame();
            }
        }
        let content_w = self.compute_slots(vw.max(1.0));
        let (_, top) = self.scroll_pos();
        let probe = top + vh * 0.3;
        self.current_page = self.slots.iter().rposition(|s| s.y <= probe).unwrap_or(0);

        // Ask for the pages near the viewport at the current size; forget far-away ones.
        let scale = window.scale_factor();
        let visible: Vec<usize> = (0..self.slots.len())
            .filter(|i| {
                let s = self.slots[*i];
                s.y + s.h >= top - vh * 0.6 && s.y <= top + vh * 1.6
            })
            .collect();
        for &i in &visible {
            let want = ((self.slots[i].w * scale).round() as u32).max(1);
            let have = self.images.get(&i).map(|(w, _)| *w);
            if have != Some(want) && self.requested.get(&i) != Some(&want) {
                self.renderer.send(Request::Render { generation: self.generation, page: i, width: want });
                self.requested.insert(i, want);
            }
        }
        let (lo, hi) = (visible.first().copied().unwrap_or(0), visible.last().copied().unwrap_or(0));
        let far: Vec<usize> = self.images.keys().copied().filter(|i| *i + 2 < lo || *i > hi + 2).collect();
        for i in far {
            if let Some((_, img)) = self.images.remove(&i) {
                self.stale_images.push(img);
            }
        }

        let doc = self.doc.as_ref().expect("checked above");
        let signing = self.sign.as_ref().is_some_and(|m| !m.busy);
        let places: Vec<Placed> = self.sign.as_ref().map(|m| m.places.clone()).unwrap_or_default();
        let signer_name = match (&self.sign, &self.identities) {
            (Some(SignMode { identity: Some(i), .. }), Some(Ok(list))) => list.get(*i).map(|id| id.cert.display_name()),
            _ => None,
        };
        let logo = match (&self.logo_image, &self.logo) {
            (Some(image), Some(l)) => Some((image.clone(), l.aspect(), self.logo_mode())),
            _ => None,
        };
        let zoom = self.zoom;

        let pages: Vec<_> = self
            .slots
            .iter()
            .enumerate()
            .map(|(i, slot)| {
                let geom = &doc.report.pages[i];
                let mut page = div()
                    .id(SharedString::from(format!("page-{i}")))
                    .relative()
                    .flex_none()
                    .w(px(slot.w))
                    .h(px(slot.h))
                    .bg(gpui::white())
                    .shadow_md();
                if let Some((_, image)) = self.images.get(&i) {
                    page = page.child(img(image.clone()).absolute().top_0().left_0().w(px(slot.w)).h(px(slot.h)));
                }
                let place = |r: [f32; 4]| (r[0] * zoom, r[1] * zoom, (r[2] - r[0]) * zoom, (r[3] - r[1]) * zoom);

                // Existing signatures: colored outline and badge.
                for (si, sig) in doc.report.signatures.iter().enumerate() {
                    let (Some(p), Some(r)) = (sig.page, sig.rect) else { continue };
                    if p != i {
                        continue;
                    }
                    let v = verdict(sig, doc.trust.get(si));
                    let color = v.level.color(theme);
                    let hovered = self.hovered_sig == Some(si);
                    let (x, y, w, h) = place(geom.user_rect_to_view(r));
                    page = page.child(
                        div()
                            .absolute()
                            .left(px(x - 3.0))
                            .top(px(y - 3.0))
                            .w(px(w + 6.0))
                            .h(px(h + 6.0))
                            .rounded(px(4.0))
                            .border(px(if hovered { 2.5 } else { 1.5 }))
                            .border_color(color.opacity(if hovered { 1.0 } else { 0.55 }))
                            .when(hovered, |d| d.bg(color.opacity(0.06)))
                            .child(div().absolute().top(px(-8.0)).right(px(-8.0)).child(status_badge(v.level, theme, 16.0))),
                    );
                }

                // Empty signature fields.
                for f in doc.report.empty_fields() {
                    let (Some(p), Some(r)) = (f.page, f.rect) else { continue };
                    if p != i || !f.visible || places.contains(&Placed::Field(f.name.clone())) {
                        continue;
                    }
                    let (x, y, w, h) = place(geom.user_rect_to_view(r));
                    let color = if signing { theme.accent } else { theme.faint };
                    page = page.child(
                        div()
                            .absolute()
                            .left(px(x))
                            .top(px(y))
                            .w(px(w))
                            .h(px(h))
                            .rounded(px(3.0))
                            .border_2()
                            .border_dashed()
                            .border_color(color)
                            .bg(color.opacity(if signing { 0.08 } else { 0.03 }))
                            .when(signing, |d| d.cursor_pointer())
                            .flex()
                            .items_end()
                            .p_1()
                            .child(
                                div()
                                    .text_size(px((10.0 * zoom).clamp(9.0, 13.0)))
                                    .text_color(color)
                                    .font_weight(FontWeight::MEDIUM)
                                    .child(if signing { format!("Click to sign here · {}", f.name) } else { f.name.clone() }),
                            ),
                    );
                }

                // Where the new signatures will go, previewed exactly as they will be drawn.
                for spot in places.iter() {
                    let rect = match spot {
                        Placed::New { page: p, rect } if *p == i => Some(*rect),
                        Placed::Field(name) => doc
                            .report
                            .fields
                            .iter()
                            .find(|f| &f.name == name && f.page == Some(i))
                            .and_then(|f| f.rect)
                            .map(|r| geom.user_rect_to_view(r)),
                        _ => None,
                    };
                    let Some(r) = rect else { continue };
                    let (x, y, w, h) = place(r);
                    page = page.child(
                        StampPreview {
                            screen: [x, y, w, h],
                            size_pt: [r[2] - r[0], r[3] - r[1]],
                            name: signer_name.clone().unwrap_or_else(|| "Choose a certificate".into()),
                            zoom,
                            logo: logo.clone(),
                            theme,
                            framed: true,
                        }
                        .render(),
                    );
                    if signing {
                        let target = spot.clone();
                        let hover = theme.hover;
                        page = page.child(
                            div()
                                .id(SharedString::from(format!("unplace-{i}-{}", (x * 10.0) as i64 + (y * 10.0) as i64 * 100_000)))
                                .absolute()
                                .left(px(x + w - 9.0))
                                .top(px(y - 9.0))
                                .size(px(18.0))
                                .rounded(px(9.0))
                                .border_1()
                                .border_color(theme.border)
                                .bg(theme.surface)
                                .shadow_sm()
                                .flex()
                                .items_center()
                                .justify_center()
                                .text_size(px(12.0))
                                .text_color(theme.muted)
                                .cursor_pointer()
                                .hover(move |s| s.bg(hover))
                                .child("×")
                                .on_mouse_down(
                                    MouseButton::Left,
                                    cx.listener(move |this, _, _, cx| {
                                        cx.stop_propagation();
                                        this.remove_place(&target, cx);
                                    }),
                                ),
                        );
                    }
                }

                if let Some(d) = self.drag.as_ref().filter(|d| d.page == i) {
                    let r = [d.start.0.min(d.current.0), d.start.1.min(d.current.1), d.start.0.max(d.current.0), d.start.1.max(d.current.1)];
                    let (x, y, w, h) = place(r);
                    page = page.child(
                        div().absolute().left(px(x)).top(px(y)).w(px(w)).h(px(h)).border_2().border_color(theme.accent).bg(theme.accent.opacity(0.1)),
                    );
                }
                page
            })
            .collect();

        let scroller = div()
            .id("viewer")
            .size_full()
            .overflow_scroll()
            .track_scroll(&self.scroll)
            .bg(theme.canvas)
            .when(signing, |d| d.cursor(CursorStyle::Crosshair))
            .on_scroll_wheel(cx.listener(|_, _, _, cx| cx.notify()))
            .on_mouse_down(MouseButton::Left, cx.listener(Self::viewer_mouse_down))
            .on_drop(cx.listener(|this, paths: &ExternalPaths, _, cx| this.open_paths(paths.paths().to_vec(), cx)))
            .drag_over::<ExternalPaths>(|s, _, _, _| s.opacity(0.85))
            .child(div().w(px(content_w)).flex().flex_col().items_center().pt(px(PAD)).pb(px(PAD)).gap(px(GAP)).children(pages));

        let handle = self.scroll.clone();
        let vbar = self.scrollbar("vscroll", &handle, Axis::Y, theme, cx);
        let hbar = self.scrollbar("hscroll", &handle, Axis::X, theme, cx);
        let toolbar = self.render_viewer_toolbar(theme, cx);
        div()
            .flex_1()
            .min_w_0()
            .h_full()
            .flex()
            .flex_col()
            .child(toolbar)
            .child(div().relative().flex_1().min_h_0().child(scroller).children(vbar).children(hbar))
            .into_any_element()
    }

    /// Above the pages: page number and navigation on the left, a hint in the middle, zoom on the right.
    fn render_viewer_toolbar(&self, theme: &Theme, cx: &mut Context<Self>) -> AnyElement {
        let count = self.slots.len().max(1);
        let pages = format!("Page {} of {count}", (self.current_page + 1).min(count));
        let zoom = format!("{}%", (self.zoom * 100.0).round());
        let hint = match &self.sign {
            Some(m) if m.busy => "Signing…",
            Some(m) if m.places.is_empty() => "Drag a box on the page for your stamp, or click for a standard size",
            Some(m) if m.places == [Placed::Invisible] => "No visible stamp",
            Some(_) => "Click another page to add a stamp there · drag again to move one",
            None => "",
        };
        div()
            .h(px(38.0))
            .flex_none()
            .px_3()
            .flex()
            .items_center()
            .gap_3()
            .border_b_1()
            .border_color(theme.border)
            .bg(theme.bg)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .child(button("prev-page", "‹", theme).on_click(cx.listener(|this, _, _, cx| {
                        this.go_to_page(this.current_page.saturating_sub(1), cx);
                    })))
                    .child(div().min_w(px(96.0)).flex().justify_center().text_size(px(12.5)).text_color(theme.muted).child(pages))
                    .child(button("next-page", "›", theme).on_click(cx.listener(|this, _, _, cx| {
                        let last = this.slots.len().saturating_sub(1);
                        this.go_to_page((this.current_page + 1).min(last), cx);
                    }))),
            )
            .child(
                div()
                    .flex_1()
                    .min_w_0()
                    .flex()
                    .justify_center()
                    .text_size(px(12.0))
                    .text_color(theme.accent)
                    .overflow_hidden()
                    .whitespace_nowrap()
                    .text_ellipsis()
                    .child(hint),
            )
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_1()
                    .child(button("zoom-out", "−", theme).on_click(cx.listener(|this, _, _, cx| this.set_zoom(this.zoom / 1.2, cx))))
                    .child(div().w(px(46.0)).flex().justify_center().text_size(px(12.5)).text_color(theme.muted).child(zoom))
                    .child(button("zoom-in", "+", theme).on_click(cx.listener(|this, _, _, cx| this.set_zoom(this.zoom * 1.2, cx))))
                    .child(button("zoom-fit", "Fit width", theme).on_click(cx.listener(|this, _, _, cx| {
                        this.fit_pending = true;
                        cx.notify();
                    }))),
            )
            .into_any_element()
    }

    /// A draggable scrollbar for a scroll area, drawn over its edge; None when nothing scrolls.
    /// Put it in a `relative` wrapper the same size as the scroll area.
    pub(super) fn scrollbar(&self, id: &'static str, handle: &ScrollHandle, axis: Axis, theme: &Theme, cx: &mut Context<Self>) -> Option<AnyElement> {
        let (view, extra, at) = scroll_metrics(handle, axis);
        if extra <= 0.5 || view <= 0.0 {
            return None;
        }
        let (thumb, travel) = thumb_geometry(view, extra);
        let pos = (at / extra).clamp(0.0, 1.0) * travel;
        let active = self.scroll_drag.as_ref().is_some_and(|d| d.axis == axis && d.handle.bounds() == handle.bounds());
        let color = theme.muted.opacity(if active { 0.8 } else { 0.45 });
        let handle = handle.clone();
        let track = div().id(id).absolute().on_mouse_down(
            MouseButton::Left,
            cx.listener(move |this, ev: &MouseDownEvent, _, cx| {
                cx.stop_propagation();
                this.start_scroll_drag(handle.clone(), axis, ev.position, cx);
            }),
        );
        Some(
            match axis {
                Axis::Y => track
                    .top_0()
                    .right_0()
                    .bottom_0()
                    .w(px(SCROLLBAR))
                    .child(div().absolute().top(px(pos)).right(px(2.0)).w(px(7.0)).h(px(thumb)).rounded(px(4.0)).bg(color)),
                Axis::X => track
                    .left_0()
                    .right_0()
                    .bottom_0()
                    .h(px(SCROLLBAR))
                    .child(div().absolute().left(px(pos)).bottom(px(2.0)).h(px(7.0)).w(px(thumb)).rounded(px(4.0)).bg(color)),
            }
            .into_any_element(),
        )
    }

    fn render_sidebar(&mut self, theme: &Theme, cx: &mut Context<Self>) -> AnyElement {
        let content = self.render_sidebar_content(theme, cx);
        let bar = self.scrollbar("sidebar-scroll", &self.sidebar_scroll.clone(), Axis::Y, theme, cx);
        div()
            .relative()
            .w(px(SIDEBAR_W))
            .h_full()
            .flex_none()
            .border_l_1()
            .border_color(theme.border)
            .bg(theme.sidebar)
            .child(content)
            .children(bar)
            .into_any_element()
    }

    fn sidebar_scroll_area(&self, column: gpui::Div, cx: &mut Context<Self>) -> gpui::Stateful<gpui::Div> {
        div()
            .id("sidebar")
            .size_full()
            .overflow_y_scroll()
            .track_scroll(&self.sidebar_scroll)
            .on_scroll_wheel(cx.listener(|_, _, _, cx| cx.notify()))
            .child(column)
    }

    fn render_sidebar_content(&mut self, theme: &Theme, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let mut col = div().w(px(SIDEBAR_W)).p_4().flex().flex_col().gap_3();

        if self.sign.is_some() {
            col = col.child(self.render_sign_panel(theme, cx));
        }

        let Some(doc) = &self.doc else {
            let col =
                col.child(div().flex().flex_col().gap_2().child(section_label("Signatures", theme)).child(
                    div().text_color(theme.muted).text_size(px(12.5)).child(
                        "Open PDFs to see who signed them and whether they changed since. Then sign them with a certificate from your Keychain.",
                    ),
                ));
            return self.sidebar_scroll_area(col, cx);
        };

        if self.sign.is_none() {
            col = col.child(self.render_sign_button(doc, theme, cx));
        }

        let total = doc.report.fields.len().max(doc.report.signatures.len());
        let signed = doc.report.signatures.len();
        let summary = if signed == 0 && total == 0 {
            "Not signed yet".to_string()
        } else if doc.report.empty_fields().next().is_some() {
            format!("{signed} of {total} signed")
        } else if signed == 1 {
            "1 signature".to_string()
        } else {
            format!("{signed} signatures")
        };
        col = col.child(
            div()
                .flex()
                .items_center()
                .justify_between()
                .child(section_label("Signatures", theme))
                .child(div().text_size(px(12.0)).text_color(theme.muted).child(summary)),
        );

        if let Some(p) = doc.report.certification {
            let text = match p {
                1 => "Certified document: no changes are allowed, so it can't be signed again.",
                2 => "Certified document: form filling and signing are allowed.",
                _ => "Certified document: form filling, comments and signing are allowed.",
            };
            col = col.child(div().text_size(px(12.0)).text_color(theme.muted).child(text));
        }

        for (i, sig) in doc.report.signatures.iter().enumerate() {
            col = col.child(self.render_sig_card(i, sig, doc.trust.get(i), theme, cx));
        }

        for f in doc.report.empty_fields() {
            let name = f.name.clone();
            col = col.child(
                div()
                    .id(SharedString::from(format!("field-{}", f.name)))
                    .rounded(px(8.0))
                    .border_1()
                    .border_dashed()
                    .border_color(theme.faint)
                    .p_3()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(div().size(px(16.0)).rounded(px(8.0)).border_1().border_color(theme.faint))
                    .child(div().flex_1().flex().flex_col().child(div().font_weight(FontWeight::MEDIUM).child(f.name.clone())).child(
                        div().text_size(px(12.0)).text_color(theme.muted).child(match f.page {
                            Some(p) => format!("Waiting for signature · page {}", p + 1),
                            None => "Waiting for signature".to_string(),
                        }),
                    ))
                    .when(self.sign.is_none(), |d| {
                        d.child(button(format!("sign-{name}"), "Sign here", theme).on_click(cx.listener(move |this, _, _, cx| {
                            this.start_signing(cx);
                            if let Some(m) = &mut this.sign {
                                m.places = vec![Placed::Field(name.clone())];
                            }
                        })))
                    }),
            );
        }

        if doc.report.signatures.is_empty() && doc.report.fields.is_empty() {
            col = col.child(
                div().text_size(px(12.5)).text_color(theme.muted).child("Nobody has signed this document yet. Click Sign… to add your signature."),
            );
        }
        self.sidebar_scroll_area(col, cx)
    }

    /// The big "Sign this document" button at the top of the right column.
    fn render_sign_button(&self, doc: &Loaded, theme: &Theme, cx: &mut Context<Self>) -> AnyElement {
        let blocker = doc.report.signing_blocker.clone();
        let enabled = blocker.is_none();
        let accent = theme.accent;
        let note = match &blocker {
            Some(b) => Some((b.clone(), theme.bad)),
            None if self.signed_by_me(doc) => Some(("You have already signed this file.".to_string(), theme.muted)),
            None => doc.report.empty_fields().next().map(|f| (format!("A signature box is waiting: “{}”.", f.name), theme.muted)),
        };
        div()
            .flex()
            .flex_col()
            .gap_2()
            .child(
                div()
                    .id("sign-big")
                    .w_full()
                    .py(px(12.0))
                    .rounded(px(8.0))
                    .bg(if enabled { accent } else { theme.faint.opacity(0.4) })
                    .text_color(theme.accent_text)
                    .flex()
                    .items_center()
                    .justify_center()
                    .gap_2()
                    .when(enabled, |d| {
                        d.cursor_pointer()
                            .shadow_sm()
                            .hover(move |s| s.bg(accent.opacity(0.88)))
                            .on_click(cx.listener(|this, _, _, cx| this.start_signing(cx)))
                    })
                    .child(div().text_size(px(14.5)).font_weight(FontWeight::SEMIBOLD).child("Sign this document"))
                    .child(div().text_size(px(11.5)).opacity(0.7).child("⌘S")),
            )
            .when_some(note, |d, (text, color)| d.child(div().text_size(px(11.5)).text_color(color).child(text)))
            .into_any_element()
    }

    fn render_sig_card(&self, idx: usize, sig: &SignatureReport, trust: Option<&TrustOutcome>, theme: &Theme, cx: &mut Context<Self>) -> AnyElement {
        let v = verdict(sig, trust);
        let expanded = self.expanded.contains(&idx);
        let color = v.level.color(theme);
        let when = match (&sig.timestamp, sig.claimed_time) {
            (Some(t), _) if t.valid => format!(
                "Signed {} · timestamp by {}",
                local(t.time),
                t.authority.as_ref().map(|a| a.display_name()).unwrap_or_else(|| "a timestamp authority".into())
            ),
            (_, Some(c)) => format!("Signed {} (signer's computer clock)", local(c.with_timezone(&Utc))),
            _ => "Signing time unknown".into(),
        };
        let kind = match sig.kind {
            SigKind::Approval => None,
            SigKind::Certification(_) => Some("Certification signature"),
            SigKind::DocTimestamp => Some("Document timestamp"),
        };
        let page = sig.page;

        let mut card = div()
            .id(SharedString::from(format!("sig-{idx}")))
            .rounded(px(8.0))
            .border_1()
            .border_color(if self.hovered_sig == Some(idx) { color.opacity(0.7) } else { theme.border })
            .bg(theme.surface)
            .p_3()
            .flex()
            .flex_col()
            .gap_1()
            .cursor_pointer()
            .on_hover(cx.listener(move |this, hovered: &bool, _, cx| {
                if *hovered {
                    this.hovered_sig = Some(idx);
                } else if this.hovered_sig == Some(idx) {
                    this.hovered_sig = None;
                }
                cx.notify();
            }))
            .on_click(cx.listener(move |this, _, _, cx| {
                if !this.expanded.remove(&idx) {
                    this.expanded.insert(idx);
                }
                if let Some(p) = page {
                    this.go_to_page(p, cx);
                }
                cx.notify();
            }))
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap_2()
                    .child(status_badge(v.level, theme, 18.0))
                    .child(div().flex_1().min_w_0().font_weight(FontWeight::SEMIBOLD).truncate().child(sig.signer_name()))
                    .child(div().text_size(px(11.0)).text_color(theme.faint).child(format!("#{}", idx + 1))),
            )
            .child(div().text_size(px(12.5)).text_color(color).child(v.title))
            .child(div().text_size(px(12.0)).text_color(theme.muted).child(when))
            .when_some(kind, |d, k| d.child(div().text_size(px(12.0)).text_color(theme.muted).child(k)));

        if expanded {
            let row = |label: &str, value: String| {
                div()
                    .flex()
                    .gap_2()
                    .text_size(px(12.0))
                    .child(div().w(px(84.0)).flex_none().text_color(theme.faint).child(label.to_string()))
                    .child(div().flex_1().min_w_0().child(value))
            };
            let mut details = div().mt_2().pt_2().border_t_1().border_color(theme.border).flex().flex_col().gap_1();
            if let Some(c) = &sig.signer {
                details = details
                    .child(row("Signer", c.subject.to_string()))
                    .child(row("Issued by", c.issuer.display_name()))
                    .child(row("Valid", format!("{} – {}", c.not_before.format("%-d %b %Y"), c.not_after.format("%-d %b %Y"))))
                    .child(row("Key", c.key_description()));
            }
            let trust_text = match trust {
                Some(t) if t.trusted && t.qualified_provider.is_some() => {
                    format!("Qualified certificate from {} (Czech trusted list)", t.qualified_provider.unwrap_or_default())
                }
                Some(t) if t.trusted => "Trusted by this Mac".to_string(),
                Some(t) => t.problem.clone().unwrap_or_else(|| "Not trusted".into()),
                None => "Unknown".into(),
            };
            details = details.child(row("Trust", trust_text));
            match &sig.timestamp {
                Some(t) if t.valid => details = details.child(row("Timestamp", format!("{} (proves the signing time)", local(t.time)))),
                Some(t) => details = details.child(row("Timestamp", format!("invalid: {}", t.problem.clone().unwrap_or_default()))),
                None => details = details.child(row("Timestamp", "none — the time comes from the signer's computer".into())),
            }
            let later = match sig.later.level {
                ChangeLevel::None => "None, it covers the whole file".to_string(),
                ChangeLevel::Signing => "Only signatures were added".to_string(),
                _ => sig.later.notes.join(" "),
            };
            details = details.child(row("Changes after", later));
            if let Some(r) = &sig.reason {
                details = details.child(row("Reason", r.clone()));
            }
            if let Some(p) = &sig.problem {
                details = details.child(row("Problem", p.clone()));
            }
            details = details.child(row("Format", format!("{} · {}", sig.sub_filter, sig.algorithm)));

            let untrusted_but_intact = sig.is_intact() && trust.is_some_and(|t| !t.trusted);
            if let Some(anchor) = trust.and_then(|t| t.anchor_candidate()).filter(|_| untrusted_but_intact).cloned() {
                let label = format!("Trust “{}” on this Mac", anchor.display_name());
                details = details.child(
                    div()
                        .mt_2()
                        .flex()
                        .flex_col()
                        .gap_1()
                        .child(div().text_size(px(11.5)).text_color(theme.muted).child(
                            "Only do this if you know this issuer, e.g. your company's certificate authority. Check the fingerprint with them:",
                        ))
                        .child(div().text_size(px(10.0)).text_color(theme.faint).child(anchor.fingerprint_hex()))
                        .child(div().flex().child(button(format!("trust-{idx}"), label, theme).on_click(cx.listener(move |this, _, _, cx| {
                            cx.stop_propagation();
                            this.trust_issuer(anchor.clone(), cx);
                        })))),
                );
            }
            card = card.child(details);
        } else {
            card = card.child(div().text_size(px(11.0)).text_color(theme.faint).child("Details…"));
        }
        card.into_any_element()
    }

    fn render_sign_panel(&mut self, theme: &Theme, cx: &mut Context<Self>) -> AnyElement {
        let mode = self.sign.as_ref().expect("sign mode");
        let blocker = self.doc.as_ref().and_then(|d| d.report.signing_blocker.clone());
        let busy = mode.busy;
        let mut panel =
            div().rounded(px(10.0)).border_1().border_color(theme.accent.opacity(0.5)).bg(theme.surface).p_3().flex().flex_col().gap_3().child(
                div().flex().items_center().justify_between().child(div().font_weight(FontWeight::SEMIBOLD).child("Sign this document")).when(
                    !busy,
                    |d| {
                        d.child(div().id("cancel-sign").text_size(px(12.0)).text_color(theme.muted).cursor_pointer().child("Cancel").on_click(
                            cx.listener(|this, _, _, cx| {
                                this.sign = None;
                                cx.notify();
                            }),
                        ))
                    },
                ),
            );

        if let Some(b) = blocker {
            return panel.child(div().text_size(px(12.5)).text_color(theme.bad).child(b)).into_any_element();
        }

        // 1. Certificate
        let mut certs = div().flex().flex_col().gap_1().child(section_label("1 · Certificate", theme));
        match &self.identities {
            None => certs = certs.child(div().text_size(px(12.5)).text_color(theme.muted).child("Reading your Keychain…")),
            Some(Err(e)) => certs = certs.child(div().text_size(px(12.5)).text_color(theme.bad).child(e.clone())),
            Some(Ok(list)) if list.is_empty() => {
                certs = certs.child(div().text_size(px(12.5)).text_color(theme.muted).child(
                    "No certificates with a private key were found in your Keychain. Import your signing certificate (.p12/.pfx) into Keychain Access, then try again.",
                ))
            }
            Some(Ok(list)) => {
                let hidden = list.iter().filter(|i| !self.cert_visible(i)).count();
                for (i, id) in list.iter().enumerate() {
                    let shown = self.cert_visible(id);
                    if !self.show_all_identities && !shown && mode.identity != Some(i) {
                        continue;
                    }
                    let selected = mode.identity == Some(i);
                    let expired = !id.cert.is_valid_at(Utc::now());
                    let sub = format!(
                        "{} · {} {}",
                        id.cert.issuer.display_name(),
                        if expired { "expired" } else { "valid until" },
                        id.cert.not_after.format("%-d %b %Y")
                    );
                    certs = certs.child(
                        div()
                            .id(SharedString::from(format!("identity-{i}")))
                            .flex()
                            .items_start()
                            .gap_2()
                            .p_2()
                            .rounded(px(6.0))
                            .cursor_pointer()
                            .when(selected, |d| d.bg(theme.accent.opacity(0.1)))
                            .hover(|s| s.bg(theme.hover))
                            .on_click(cx.listener(move |this, _, _, cx| {
                                if let Some(m) = &mut this.sign {
                                    m.identity = Some(i);
                                }
                                cx.notify();
                            }))
                            .child(
                                div()
                                    .mt(px(2.0))
                                    .size(px(12.0))
                                    .rounded(px(6.0))
                                    .border_1()
                                    .border_color(if selected { theme.accent } else { theme.faint })
                                    .when(selected, |d| d.border(px(4.0))),
                            )
                            .child(
                                div()
                                    .flex_1()
                                    .min_w_0()
                                    .flex()
                                    .flex_col()
                                    .child(div().text_size(px(12.5)).font_weight(FontWeight::MEDIUM).child(id.cert.display_name()))
                                    .child(div().text_size(px(11.5)).text_color(if expired { theme.bad } else { theme.muted }).child(sub)),
                            ),
                    );
                }
                if hidden > 0 {
                    let label = if self.show_all_identities {
                        "Hide them again".to_string()
                    } else if hidden == 1 {
                        "Show 1 hidden certificate (choose which appear in Settings)".to_string()
                    } else {
                        format!("Show {hidden} hidden certificates (choose which appear in Settings)")
                    };
                    certs = certs.child(div().id("show-all-ids").text_size(px(11.5)).text_color(theme.accent).cursor_pointer().child(label).on_click(
                        cx.listener(|this, _, _, cx| {
                            this.show_all_identities = !this.show_all_identities;
                            cx.notify();
                        }),
                    ));
                }
            }
        }
        panel = panel.child(certs);

        // 2. Placement
        let has_empty = self.doc.as_ref().is_some_and(|d| d.report.empty_fields().any(|f| f.visible));
        let invisible = mode.places == [Placed::Invisible];
        let mut place_list = div().flex().flex_col().gap_1();
        if mode.places.is_empty() {
            place_list = place_list.child(div().text_size(px(12.5)).text_color(theme.muted).child(if has_empty {
                "Click an empty signature box on the page, or drag a box anywhere."
            } else {
                "Drag a box on the page where the stamp should go, or just click for a standard size."
            }));
        } else if invisible {
            place_list = place_list
                .child(div().text_size(px(12.5)).text_color(theme.muted).child("No visible stamp. The signature still shows in signature panels."));
        } else if let Some(doc) = &self.doc {
            let mut sorted = mode.places.clone();
            sorted.sort_by_key(|p| place_order(doc, p));
            for (k, place) in sorted.into_iter().enumerate() {
                let page = place_page(doc, &place).map(|p| format!("Page {}", p + 1)).unwrap_or_default();
                let what = match &place {
                    Placed::Field(name) => format!("{page} · box “{name}”"),
                    _ => page,
                };
                let hover = theme.hover;
                place_list = place_list.child(
                    div()
                        .flex()
                        .items_center()
                        .gap_2()
                        .px_2()
                        .py(px(5.0))
                        .rounded(px(6.0))
                        .bg(theme.accent.opacity(0.07))
                        .child(div().flex_1().min_w_0().truncate().text_size(px(12.5)).child(what))
                        .when(!busy, |d| {
                            d.child(
                                div()
                                    .id(SharedString::from(format!("remove-place-{k}")))
                                    .px_1()
                                    .rounded(px(4.0))
                                    .text_color(theme.muted)
                                    .cursor_pointer()
                                    .hover(move |s| s.bg(hover))
                                    .child("×")
                                    .on_click(cx.listener(move |this, _, _, cx| this.remove_place(&place, cx))),
                            )
                        }),
                );
            }
            let n = mode.places.len();
            place_list = place_list.child(div().text_size(px(11.5)).text_color(theme.faint).child(if n == 1 {
                "Need it on another page too? Click there to add a second stamp.".to_string()
            } else {
                format!("{n} stamps, each its own signature, saved together in one copy. macOS may ask for your Keychain password for each.")
            }));
        }
        panel = panel.child(div().flex().flex_col().gap_1().child(section_label("2 · Where", theme)).child(place_list).child(
            checkbox("invisible", invisible, "No visible stamp", theme).on_click(cx.listener(move |this, _, _, cx| {
                if let Some(m) = &mut this.sign {
                    m.places = if invisible { Vec::new() } else { vec![Placed::Invisible] };
                }
                cx.notify();
            })),
        ));

        // 3. Timestamp
        let ts = mode.timestamp;
        panel = panel.child(
            div()
                .flex()
                .flex_col()
                .gap_1()
                .child(section_label("3 · Time", theme))
                .child(checkbox("timestamp", ts, "Add a trusted timestamp", theme).on_click(cx.listener(move |this, _, _, cx| {
                    if let Some(m) = &mut this.sign {
                        m.timestamp = !ts;
                    }
                    cx.notify();
                })))
                .child(div().text_size(px(11.5)).text_color(theme.faint).child(if ts {
                    "Proves when you signed (from DigiCert's free timestamp service; only a fingerprint of your signature is sent)."
                } else {
                    "The time will come from this Mac's clock only."
                })),
        );

        let ready = self.can_sign();
        let stamps = mode.places.len();
        let sign_label = if busy {
            "Signing…".to_string()
        } else if stamps > 1 {
            format!("Sign {stamps}× and save copy…")
        } else {
            "Sign and save copy…".to_string()
        };
        panel = panel.child(
            div()
                .flex()
                .items_center()
                .gap_2()
                .child(
                    primary_button("do-sign", sign_label, ready, theme)
                        .when(ready, |d| d.on_click(cx.listener(|this, _, _, cx| this.sign_and_save(cx)))),
                )
                .when(busy, |d| d.child(div().text_size(px(11.5)).text_color(theme.muted).child("Confirm in the Keychain prompt if asked."))),
        );
        panel.into_any_element()
    }
}
