//! The main window: a list of open files (left), the pages (middle), signatures and signing
//! (right). State and behaviour live here; drawing is in `render.rs`.

mod render;
mod settings_view;
mod welcome;
mod widgets;

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use futures::StreamExt;
use gpui::{
    AppContext as _, Context, Entity, FocusHandle, MouseDownEvent, MouseMoveEvent, PathPromptOptions, Pixels, Point, RenderImage, ScrollHandle,
    Subscription, Window, point, px,
};
use rocksign_core::Certificate;
use rocksign_core::logo::Logo;
use rocksign_core::sign::Target;
use rocksign_core::stamp::{LogoMode, Watermark};
use smallvec::SmallVec;

use crate::actions::*;
use crate::jobs::{self, Loaded, SignJob};
use crate::keychain::{self, Identity};
use crate::render::{Rendered, Request, Worker};
use crate::settings::{self, NameVars, Settings};
use crate::text_input::{InputEvent, TextInput};
use crate::trust;
use widgets::{Level, verdict};

pub const TITLEBAR_H: f32 = 40.0;

/// A file name cut in the middle when long: "Smlouva o dílo pro… (signed 2).pdf".
fn short_name(name: &str, max: usize) -> String {
    let chars: Vec<char> = name.chars().collect();
    if chars.len() <= max {
        return name.to_string();
    }
    let tail = (max * 2 / 5).min(chars.len());
    let head = max.saturating_sub(tail + 1);
    let start: String = chars[..head].iter().collect();
    let end: String = chars[chars.len() - tail..].iter().collect();
    format!("{}…{}", start.trim_end(), end)
}

/// Settings key for a certificate: its SHA-256 fingerprint in hex.
fn cert_key(cert: &Certificate) -> String {
    cert.sha256_fingerprint().iter().map(|b| format!("{b:02x}")).collect()
}

/// The page a stamp goes on, if it is visible.
fn place_page(doc: &Loaded, place: &Placed) -> Option<usize> {
    match place {
        Placed::New { page, .. } => Some(*page),
        Placed::Field(name) => doc.report.fields.iter().find(|f| &f.name == name).and_then(|f| f.page),
        Placed::Invisible => None,
    }
}

/// Sort key: by page, then top to bottom.
fn place_order(doc: &Loaded, place: &Placed) -> (usize, i64) {
    let page = place_page(doc, place).unwrap_or(0);
    let top = match place {
        Placed::New { rect, .. } => rect[1],
        Placed::Field(name) => doc
            .report
            .fields
            .iter()
            .find(|f| &f.name == name)
            .and_then(|f| Some(doc.report.pages.get(f.page?)?.user_rect_to_view(f.rect?)[1]))
            .unwrap_or(0.0),
        Placed::Invisible => 0.0,
    };
    (page, top as i64)
}

/// Whether a certificate appears in the sign panel under these settings.
fn cert_visible_in(settings: &Settings, id: &Identity) -> bool {
    settings.cert_visible.get(&cert_key(&id.cert)).copied().unwrap_or_else(|| id.cert.fits_document_signing())
}

fn logo_mode_of(settings: &Settings) -> LogoMode {
    if settings.logo_style == "header" {
        LogoMode::Header
    } else {
        LogoMode::Watermark(Watermark {
            opacity: settings.logo_opacity.clamp(0.05, 1.0),
            x: settings.watermark_x,
            y: settings.watermark_y,
            scale: settings.watermark_size,
        })
    }
}

/// The logo for a settings choice: "none", "rocksign" or a file path.
fn make_logo(choice: &str) -> Option<Arc<Logo>> {
    let logo = match choice {
        "none" | "" => None,
        "rocksign" => Logo::rocksign().ok(),
        path => std::fs::read(path).ok().and_then(|b| Logo::from_bytes(&b).ok()),
    };
    logo.map(Arc::new)
}

/// The logo as a GPUI image (BGRA).
fn logo_image(logo: &Logo) -> Arc<RenderImage> {
    let mut bgra = logo.rgba.clone();
    for px in bgra.chunks_exact_mut(4) {
        px.swap(0, 2);
    }
    let buffer = image::RgbaImage::from_raw(logo.width, logo.height, bgra).expect("logo buffer");
    let frames: SmallVec<[image::Frame; 1]> = SmallVec::from_elem(image::Frame::new(buffer), 1);
    Arc::new(RenderImage::new(frames))
}

#[derive(Clone, Copy, PartialEq)]
enum SettingsTab {
    General,
    Stamp,
    Certificates,
}

/// The welcome steps on first start.
#[derive(Clone, Copy, PartialEq)]
enum WelcomeStep {
    Certificates,
    FileName,
    Ready,
}

/// Settings being edited, applied on Save.
struct Draft {
    settings: Settings,
    tab: SettingsTab,
    /// Shown as the first-start welcome, at this step, instead of the Settings window.
    welcome: Option<WelcomeStep>,
    logo: Option<Arc<Logo>>,
    logo_image: Option<Arc<RenderImage>>,
}
const FILES_W: f32 = 250.0;
const SIDEBAR_W: f32 = 340.0;
/// Space around and between pages, in pixels.
const PAD: f32 = 28.0;
const GAP: f32 = 18.0;
const MIN_ZOOM: f32 = 0.3;
const MAX_ZOOM: f32 = 4.0;
/// Stamp size placed by a single click, in points.
const DEFAULT_STAMP: (f32, f32) = (190.0, 72.0);
/// Smallest stamp box a drag can make, in points.
const MIN_STAMP: (f32, f32) = (40.0, 12.0);
/// Arrow-key scroll step, in pixels.
const LINE_STEP: f32 = 60.0;
const SCROLLBAR: f32 = 12.0;

enum FileStatus {
    Loading,
    Failed(String),
    Ready(Box<Loaded>),
}

struct FileEntry {
    path: PathBuf,
    status: FileStatus,
    /// Identifies the latest load, so results of older loads are ignored.
    token: u64,
    /// Zoom and scroll position to return to.
    view: Option<(f32, Point<Pixels>)>,
    /// Keep zoom and position when this load finishes (after signing).
    keep_view: bool,
}

#[derive(Clone, PartialEq)]
enum Placed {
    /// A new stamp: page and rectangle in view points [left, top, right, bottom].
    New {
        page: usize,
        rect: [f32; 4],
    },
    /// An existing empty signature field.
    Field(String),
    Invisible,
}

struct SignMode {
    identity: Option<usize>,
    /// Where the stamps go: each one becomes its own signature, all saved in one copy.
    /// At most one new box per page; `Invisible` is always alone.
    places: Vec<Placed>,
    timestamp: bool,
    busy: bool,
}

struct Drag {
    page: usize,
    start: (f32, f32),
    current: (f32, f32),
}

#[derive(Clone, Copy, PartialEq)]
enum Axis {
    X,
    Y,
}

struct ScrollDrag {
    handle: ScrollHandle,
    axis: Axis,
    /// Mouse position along the axis when the drag started (window coordinates).
    start_mouse: f32,
    start_pos: f32,
    /// Content pixels per thumb pixel.
    ratio: f32,
    /// Furthest scroll position.
    max: f32,
}

/// Along an axis: (visible length, how much further the content goes, current position).
fn scroll_metrics(handle: &ScrollHandle, axis: Axis) -> (f32, f32, f32) {
    let (b, m, o) = (handle.bounds(), handle.max_offset(), handle.offset());
    match axis {
        Axis::Y => (b.size.height.into(), m.height.into(), -f32::from(o.y)),
        Axis::X => (b.size.width.into(), m.width.into(), -f32::from(o.x)),
    }
}

/// Scrollbar thumb length and how far it can travel.
fn thumb_geometry(view: f32, extra: f32) -> (f32, f32) {
    let thumb = (view * view / (view + extra)).clamp(28.0, view);
    (thumb, (view - thumb).max(1.0))
}

fn set_axis_offset(handle: &ScrollHandle, axis: Axis, v: f32) {
    let o = handle.offset();
    match axis {
        Axis::Y => handle.set_offset(point(o.x, px(-v))),
        Axis::X => handle.set_offset(point(px(-v), o.y)),
    }
}

struct Toast {
    id: u64,
    level: Level,
    text: String,
}

/// Where a page sits inside the scrolled content, in pixels.
#[derive(Clone, Copy)]
struct Slot {
    x: f32,
    y: f32,
    w: f32,
    h: f32,
}

pub struct RockSignView {
    focus: FocusHandle,
    files: Vec<FileEntry>,
    current: Option<usize>,
    doc: Option<Loaded>,
    next_token: u64,

    zoom: f32,
    fit_pending: bool,
    scroll: ScrollHandle,
    files_scroll: ScrollHandle,
    sidebar_scroll: ScrollHandle,
    settings_scroll: ScrollHandle,
    /// Scroll area sizes seen at the last render, to redraw scrollbars once layout settles.
    scroll_seen: [(f32, f32); 4],
    slots: Vec<Slot>,
    /// Size of the scrolled content, in pixels.
    content: (f32, f32),
    current_page: usize,
    scroll_drag: Option<ScrollDrag>,

    renderer: Worker,
    generation: u64,
    images: HashMap<usize, (u32, Arc<RenderImage>)>,
    requested: HashMap<usize, u32>,
    stale_images: Vec<Arc<RenderImage>>,
    /// The rocket shown at the top of the welcome steps, while they're open.
    welcome_art: Option<Arc<RenderImage>>,

    identities: Option<Result<Vec<Identity>, String>>,
    show_all_identities: bool,
    sign: Option<SignMode>,
    drag: Option<Drag>,
    toast: Option<Toast>,
    next_toast: u64,
    expanded: HashSet<usize>,
    hovered_sig: Option<usize>,
    anchors: Vec<Certificate>,

    settings: Settings,
    /// The Settings window, when open: edits are kept here until Save.
    draft: Option<Draft>,
    suffix_input: Entity<TextInput>,
    logo: Option<Arc<Logo>>,
    logo_image: Option<Arc<RenderImage>>,
    _subscriptions: Vec<Subscription>,
}

impl RockSignView {
    pub fn new(paths: Vec<PathBuf>, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let (tx, mut rx) = futures::channel::mpsc::unbounded::<Rendered>();
        cx.spawn(async move |this, cx| {
            while let Some(r) = rx.next().await {
                if this.update(cx, |this, cx| this.on_rendered(r, cx)).is_err() {
                    break;
                }
            }
        })
        .detach();
        cx.observe_window_appearance(window, |_, _, cx| cx.notify()).detach();

        // The demo uses default settings and never saves them.
        let settings = if crate::demo::active() { Settings { setup_done: true, ..Settings::default() } } else { Settings::load() };
        let suffix_input = cx.new(|cx| {
            let mut input = TextInput::new(settings::DEFAULT_SUFFIX, cx);
            input.set_text(&settings.file_suffix, cx);
            input
        });
        let subscription = cx.subscribe_in(&suffix_input, window, |this, input, ev: &InputEvent, window, cx| match ev {
            InputEvent::Changed => {
                let text = input.read(cx).text();
                if let Some(d) = &mut this.draft {
                    d.settings.file_suffix = text;
                }
                cx.notify();
            }
            InputEvent::Confirm if this.draft.as_ref().is_some_and(|d| d.welcome.is_some()) => this.welcome_next(window, cx),
            InputEvent::Confirm => this.save_settings_draft(window, cx),
            InputEvent::Cancel if this.draft.as_ref().is_some_and(|d| d.welcome.is_some()) => window.focus(&this.focus),
            InputEvent::Cancel => this.discard_settings(window, cx),
            _ => {}
        });

        let focus = cx.focus_handle();
        window.focus(&focus);
        let mut view = RockSignView {
            focus,
            files: Vec::new(),
            current: None,
            doc: None,
            next_token: 0,
            zoom: 1.0,
            fit_pending: true,
            scroll: ScrollHandle::new(),
            files_scroll: ScrollHandle::new(),
            sidebar_scroll: ScrollHandle::new(),
            settings_scroll: ScrollHandle::new(),
            scroll_seen: [(0.0, 0.0); 4],
            slots: Vec::new(),
            content: (0.0, 0.0),
            current_page: 0,
            scroll_drag: None,
            renderer: Worker::spawn(tx),
            generation: 0,
            images: HashMap::new(),
            requested: HashMap::new(),
            stale_images: Vec::new(),
            welcome_art: None,
            identities: None,
            show_all_identities: false,
            sign: None,
            drag: None,
            toast: None,
            next_toast: 0,
            expanded: HashSet::new(),
            hovered_sig: None,
            anchors: if crate::demo::active() { crate::demo::anchors() } else { trust::load_anchors() },
            settings,
            draft: None,
            suffix_input,
            logo: None,
            logo_image: None,
            _subscriptions: vec![subscription],
        };
        view.load_logo();
        view.load_identities(cx);
        view.open_paths(paths, cx);
        if !view.settings.setup_done {
            view.open_welcome(window, cx);
        }
        view
    }

    // --- files -----------------------------------------------------------------

    pub fn open_paths(&mut self, paths: Vec<PathBuf>, cx: &mut Context<Self>) {
        let mut first = None;
        let mut skipped = 0;
        for path in paths {
            if !path.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf")) {
                skipped += 1;
                continue;
            }
            let i = match self.files.iter().position(|f| f.path == path) {
                Some(i) => i,
                None => {
                    self.files.push(FileEntry { path, status: FileStatus::Loading, token: 0, view: None, keep_view: false });
                    self.files.len() - 1
                }
            };
            self.load_file(i, cx);
            first.get_or_insert(i);
        }
        if skipped > 0 {
            self.show_toast(Level::Warn, "Only PDF files can be opened.".into(), cx);
        }
        if let Some(i) = first {
            self.select_file(i, cx);
        }
        cx.notify();
    }

    fn load_file(&mut self, i: usize, cx: &mut Context<Self>) {
        self.next_token += 1;
        let token = self.next_token;
        let entry = &mut self.files[i];
        entry.token = token;
        entry.status = FileStatus::Loading;
        let path = entry.path.clone();
        let anchors = self.anchors.clone();
        cx.spawn(async move |this, cx| {
            let result = cx.background_executor().spawn(async move { jobs::load(&path, &anchors) }).await;
            this.update(cx, |this, cx| this.file_loaded(token, result, cx)).ok();
        })
        .detach();
    }

    fn file_loaded(&mut self, token: u64, result: anyhow::Result<Loaded>, cx: &mut Context<Self>) {
        let Some(i) = self.files.iter().position(|f| f.token == token) else { return };
        self.files[i].status = match result {
            Ok(loaded) => FileStatus::Ready(Box::new(loaded)),
            Err(e) => FileStatus::Failed(format!("{e:#}")),
        };
        if self.current == Some(i) {
            self.show_current();
            if self.doc.is_some() && crate::demo::take_scene() {
                self.start_signing(cx);
            }
        }
        cx.notify();
    }

    fn select_file(&mut self, i: usize, cx: &mut Context<Self>) {
        if i >= self.files.len() {
            return;
        }
        if self.current != Some(i) {
            if let (Some(c), Some(_)) = (self.current, &self.doc)
                && let Some(entry) = self.files.get_mut(c)
            {
                entry.view = Some((self.zoom, self.scroll.offset()));
            }
            self.current = Some(i);
            self.doc = None;
            self.show_current();
        }
        cx.notify();
    }

    fn show_current(&mut self) {
        let Some(entry) = self.current.and_then(|i| self.files.get_mut(i)) else {
            self.doc = None;
            return;
        };
        let FileStatus::Ready(loaded) = &entry.status else {
            self.doc = None;
            return;
        };
        let loaded = (**loaded).clone();
        let keep = std::mem::take(&mut entry.keep_view);
        let view = if keep { None } else { entry.view };
        self.set_doc(loaded, keep);
        if let Some((zoom, offset)) = view {
            self.zoom = zoom;
            self.fit_pending = false;
            self.scroll.set_offset(offset);
        }
    }

    fn set_doc(&mut self, loaded: Loaded, keep_view: bool) {
        self.generation += 1;
        self.renderer.send(Request::Open { generation: self.generation, bytes: loaded.bytes.clone() });
        self.stale_images.extend(self.images.drain().map(|(_, (_, img))| img));
        self.requested.clear();
        self.expanded.clear();
        self.hovered_sig = None;
        self.drag = None;
        self.sign = None;
        if !keep_view {
            self.fit_pending = true;
            self.scroll.set_offset(point(px(0.0), px(0.0)));
        }
        self.doc = Some(loaded);
    }

    fn remove_file(&mut self, i: usize, cx: &mut Context<Self>) {
        self.remove_files(vec![i], cx);
    }

    /// Takes files off the list (they stay on disk). If the open one goes, the next file
    /// in the list opens instead.
    fn remove_files(&mut self, mut which: Vec<usize>, cx: &mut Context<Self>) {
        which.retain(|&i| i < self.files.len());
        which.sort_unstable();
        which.dedup();
        if which.is_empty() {
            return;
        }
        let mut removed_current = None;
        for &i in which.iter().rev() {
            self.files.remove(i);
            match self.current {
                Some(c) if c == i => {
                    self.current = None;
                    removed_current = Some(i);
                }
                Some(c) if c > i => self.current = Some(c - 1),
                _ => {}
            }
        }
        if let Some(at) = removed_current {
            self.doc = None;
            if self.files.is_empty() {
                self.generation += 1;
                self.stale_images.extend(self.images.drain().map(|(_, (_, img))| img));
                self.requested.clear();
                if self.sign.as_ref().is_some_and(|m| !m.busy) {
                    self.sign = None;
                }
            } else {
                let before = which.iter().filter(|&&j| j < at).count();
                self.select_file((at - before).min(self.files.len() - 1), cx);
            }
        }
        cx.notify();
    }

    /// Files that carry a valid signature of yours.
    fn signed_files(&self) -> Vec<usize> {
        (0..self.files.len()).filter(|&i| matches!(&self.files[i].status, FileStatus::Ready(l) if self.signed_by_me(l))).collect()
    }

    fn clear_signed(&mut self, cx: &mut Context<Self>) {
        let which = self.signed_files();
        if which.is_empty() {
            self.show_toast(Level::Warn, "None of the documents carry your signature yet.".into(), cx);
            return;
        }
        self.remove_files(which, cx);
    }

    fn clear_all(&mut self, cx: &mut Context<Self>) {
        self.remove_files((0..self.files.len()).collect(), cx);
    }

    /// Whether this file holds a valid signature made with one of your certificates.
    fn signed_by_me(&self, loaded: &Loaded) -> bool {
        let Some(Ok(ids)) = &self.identities else { return false };
        loaded.report.signatures.iter().any(|s| s.is_intact() && s.signer.as_ref().is_some_and(|c| ids.iter().any(|i| i.cert.der == c.der)))
    }

    fn prompt_open(&mut self, cx: &mut Context<Self>) {
        let rx = cx.prompt_for_paths(PathPromptOptions { files: true, directories: false, multiple: true, prompt: Some("Open".into()) });
        cx.spawn(async move |this, cx| {
            if let Ok(Ok(Some(paths))) = rx.await {
                this.update(cx, |this, cx| this.open_paths(paths, cx)).ok();
            }
        })
        .detach();
    }

    fn on_rendered(&mut self, r: Rendered, cx: &mut Context<Self>) {
        match r.image {
            Ok(image) if r.generation == self.generation => {
                if let Some((_, old)) = self.images.insert(r.page, (r.width, image)) {
                    self.stale_images.push(old);
                }
                if self.requested.get(&r.page) == Some(&r.width) {
                    self.requested.remove(&r.page);
                }
                cx.notify();
            }
            Ok(image) => self.stale_images.push(image),
            Err(e) => {
                self.requested.remove(&r.page);
                eprintln!("rocksign: page {} did not render: {e}", r.page + 1);
            }
        }
    }

    fn show_toast(&mut self, level: Level, text: String, cx: &mut Context<Self>) {
        self.next_toast += 1;
        let id = self.next_toast;
        self.toast = Some(Toast { id, level, text });
        let secs = if level == Level::Bad { 12 } else { 7 };
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(Duration::from_secs(secs)).await;
            this.update(cx, |this, cx| {
                if this.toast.as_ref().is_some_and(|t| t.id == id) {
                    this.toast = None;
                    cx.notify();
                }
            })
            .ok();
        })
        .detach();
        cx.notify();
    }

    // --- settings and logo -------------------------------------------------------

    fn save_settings(&mut self, cx: &mut Context<Self>) {
        if crate::demo::active() {
            return;
        }
        if let Err(e) = self.settings.save() {
            self.show_toast(Level::Bad, format!("Could not save settings: {e:#}"), cx);
        }
        cx.notify();
    }

    fn load_logo(&mut self) {
        let logo = make_logo(&self.settings.logo);
        if let Some(old) = self.logo_image.take() {
            self.stale_images.push(old);
        }
        self.logo_image = logo.as_deref().map(logo_image);
        self.logo = logo;
    }

    fn logo_mode(&self) -> LogoMode {
        logo_mode_of(&self.settings)
    }

    // --- signing ---------------------------------------------------------------

    fn load_identities(&mut self, cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            let result = cx
                .background_executor()
                .spawn(async move { if crate::demo::active() { crate::demo::identities() } else { keychain::identities() } })
                .await;
            this.update(cx, |this, cx| {
                this.identities = Some(result.map_err(|e| format!("{e:#}")));
                let default = this.default_identity();
                if let Some(mode) = this.sign.as_mut()
                    && mode.identity.is_none()
                {
                    mode.identity = default;
                }
                cx.notify();
            })
            .ok();
        })
        .detach();
    }

    fn start_signing(&mut self, cx: &mut Context<Self>) {
        let Some(doc) = &self.doc else {
            if self.files.is_empty() {
                self.prompt_open(cx);
            }
            return;
        };
        if self.sign.is_some() {
            return;
        }
        let only_field = {
            let empty: Vec<_> = doc.report.empty_fields().collect();
            (empty.len() == 1).then(|| Placed::Field(empty[0].name.clone()))
        };
        let identity = self.default_identity();
        self.sign = Some(SignMode { identity, places: only_field.into_iter().collect(), timestamp: self.settings.timestamp, busy: false });
        if matches!(self.identities, Some(Err(_))) {
            self.identities = None;
            self.load_identities(cx);
        }
        cx.notify();
    }

    /// Whether a certificate appears in the sign panel.
    fn cert_visible(&self, id: &Identity) -> bool {
        cert_visible_in(&self.settings, id)
    }

    /// The certificate to preselect: the chosen default if it is shown and valid, else the
    /// first shown, valid one (the list is sorted longest-valid first).
    fn default_identity(&self) -> Option<usize> {
        let Some(Ok(list)) = &self.identities else { return None };
        let ok = |id: &Identity| id.is_usable() && self.cert_visible(id);
        self.settings
            .default_cert
            .as_ref()
            .and_then(|key| list.iter().position(|id| &cert_key(&id.cert) == key && ok(id)))
            .or_else(|| list.iter().position(ok))
    }

    /// After the certificate settings change, select the default in an open sign panel.
    fn reselect_identity(&mut self) {
        let default = self.default_identity();
        if let Some(mode) = self.sign.as_mut().filter(|m| !m.busy) {
            mode.identity = default;
        }
    }

    fn can_sign(&self) -> bool {
        let Some(mode) = &self.sign else { return false };
        !mode.busy && mode.identity.is_some() && !mode.places.is_empty() && self.doc.as_ref().is_some_and(|d| d.report.signing_blocker.is_none())
    }

    fn sign_and_save(&mut self, cx: &mut Context<Self>) {
        if !self.can_sign() {
            return;
        }
        let logo_mode = self.logo_mode();
        let (Some(doc), Some(mode), Some(Ok(identities))) = (&self.doc, &mut self.sign, &self.identities) else { return };
        let Some(idx) = mode.identity else { return };
        let identity = identities[idx].clone();
        let mut places = mode.places.clone();
        places.sort_by_key(|p| place_order(doc, p));
        let targets: Vec<Target> = places
            .iter()
            .map(|p| match p {
                Placed::New { page, rect } => Target::NewField { page: *page, rect: doc.report.pages[*page].view_rect_to_user(*rect) },
                Placed::Field(name) => Target::Field { name: name.clone() },
                Placed::Invisible => Target::Invisible,
            })
            .collect();
        let boxes = doc.report.fields.len();
        let total = (doc.report.empty_fields().next().is_some() && places.iter().any(|p| matches!(p, Placed::Field(_)))).then_some(boxes);
        // People, not signatures: several stamps by one person count once.
        let mut signers: HashSet<String> = doc.report.signatures.iter().filter_map(|s| s.signer.as_ref()).map(cert_key).collect();
        signers.insert(cert_key(&identity.cert));
        let vars =
            NameVars { n: signers.len(), total, name: &identity.cert.display_name(), date: chrono::Local::now().format("%Y-%m-%d").to_string() };
        let suggested = settings::suggested_name(&doc.path, &self.settings.file_suffix, &vars);
        let dir = doc.path.parent().map(|p| p.to_path_buf()).unwrap_or_else(|| PathBuf::from("."));
        let source = doc.path.clone();
        let input = doc.bytes.clone();
        let timestamp = mode.timestamp;
        let logo = self.logo.clone();
        mode.busy = true;
        let rx = cx.prompt_for_new_path(&dir, Some(&suggested));
        cx.spawn(async move |this, cx| {
            let path = match rx.await {
                Ok(Ok(Some(p))) => p,
                _ => {
                    this.update(cx, |this, cx| {
                        if let Some(m) = &mut this.sign {
                            m.busy = false;
                        }
                        cx.notify();
                    })
                    .ok();
                    return;
                }
            };
            let output = if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("pdf")) { path } else { path.with_extension("pdf") };
            let job =
                SignJob { input, output, identity: identity.identity.clone(), cert: identity.cert.clone(), targets, timestamp, logo, logo_mode };
            let result = cx.background_executor().spawn(async move { jobs::sign(job) }).await;
            this.update(cx, |this, cx| this.signed(source, result, cx)).ok();
        })
        .detach();
        cx.notify();
    }

    fn signed(&mut self, source: PathBuf, result: anyhow::Result<PathBuf>, cx: &mut Context<Self>) {
        let path = match result {
            Ok(p) => p,
            Err(e) => {
                if let Some(m) = &mut self.sign {
                    m.busy = false;
                }
                self.show_toast(Level::Bad, format!("{e:#}"), cx);
                return;
            }
        };
        self.sign = None;
        let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        // The list entry now points at the signed copy.
        let mut i = match self.files.iter().position(|f| f.path == source) {
            Some(i) => {
                self.files[i].path = path.clone();
                i
            }
            None => {
                self.files.push(FileEntry { path: path.clone(), status: FileStatus::Loading, token: 0, view: None, keep_view: false });
                self.files.len() - 1
            }
        };
        // Saved over another open file: drop that entry.
        if let Some(dup) = (0..self.files.len()).find(|&j| j != i && self.files[j].path == path) {
            self.files.remove(dup);
            if dup < i {
                i -= 1;
            }
            self.current = match self.current {
                Some(c) if c == dup => Some(i),
                Some(c) if c > dup => Some(c - 1),
                other => other,
            };
        }
        self.files[i].keep_view = self.current == Some(i);
        self.load_file(i, cx);
        let remaining =
            self.files.iter().enumerate().filter(|(j, f)| *j != i && matches!(&f.status, FileStatus::Ready(l) if !self.signed_by_me(l))).count();
        let next = match remaining {
            0 => "Send it to the next person.".to_string(),
            1 => "1 more file is waiting for your signature.".to_string(),
            n => format!("{n} more files are waiting for your signature."),
        };
        self.show_toast(Level::Ok, format!("Signed and saved as “{}”. {next}", short_name(&name, 52)), cx);
    }

    fn trust_issuer(&mut self, cert: Certificate, cx: &mut Context<Self>) {
        if let Err(e) = trust::add_anchor(&cert) {
            self.show_toast(Level::Bad, format!("Could not save: {e:#}"), cx);
            return;
        }
        self.anchors = trust::load_anchors();
        if let Some(doc) = &mut self.doc {
            doc.trust = jobs::check_trust(&doc.report, &self.anchors);
        }
        for f in &mut self.files {
            if let FileStatus::Ready(l) = &mut f.status {
                l.trust = jobs::check_trust(&l.report, &self.anchors);
            }
        }
        self.show_toast(Level::Ok, format!("RockSign now trusts certificates issued by “{}”.", cert.display_name()), cx);
    }

    // --- scrolling and pages -----------------------------------------------------

    fn viewport(&self) -> (f32, f32) {
        let b = self.scroll.bounds();
        (b.size.width.into(), b.size.height.into())
    }

    fn scroll_pos(&self) -> (f32, f32) {
        let o = self.scroll.offset();
        (-f32::from(o.x), -f32::from(o.y))
    }

    fn set_scroll(&mut self, x: f32, y: f32, cx: &mut Context<Self>) {
        let (vw, vh) = self.viewport();
        let x = x.clamp(0.0, (self.content.0 - vw).max(0.0));
        let y = y.clamp(0.0, (self.content.1 - vh).max(0.0));
        self.scroll.set_offset(point(px(-x), px(-y)));
        cx.notify();
    }

    fn scroll_by(&mut self, dy: f32, cx: &mut Context<Self>) {
        let (x, y) = self.scroll_pos();
        self.set_scroll(x, y + dy, cx);
    }

    fn go_to_page(&mut self, page: usize, cx: &mut Context<Self>) {
        if let Some(s) = self.slots.get(page).copied() {
            let (x, _) = self.scroll_pos();
            self.set_scroll(x, s.y - PAD / 2.0, cx);
        }
    }

    fn set_zoom(&mut self, zoom: f32, cx: &mut Context<Self>) {
        let zoom = zoom.clamp(MIN_ZOOM, MAX_ZOOM);
        let ratio = zoom / self.zoom;
        let off = self.scroll.offset();
        self.zoom = zoom;
        self.fit_pending = false;
        self.scroll.set_offset(point(off.x * ratio, off.y * ratio));
        cx.notify();
    }

    /// Mouse down on a scrollbar: grab the thumb, or jump to the clicked spot and grab it.
    fn start_scroll_drag(&mut self, handle: ScrollHandle, axis: Axis, pos: Point<Pixels>, cx: &mut Context<Self>) {
        let (view, extra, at) = scroll_metrics(&handle, axis);
        if extra <= 0.5 || view <= 0.0 {
            return;
        }
        let (thumb, travel) = thumb_geometry(view, extra);
        let ratio = extra / travel;
        let b = handle.bounds();
        let (mouse, local) = match axis {
            Axis::Y => (f32::from(pos.y), f32::from(pos.y - b.origin.y)),
            Axis::X => (f32::from(pos.x), f32::from(pos.x - b.origin.x)),
        };
        let thumb_start = at / ratio;
        let mut start_pos = at;
        if local < thumb_start || local > thumb_start + thumb {
            start_pos = ((local - thumb / 2.0) * ratio).clamp(0.0, extra);
            set_axis_offset(&handle, axis, start_pos);
        }
        self.scroll_drag = Some(ScrollDrag { handle, axis, start_mouse: mouse, start_pos, ratio, max: extra });
        cx.notify();
    }

    fn drag_scroll(&mut self, pos: Point<Pixels>, cx: &mut Context<Self>) {
        let Some(d) = &self.scroll_drag else { return };
        let mouse = match d.axis {
            Axis::Y => f32::from(pos.y),
            Axis::X => f32::from(pos.x),
        };
        let v = (d.start_pos + (mouse - d.start_mouse) * d.ratio).clamp(0.0, d.max);
        set_axis_offset(&d.handle, d.axis, v);
        cx.notify();
    }

    // --- actions ---------------------------------------------------------------

    fn on_open(&mut self, _: &OpenFile, _: &mut Window, cx: &mut Context<Self>) {
        self.prompt_open(cx);
    }

    fn on_start_signing(&mut self, _: &StartSigning, _: &mut Window, cx: &mut Context<Self>) {
        if self.sign.is_some() {
            self.sign_and_save(cx);
        } else {
            self.start_signing(cx);
        }
    }

    fn on_zoom_in(&mut self, _: &ZoomIn, _: &mut Window, cx: &mut Context<Self>) {
        self.set_zoom(self.zoom * 1.2, cx);
    }

    fn on_zoom_out(&mut self, _: &ZoomOut, _: &mut Window, cx: &mut Context<Self>) {
        self.set_zoom(self.zoom / 1.2, cx);
    }

    fn on_zoom_fit(&mut self, _: &ZoomFit, _: &mut Window, cx: &mut Context<Self>) {
        self.fit_pending = true;
        cx.notify();
    }

    fn on_page_down(&mut self, _: &PageDown, _: &mut Window, cx: &mut Context<Self>) {
        self.scroll_by(self.viewport().1 * 0.9, cx);
    }

    fn on_page_up(&mut self, _: &PageUp, _: &mut Window, cx: &mut Context<Self>) {
        self.scroll_by(-self.viewport().1 * 0.9, cx);
    }

    fn on_line_down(&mut self, _: &LineDown, _: &mut Window, cx: &mut Context<Self>) {
        self.scroll_by(LINE_STEP, cx);
    }

    fn on_line_up(&mut self, _: &LineUp, _: &mut Window, cx: &mut Context<Self>) {
        self.scroll_by(-LINE_STEP, cx);
    }

    fn on_first_page(&mut self, _: &FirstPage, _: &mut Window, cx: &mut Context<Self>) {
        let (x, _) = self.scroll_pos();
        self.set_scroll(x, 0.0, cx);
    }

    fn on_last_page(&mut self, _: &LastPage, _: &mut Window, cx: &mut Context<Self>) {
        let (x, _) = self.scroll_pos();
        self.set_scroll(x, f32::MAX, cx);
    }

    fn on_next_page(&mut self, _: &NextPage, _: &mut Window, cx: &mut Context<Self>) {
        self.go_to_page((self.current_page + 1).min(self.slots.len().saturating_sub(1)), cx);
    }

    fn on_prev_page(&mut self, _: &PrevPage, _: &mut Window, cx: &mut Context<Self>) {
        // From the middle of a page, go to its top first.
        let top = self.slots.get(self.current_page).map(|s| s.y - PAD / 2.0).unwrap_or(0.0);
        if self.scroll_pos().1 > top + 4.0 {
            self.go_to_page(self.current_page, cx);
        } else {
            self.go_to_page(self.current_page.saturating_sub(1), cx);
        }
    }

    fn on_next_file(&mut self, _: &NextFile, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(c) = self.current {
            self.select_file((c + 1).min(self.files.len().saturating_sub(1)), cx);
        }
    }

    fn on_prev_file(&mut self, _: &PrevFile, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(c) = self.current {
            self.select_file(c.saturating_sub(1), cx);
        }
    }

    fn on_show_welcome(&mut self, _: &ShowWelcome, window: &mut Window, cx: &mut Context<Self>) {
        self.open_welcome(window, cx);
    }

    fn on_toggle_settings(&mut self, _: &ToggleSettings, window: &mut Window, cx: &mut Context<Self>) {
        if self.draft.as_ref().is_some_and(|d| d.welcome.is_some()) {
            return;
        }
        if self.draft.is_some() {
            self.discard_settings(window, cx);
        } else {
            self.open_settings(window, cx);
        }
    }

    fn on_escape(&mut self, _: &Escape, window: &mut Window, cx: &mut Context<Self>) {
        if self.draft.as_ref().is_some_and(|d| d.welcome.is_some()) {
            self.skip_welcome(window, cx);
        } else if self.draft.is_some() {
            self.discard_settings(window, cx);
        } else if self.drag.take().is_some() {
        } else if self.sign.as_ref().is_some_and(|m| !m.busy) {
            self.sign = None;
        } else {
            self.toast = None;
        }
        cx.notify();
    }

    fn on_remove_file(&mut self, _: &RemoveFile, _: &mut Window, cx: &mut Context<Self>) {
        if let Some(i) = self.current {
            self.remove_file(i, cx);
        }
    }

    fn on_clear_signed(&mut self, _: &ClearSignedFiles, _: &mut Window, cx: &mut Context<Self>) {
        self.clear_signed(cx);
    }

    fn on_clear_all(&mut self, _: &ClearAllFiles, _: &mut Window, cx: &mut Context<Self>) {
        self.clear_all(cx);
    }

    fn on_close_window(&mut self, _: &CloseWindow, window: &mut Window, _: &mut Context<Self>) {
        window.remove_window();
    }

    // --- page geometry and placing the stamp ------------------------------------

    fn compute_slots(&mut self, viewport_w: f32) -> f32 {
        self.slots.clear();
        let Some(doc) = &self.doc else {
            self.content = (0.0, 0.0);
            return viewport_w;
        };
        let sizes: Vec<(f32, f32)> = doc.report.pages.iter().map(|p| p.view_size()).map(|(w, h)| (w * self.zoom, h * self.zoom)).collect();
        let max_w = sizes.iter().map(|s| s.0).fold(0.0, f32::max);
        let content_w = viewport_w.max(max_w + 2.0 * PAD);
        let mut y = PAD;
        for (w, h) in sizes {
            self.slots.push(Slot { x: (content_w - w) / 2.0, y, w, h });
            y += h + GAP;
        }
        self.content = (content_w, y - GAP + PAD);
        content_w
    }

    fn fit_zoom(&self, viewport_w: f32) -> f32 {
        let max_w = self.doc.as_ref().map(|d| d.report.pages.iter().map(|p| p.view_size().0).fold(0.0, f32::max)).unwrap_or(600.0).max(1.0);
        ((viewport_w - 2.0 * PAD) / max_w).clamp(0.5, 1.6)
    }

    /// Page and point (in page points, view orientation) under a window position.
    fn hit(&self, pos: Point<Pixels>) -> Option<(usize, f32, f32)> {
        let b = self.scroll.bounds();
        let off = self.scroll.offset();
        let x: f32 = (pos.x - b.origin.x - off.x).into();
        let y: f32 = (pos.y - b.origin.y - off.y).into();
        self.slots
            .iter()
            .position(|s| x >= s.x && x <= s.x + s.w && y >= s.y && y <= s.y + s.h)
            .map(|i| (i, (x - self.slots[i].x) / self.zoom, (y - self.slots[i].y) / self.zoom))
    }

    /// Position on a given page, clamped to it.
    fn point_on_page(&self, page: usize, pos: Point<Pixels>) -> Option<(f32, f32)> {
        let s = self.slots.get(page)?;
        let b = self.scroll.bounds();
        let off = self.scroll.offset();
        let x: f32 = (pos.x - b.origin.x - off.x).into();
        let y: f32 = (pos.y - b.origin.y - off.y).into();
        Some(((x - s.x).clamp(0.0, s.w) / self.zoom, (y - s.y).clamp(0.0, s.h) / self.zoom))
    }

    fn empty_field_at(&self, page: usize, u: f32, v: f32) -> Option<String> {
        let doc = self.doc.as_ref()?;
        let geom = doc.report.pages.get(page)?;
        doc.report.empty_fields().find_map(|f| {
            let r = geom.user_rect_to_view(f.rect?);
            (f.page == Some(page) && f.visible && u >= r[0] && u <= r[2] && v >= r[1] && v <= r[3]).then(|| f.name.clone())
        })
    }

    fn viewer_mouse_down(&mut self, ev: &MouseDownEvent, window: &mut Window, cx: &mut Context<Self>) {
        window.focus(&self.focus);
        if self.sign.as_ref().is_none_or(|m| m.busy) {
            return;
        }
        let Some((page, u, v)) = self.hit(ev.position) else { return };
        if let Some(name) = self.empty_field_at(page, u, v) {
            if let Some(m) = &mut self.sign {
                m.places.retain(|p| *p != Placed::Invisible);
                let field = Placed::Field(name);
                if let Some(at) = m.places.iter().position(|p| *p == field) {
                    m.places.remove(at);
                } else {
                    m.places.push(field);
                }
            }
            cx.notify();
            return;
        }
        self.drag = Some(Drag { page, start: (u, v), current: (u, v) });
        cx.notify();
    }

    fn root_mouse_move(&mut self, ev: &MouseMoveEvent, _: &mut Window, cx: &mut Context<Self>) {
        if self.scroll_drag.is_some() {
            self.drag_scroll(ev.position, cx);
            return;
        }
        let Some(page) = self.drag.as_ref().map(|d| d.page) else { return };
        if let Some(p) = self.point_on_page(page, ev.position) {
            if let Some(d) = &mut self.drag {
                d.current = p;
            }
            cx.notify();
        }
    }

    fn finish_drag(&mut self, cx: &mut Context<Self>) {
        if self.scroll_drag.take().is_some() {
            cx.notify();
        }
        let Some(d) = self.drag.take() else { return };
        let Some(doc) = &self.doc else { return };
        let (pw, ph) = doc.report.pages[d.page].view_size();
        let (l, r) = (d.start.0.min(d.current.0), d.start.0.max(d.current.0));
        let (t, b) = (d.start.1.min(d.current.1), d.start.1.max(d.current.1));
        let rect = if (r - l).max(b - t) < 8.0 {
            // A click: standard size, centered on the click.
            let (dw, dh) = (DEFAULT_STAMP.0.min(pw), DEFAULT_STAMP.1.min(ph));
            let l = (d.start.0 - dw / 2.0).clamp(0.0, pw - dw);
            let t = (d.start.1 - dh / 2.0).clamp(0.0, ph - dh);
            [l, t, l + dw, t + dh]
        } else {
            // Keep the dragged shape; the stamp adapts to it.
            let (w, h) = ((r - l).max(MIN_STAMP.0).min(pw), (b - t).max(MIN_STAMP.1).min(ph));
            let (l, t) = (l.min(pw - w).max(0.0), t.min(ph - h).max(0.0));
            [l, t, l + w, t + h]
        };
        if let Some(m) = &mut self.sign {
            // One new box per page: dragging again on a page moves its box.
            m.places.retain(|p| *p != Placed::Invisible && !matches!(p, Placed::New { page, .. } if *page == d.page));
            m.places.push(Placed::New { page: d.page, rect });
        }
        cx.notify();
    }

    fn remove_place(&mut self, place: &Placed, cx: &mut Context<Self>) {
        if let Some(m) = self.sign.as_mut().filter(|m| !m.busy) {
            m.places.retain(|p| p != place);
        }
        cx.notify();
    }

    fn verdict_level(&self, loaded: &Loaded) -> Option<Level> {
        loaded.report.signatures.iter().enumerate().map(|(i, s)| verdict(s, loaded.trust.get(i)).level).max_by_key(|l| match l {
            Level::Ok => 0,
            Level::Warn => 1,
            Level::Bad => 2,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::short_name;

    #[test]
    fn long_names_are_cut_in_the_middle() {
        assert_eq!(short_name("Contract.pdf", 52), "Contract.pdf");
        let long = "Smlouva o dílo mezi objednatelem a zhotovitelem s velmi dlouhým názvem (signed 2).pdf";
        let short = short_name(long, 52);
        assert_eq!(short.chars().count(), 52);
        assert!(short.starts_with("Smlouva o dílo") && short.ends_with("(signed 2).pdf"), "{short}");
    }
}
