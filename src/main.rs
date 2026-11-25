mod actions;
mod jobs;
mod keychain;
mod render;
mod settings;
mod text_input;
mod theme;
mod trust;
mod ui;

use std::path::PathBuf;

use gpui::{App, AppContext as _, Application, Bounds, KeyBinding, Menu, MenuItem, TitlebarOptions, WindowBounds, WindowOptions, px, size};

use crate::actions::*;
use crate::ui::RockSignView;

/// Traffic lights (14px tall) vertically centered in the title bar.
const TRAFFIC_LIGHTS: gpui::Point<gpui::Pixels> = gpui::Point { x: px(16.0), y: px(13.0) };

fn open_window(paths: Vec<PathBuf>, cx: &mut App) {
    let bounds = Bounds::centered(None, size(px(1240.0), px(860.0)), cx);
    let result = cx.open_window(
        WindowOptions {
            window_bounds: Some(WindowBounds::Windowed(bounds)),
            titlebar: Some(TitlebarOptions {
                title: Some("RockSign".into()),
                appears_transparent: true,
                traffic_light_position: Some(TRAFFIC_LIGHTS),
            }),
            window_min_size: Some(size(px(760.0), px(480.0))),
            ..Default::default()
        },
        |window, cx| cx.new(|cx| RockSignView::new(paths, window, cx)),
    );
    if let Err(err) = result {
        eprintln!("rocksign: could not open window: {err:#}");
    }
}

fn bind_keys(cx: &mut App) {
    text_input::bind_keys(cx);
    // Plain keys scroll the pages, except while typing in a text field.
    let nav = Some("RockSign && !TextInput");
    cx.bind_keys([
        KeyBinding::new("pagedown", PageDown, nav),
        KeyBinding::new("space", PageDown, nav),
        KeyBinding::new("pageup", PageUp, nav),
        KeyBinding::new("shift-space", PageUp, nav),
        KeyBinding::new("down", LineDown, nav),
        KeyBinding::new("up", LineUp, nav),
        KeyBinding::new("home", FirstPage, nav),
        KeyBinding::new("end", LastPage, nav),
        KeyBinding::new("right", NextPage, nav),
        KeyBinding::new("left", PrevPage, nav),
        KeyBinding::new("escape", Escape, nav),
        KeyBinding::new("cmd-backspace", RemoveFile, nav),
    ]);
    let ctx = Some("RockSign");
    cx.bind_keys([
        KeyBinding::new("cmd-up", FirstPage, ctx),
        KeyBinding::new("cmd-down", LastPage, ctx),
        KeyBinding::new("cmd-]", NextFile, ctx),
        KeyBinding::new("cmd-[", PrevFile, ctx),
        KeyBinding::new("alt-down", NextFile, ctx),
        KeyBinding::new("alt-up", PrevFile, ctx),
        KeyBinding::new("cmd-,", ToggleSettings, ctx),
        KeyBinding::new("cmd-o", OpenFile, ctx),
        KeyBinding::new("cmd-s", StartSigning, ctx),
        KeyBinding::new("cmd-=", ZoomIn, ctx),
        KeyBinding::new("cmd-+", ZoomIn, ctx),
        KeyBinding::new("cmd--", ZoomOut, ctx),
        KeyBinding::new("cmd-0", ZoomFit, ctx),
        KeyBinding::new("cmd-w", CloseWindow, ctx),
        KeyBinding::new("cmd-q", Quit, None),
    ]);
}

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    // Debug helper: render a page with the app's renderer to a PNG.
    if args.get(1).map(String::as_str) == Some("--render") {
        let bytes = std::fs::read(&args[2])?;
        let page: usize = args.get(4).map(|p| p.parse()).transpose()?.unwrap_or(1);
        let width: u32 = args.get(5).map(|p| p.parse()).transpose()?.unwrap_or(1200);
        let doc = render::PdfKitDocument::open(&bytes)?;
        eprintln!("{} pages", doc.page_count());
        doc.render(page - 1, width)?.save_png(std::path::Path::new(&args[3]))?;
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("--list-certs") {
        for id in keychain::identities()? {
            let c = &id.cert;
            let usable = if id.is_usable() {
                "usable"
            } else if c.fits_document_signing() {
                "expired"
            } else {
                "not for signing"
            };
            let trusted = trust::evaluate(c, &[], None, &trust::load_anchors());
            println!(
                "{} — issued by {} — until {} — {} — key usage {:?} — [{usable}] trusted by macOS: {}",
                c.display_name(),
                c.issuer.display_name(),
                c.not_after.format("%Y-%m-%d"),
                c.key_description(),
                c.key_usage.map(|k| format!("{k:04x}")),
                if trusted.trusted { "yes".to_string() } else { trusted.problem.unwrap_or_default() }
            );
        }
        return Ok(());
    }
    if args.get(1).map(String::as_str) == Some("--check") {
        let loaded = jobs::load(std::path::Path::new(&args[2]), &trust::load_anchors())?;
        for (s, t) in loaded.report.signatures.iter().zip(&loaded.trust) {
            println!(
                "{}: intact={} trusted={} later={:?} {}",
                s.signer_name(),
                s.is_intact(),
                t.trusted,
                s.later.level,
                t.problem.clone().unwrap_or_default()
            );
        }
        return Ok(());
    }
    let initial: Vec<PathBuf> = args.iter().skip(1).map(PathBuf::from).filter(|p| p.exists()).collect();

    let app = Application::new();
    // Files opened from Finder ("Open With", double-click, drop on the Dock icon) arrive as
    // file:// URLs, also while the app is still starting.
    let (open_tx, mut open_rx) = futures::channel::mpsc::unbounded::<Vec<PathBuf>>();
    app.on_open_urls(move |urls| {
        let paths: Vec<PathBuf> = urls.iter().filter_map(|u| file_url_to_path(u)).collect();
        if !paths.is_empty() {
            open_tx.unbounded_send(paths).ok();
        }
    });
    app.on_reopen(|cx| {
        if cx.windows().is_empty() {
            open_window(Vec::new(), cx);
        }
    });
    app.run(move |cx: &mut App| {
        bind_keys(cx);
        cx.on_action(|_: &Quit, cx| cx.quit());
        cx.set_menus(vec![
            Menu {
                name: "RockSign".into(),
                items: vec![
                    MenuItem::action("Settings…", ToggleSettings),
                    MenuItem::action("Set Up RockSign…", ShowWelcome),
                    MenuItem::separator(),
                    MenuItem::action("Quit RockSign", Quit),
                ],
            },
            Menu {
                name: "File".into(),
                items: vec![
                    MenuItem::action("Open…", OpenFile),
                    MenuItem::action("Sign…", StartSigning),
                    MenuItem::separator(),
                    MenuItem::action("Remove Document from List", RemoveFile),
                    MenuItem::action("Clear Signed Documents", ClearSignedFiles),
                    MenuItem::action("Clear All Documents", ClearAllFiles),
                    MenuItem::separator(),
                    MenuItem::action("Close Window", CloseWindow),
                ],
            },
            Menu {
                name: "View".into(),
                items: vec![
                    MenuItem::action("Zoom In", ZoomIn),
                    MenuItem::action("Zoom Out", ZoomOut),
                    MenuItem::action("Fit Width", ZoomFit),
                    MenuItem::separator(),
                    MenuItem::action("Next Page", NextPage),
                    MenuItem::action("Previous Page", PrevPage),
                    MenuItem::action("Next Document", NextFile),
                    MenuItem::action("Previous Document", PrevFile),
                ],
            },
        ]);
        cx.activate(true);
        open_window(initial.clone(), cx);
        cx.spawn(async move |cx| {
            use futures::StreamExt as _;
            while let Some(paths) = open_rx.next().await {
                cx.update(|cx| open_in_window(paths, cx)).ok();
            }
        })
        .detach();
    });
    Ok(())
}

/// Open files in the existing window, or in a new one if it was closed.
fn open_in_window(paths: Vec<PathBuf>, cx: &mut App) {
    cx.activate(true);
    let window = cx.windows().into_iter().find_map(|w| w.downcast::<RockSignView>());
    let opened = window.is_some_and(|w| {
        w.update(cx, |view, window, cx| {
            window.activate_window();
            view.open_paths(paths.clone(), cx);
        })
        .is_ok()
    });
    if !opened {
        open_window(paths, cx);
    }
}

/// `file:///Users/me/My%20File.pdf` → `/Users/me/My File.pdf`.
fn file_url_to_path(url: &str) -> Option<PathBuf> {
    use std::os::unix::ffi::OsStrExt as _;
    let rest = url.strip_prefix("file://")?;
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    if !rest.starts_with('/') {
        return None;
    }
    let raw = rest.as_bytes();
    let mut bytes = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        let hex = |b: u8| (b as char).to_digit(16);
        match (raw[i], raw.get(i + 1).copied().and_then(hex), raw.get(i + 2).copied().and_then(hex)) {
            (b'%', Some(hi), Some(lo)) => {
                bytes.push((hi * 16 + lo) as u8);
                i += 3;
            }
            (b, ..) => {
                bytes.push(b);
                i += 1;
            }
        }
    }
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(&bytes)))
}

#[cfg(test)]
mod tests {
    use super::file_url_to_path;
    use std::path::PathBuf;

    #[test]
    fn file_urls_become_paths() {
        assert_eq!(file_url_to_path("file:///Users/me/a.pdf"), Some(PathBuf::from("/Users/me/a.pdf")));
        assert_eq!(file_url_to_path("file:///Users/me/Smlouva%20o%20d%C3%ADlo%20(1).pdf"), Some(PathBuf::from("/Users/me/Smlouva o dílo (1).pdf")));
        assert_eq!(file_url_to_path("file://localhost/tmp/x.pdf"), Some(PathBuf::from("/tmp/x.pdf")));
        assert_eq!(file_url_to_path("https://example.com/a.pdf"), None);
    }
}
