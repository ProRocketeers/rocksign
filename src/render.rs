//! Page pixels from Apple's PDFKit, on one background thread that owns the document.
//!
//! PDFKit only draws here; it never saves. (Saving through PDFKit rewrites the whole file and
//! breaks every signature in it.)

use std::collections::VecDeque;
use std::sync::{Arc, mpsc};

use anyhow::{Context, Result};
use futures::channel::mpsc::UnboundedSender;
use gpui::RenderImage;
use objc2::AllocAnyThread;
use objc2::rc::{Retained, autoreleasepool};
use objc2_core_foundation::{CGAffineTransform, CGPoint, CGRect, CGSize};
use objc2_core_graphics::{CGBitmapContextCreate, CGColorSpace, CGContext, CGImageAlphaInfo, CGImageByteOrderInfo, CGInterpolationQuality};
use objc2_foundation::NSData;
use objc2_pdf_kit::{PDFDisplayBox, PDFDocument};
use smallvec::SmallVec;

/// Pixels in BGRA order (what GPUI's images use), premultiplied, opaque.
pub struct Bitmap {
    pub width: u32,
    pub height: u32,
    pub bgra: Vec<u8>,
}

pub struct PdfKitDocument {
    doc: Retained<PDFDocument>,
}

impl PdfKitDocument {
    pub fn open(bytes: &[u8]) -> Result<Self> {
        let data = NSData::with_bytes(bytes);
        let doc = unsafe { PDFDocument::initWithData(PDFDocument::alloc(), &data) }.context("PDFKit could not open this file")?;
        Ok(PdfKitDocument { doc })
    }

    pub fn page_count(&self) -> usize {
        unsafe { self.doc.pageCount() }
    }

    /// Draw page `index` so it is `width_px` pixels wide as shown (rotation applied).
    pub fn render(&self, index: usize, width_px: u32) -> Result<Bitmap> {
        autoreleasepool(|_| {
            let page = unsafe { self.doc.pageAtIndex(index) }.context("no such page")?;
            let bounds = unsafe { page.boundsForBox(PDFDisplayBox::CropBox) };
            let rotation = unsafe { page.rotation() }.rem_euclid(360);
            let (pw, ph) = if rotation % 180 == 90 { (bounds.size.height, bounds.size.width) } else { (bounds.size.width, bounds.size.height) };
            if pw <= 0.0 || ph <= 0.0 {
                anyhow::bail!("the page has no size");
            }
            let scale = width_px.max(1) as f64 / pw;
            let w = width_px.max(1) as usize;
            let h = ((ph * scale).round() as usize).max(1);
            let mut bgra = vec![0u8; w * h * 4];
            let space = CGColorSpace::new_device_rgb();
            let info = CGImageAlphaInfo::PremultipliedFirst.0 | CGImageByteOrderInfo::Order32Little.0;
            let ctx = unsafe { CGBitmapContextCreate(bgra.as_mut_ptr().cast(), w, h, 8, w * 4, space.as_deref(), info) }
                .context("could not create a bitmap")?;
            let ctx_ref: &CGContext = &ctx;
            CGContext::set_rgb_fill_color(Some(ctx_ref), 1.0, 1.0, 1.0, 1.0);
            CGContext::fill_rect(Some(ctx_ref), CGRect::new(CGPoint::new(0.0, 0.0), CGSize::new(w as f64, h as f64)));
            CGContext::set_interpolation_quality(Some(ctx_ref), CGInterpolationQuality::High);
            CGContext::scale_ctm(Some(ctx_ref), scale, scale);
            // PDFKit skips annotations (signature stamps!) when it rotates a page itself, so draw
            // the page unrotated and rotate the context instead. This changes only our
            // in-memory copy; nothing is ever saved through PDFKit.
            if rotation != 0 {
                unsafe { page.setRotation(0) };
                let (bw, bh) = (bounds.size.width, bounds.size.height);
                let t = match rotation {
                    90 => CGAffineTransform { a: 0.0, b: -1.0, c: 1.0, d: 0.0, tx: 0.0, ty: bw },
                    180 => CGAffineTransform { a: -1.0, b: 0.0, c: 0.0, d: -1.0, tx: bw, ty: bh },
                    _ => CGAffineTransform { a: 0.0, b: 1.0, c: -1.0, d: 0.0, tx: bh, ty: 0.0 },
                };
                CGContext::concat_ctm(Some(ctx_ref), t);
            }
            unsafe { page.drawWithBox_toContext(PDFDisplayBox::CropBox, ctx_ref) };
            if rotation != 0 {
                unsafe { page.setRotation(rotation) };
            }
            drop(ctx);
            Ok(Bitmap { width: w as u32, height: h as u32, bgra })
        })
    }
}

impl Bitmap {
    pub fn into_render_image(self) -> Arc<RenderImage> {
        let buffer = image::RgbaImage::from_raw(self.width, self.height, self.bgra).expect("buffer matches size");
        let frames: SmallVec<[image::Frame; 1]> = SmallVec::from_elem(image::Frame::new(buffer), 1);
        Arc::new(RenderImage::new(frames))
    }

    /// Save as PNG (for debugging the renderer).
    pub fn save_png(&self, path: &std::path::Path) -> Result<()> {
        let mut rgba = self.bgra.clone();
        for px in rgba.chunks_exact_mut(4) {
            px.swap(0, 2);
        }
        image::RgbaImage::from_raw(self.width, self.height, rgba).context("bitmap size")?.save(path)?;
        Ok(())
    }
}

pub enum Request {
    Open { generation: u64, bytes: Arc<Vec<u8>> },
    Render { generation: u64, page: usize, width: u32 },
}

pub struct Rendered {
    pub generation: u64,
    pub page: usize,
    pub width: u32,
    pub image: Result<Arc<RenderImage>, String>,
}

/// Handle to the render thread.
pub struct Worker {
    tx: mpsc::Sender<Request>,
}

impl Worker {
    pub fn spawn(out: UnboundedSender<Rendered>) -> Self {
        let (tx, rx) = mpsc::channel::<Request>();
        std::thread::Builder::new().name("pdf-render".into()).spawn(move || run(rx, out)).expect("start render thread");
        Worker { tx }
    }

    pub fn send(&self, req: Request) {
        let _ = self.tx.send(req);
    }
}

fn run(rx: mpsc::Receiver<Request>, out: UnboundedSender<Rendered>) {
    let mut doc: Option<(u64, PdfKitDocument)> = None;
    let mut queue: VecDeque<(u64, usize, u32)> = VecDeque::new();
    loop {
        // Wait for work, then take everything that piled up so stale requests can be skipped.
        let first = if queue.is_empty() {
            match rx.recv() {
                Ok(r) => Some(r),
                Err(_) => return,
            }
        } else {
            None
        };
        for req in first.into_iter().chain(rx.try_iter()) {
            match req {
                Request::Open { generation, bytes } => {
                    queue.clear();
                    doc = PdfKitDocument::open(&bytes).ok().map(|d| (generation, d));
                }
                Request::Render { generation, page, width } => {
                    queue.retain(|(_, p, _)| *p != page);
                    // Newest requests are the pages on screen now: do them first.
                    queue.push_front((generation, page, width));
                }
            }
        }
        let Some((generation, page, width)) = queue.pop_front() else { continue };
        let Some((doc_gen, d)) = doc.as_ref() else { continue };
        if *doc_gen != generation {
            continue;
        }
        let image = d.render(page, width).map(Bitmap::into_render_image).map_err(|e| e.to_string());
        if out.unbounded_send(Rendered { generation, page, width, image }).is_err() {
            return;
        }
    }
}
