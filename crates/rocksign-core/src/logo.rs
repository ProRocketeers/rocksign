//! A logo for the signature stamp: SVG (rendered with resvg), PNG or JPEG, turned into an RGBA
//! bitmap and embedded in the PDF as an image with a transparency mask.

use std::io::Write;

use anyhow::{Context, Result, bail};
use flate2::{Compression, write::ZlibEncoder};
use lopdf::{Dictionary, Object, Stream};

/// The RockSign logo (a rocket whose trail is a signature), offered as a stamp logo.
pub const ROCKSIGN_SVG: &[u8] = include_bytes!("../assets/rocksign-logo.svg");

/// Long side of the bitmap: sharp in print at the size of a stamp.
const MAX_SIDE: u32 = 900;

#[derive(Clone)]
pub struct Logo {
    pub width: u32,
    pub height: u32,
    /// Straight (not premultiplied) RGBA.
    pub rgba: Vec<u8>,
}

impl Logo {
    /// The built-in RockSign logo.
    pub fn rocksign() -> Result<Logo> {
        Logo::from_bytes(ROCKSIGN_SVG)
    }

    /// SVG, PNG or JPEG.
    pub fn from_bytes(bytes: &[u8]) -> Result<Logo> {
        let head = String::from_utf8_lossy(&bytes[..bytes.len().min(512)]).to_lowercase();
        let logo = if head.contains("<svg") || head.trim_start().starts_with("<?xml") { Self::from_svg(bytes)? } else { Self::from_raster(bytes)? };
        Ok(logo.trimmed())
    }

    fn from_svg(bytes: &[u8]) -> Result<Logo> {
        let tree = resvg::usvg::Tree::from_data(bytes, &resvg::usvg::Options::default()).context("this SVG could not be read")?;
        let size = tree.size();
        let scale = MAX_SIDE as f32 / size.width().max(size.height());
        let (w, h) = ((size.width() * scale).ceil() as u32, (size.height() * scale).ceil() as u32);
        let mut pixmap = resvg::tiny_skia::Pixmap::new(w.max(1), h.max(1)).context("logo too large")?;
        resvg::render(&tree, resvg::tiny_skia::Transform::from_scale(scale, scale), &mut pixmap.as_mut());
        let mut rgba = pixmap.take();
        for px in rgba.chunks_exact_mut(4) {
            let a = px[3] as u32;
            if a > 0 && a < 255 {
                for c in &mut px[..3] {
                    *c = ((*c as u32 * 255 + a / 2) / a).min(255) as u8;
                }
            }
        }
        Ok(Logo { width: w.max(1), height: h.max(1), rgba })
    }

    fn from_raster(bytes: &[u8]) -> Result<Logo> {
        let img = image::load_from_memory(bytes).context("this image could not be read (use PNG, JPEG or SVG)")?.to_rgba8();
        let (w, h) = img.dimensions();
        let img = if w.max(h) > MAX_SIDE {
            let s = MAX_SIDE as f32 / w.max(h) as f32;
            image::imageops::resize(&img, ((w as f32 * s) as u32).max(1), ((h as f32 * s) as u32).max(1), image::imageops::FilterType::Lanczos3)
        } else {
            img
        };
        let (width, height) = img.dimensions();
        Ok(Logo { width, height, rgba: img.into_raw() })
    }

    /// Cut away transparent margins.
    fn trimmed(self) -> Logo {
        let (w, h) = (self.width as usize, self.height as usize);
        let visible = |x: usize, y: usize| self.rgba[(y * w + x) * 4 + 3] > 8;
        let rows: Vec<usize> = (0..h).filter(|&y| (0..w).any(|x| visible(x, y))).collect();
        let cols: Vec<usize> = (0..w).filter(|&x| (0..h).any(|y| visible(x, y))).collect();
        let (Some(&y0), Some(&y1), Some(&x0), Some(&x1)) = (rows.first(), rows.last(), cols.first(), cols.last()) else {
            return self;
        };
        if (x0, y0, x1, y1) == (0, 0, w - 1, h - 1) {
            return self;
        }
        let (nw, nh) = (x1 - x0 + 1, y1 - y0 + 1);
        let mut rgba = Vec::with_capacity(nw * nh * 4);
        for y in y0..=y1 {
            rgba.extend_from_slice(&self.rgba[(y * w + x0) * 4..(y * w + x1 + 1) * 4]);
        }
        Logo { width: nw as u32, height: nh as u32, rgba }
    }

    /// Width divided by height.
    pub fn aspect(&self) -> f32 {
        self.width as f32 / self.height as f32
    }

    /// The image and its transparency mask as PDF streams: (image, mask). The caller links the
    /// mask with /SMask.
    pub fn pdf_streams(&self) -> Result<(Stream, Stream)> {
        let mut rgb = Vec::with_capacity(self.rgba.len() / 4 * 3);
        let mut alpha = Vec::with_capacity(self.rgba.len() / 4);
        for px in self.rgba.chunks_exact(4) {
            rgb.extend_from_slice(&px[..3]);
            alpha.push(px[3]);
        }
        let image = |data: &[u8], color: &str| -> Result<Stream> {
            let mut enc = ZlibEncoder::new(Vec::new(), Compression::best());
            enc.write_all(data)?;
            let mut d = Dictionary::new();
            d.set("Type", Object::Name(b"XObject".to_vec()));
            d.set("Subtype", Object::Name(b"Image".to_vec()));
            d.set("Width", Object::Integer(self.width as i64));
            d.set("Height", Object::Integer(self.height as i64));
            d.set("ColorSpace", Object::Name(color.as_bytes().to_vec()));
            d.set("BitsPerComponent", Object::Integer(8));
            d.set("Filter", Object::Name(b"FlateDecode".to_vec()));
            Ok(Stream::new(d, enc.finish()?))
        };
        if self.width == 0 || self.height == 0 {
            bail!("empty logo");
        }
        Ok((image(&rgb, "DeviceRGB")?, image(&alpha, "DeviceGray")?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rocksign_logo_renders() {
        let logo = Logo::rocksign().unwrap();
        // Rocket and trail make a roughly square mark.
        assert!(logo.aspect() > 0.9 && logo.aspect() < 1.4, "{}", logo.aspect());
        assert!(logo.rgba.chunks_exact(4).any(|p| p[3] == 255));
        let (img, mask) = logo.pdf_streams().unwrap();
        assert!(img.content.len() < 200_000 && mask.content.len() < 100_000);
    }
}
