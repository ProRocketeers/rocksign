//! Render an SVG to a square-fitted PNG, used to build the app icon:
//!
//!     cargo run -p rocksign-core --example render_svg -- in.svg out.png SIZE
//!
//! The image is scaled so its longer side is SIZE pixels.

use anyhow::{Context, Result};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [input, output, size] = args.as_slice() else {
        anyhow::bail!("usage: render_svg in.svg out.png SIZE");
    };
    let size: f32 = size.parse().context("SIZE must be a number")?;
    let data = std::fs::read(input).with_context(|| format!("could not read {input}"))?;
    let tree = resvg::usvg::Tree::from_data(&data, &resvg::usvg::Options::default())?;
    let s = size / tree.size().width().max(tree.size().height());
    let (w, h) = ((tree.size().width() * s).round() as u32, (tree.size().height() * s).round() as u32);
    let mut pixmap = resvg::tiny_skia::Pixmap::new(w, h).context("bad size")?;
    resvg::render(&tree, resvg::tiny_skia::Transform::from_scale(s, s), &mut pixmap.as_mut());
    pixmap.save_png(output)?;
    Ok(())
}
