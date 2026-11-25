//! RockSign core: validate PDF signatures and sign PDFs (PAdES), with no platform code.
//!
//! - [`verify::analyze`] checks every signature in a file.
//! - [`sign::prepare`] + [`cms::signed_attributes`] + [`cms::signed_data`] + [`sign::embed`]
//!   add a signature; the private-key operation happens outside, between those calls.

pub mod anchors;
mod anchors_cz;
pub mod asn1;
pub mod cms;
pub mod crypto;
pub mod logo;
pub mod pdf;
pub mod sign;
pub mod stamp;
pub mod verify;
pub mod writer;
pub mod x509;

pub use verify::{ChangeLevel, Integrity, Report, SignatureReport, analyze};
pub use x509::Certificate;
