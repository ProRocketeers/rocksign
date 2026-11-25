//! Built-in trust anchors: certification authorities on the Czech trusted list that issue
//! qualified certificates for e-signatures and e-seals (PostSignum, I.CA, eIdentita, NCA, KB).
//! macOS doesn't trust most of these out of the box; Acrobat does via the EU trusted list.
//!
//! Refresh with `cargo run -p rocksign-core --example update_cz_trusted_list`.

use std::sync::OnceLock;

use crate::anchors_cz;
use crate::x509::Certificate;

pub struct Anchor {
    pub provider: &'static str,
    pub certificate: Certificate,
}

/// The Czech trusted list snapshot's issue date.
pub const CZ_LIST_ISSUED: &str = anchors_cz::LIST_ISSUED;

pub fn czech_qualified() -> &'static [Anchor] {
    static ANCHORS: OnceLock<Vec<Anchor>> = OnceLock::new();
    ANCHORS.get_or_init(|| {
        anchors_cz::CERTIFICATES
            .iter()
            .filter_map(|(provider, _, der)| Certificate::parse(der).ok().map(|certificate| Anchor { provider, certificate }))
            .collect()
    })
}

/// If this chain passes through a qualified Czech CA, its provider's name.
pub fn qualified_provider(chain: &[Certificate]) -> Option<&'static str> {
    czech_qualified().iter().find(|a| chain.iter().any(|c| c.der == a.certificate.der)).map(|a| a.provider)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_anchors_parse() {
        assert_eq!(czech_qualified().len(), anchors_cz::CERTIFICATES.len());
        assert!(czech_qualified().iter().any(|a| a.certificate.display_name() == "PostSignum Qualified CA 4"));
    }
}
