use thiserror::Error;
use url::Url;

use crate::profile::{
    is_canonical_service_fqdn, valid_coral_name, valid_lattice_fqdn, valid_reef_name,
};

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LatticeUriError {
    #[error("invalid Lattice URI")]
    Invalid,
}

/// Converts an `lttc://` deep link into the only browser-safe form accepted by Lattice.
/// The authority is a single service slug; credentials, ports, fragments and
/// ambiguous percent-encoded hosts fail closed.
pub fn lattice_uri_to_https(input: &str) -> Result<Url, LatticeUriError> {
    let parsed = Url::parse(input).map_err(|_| LatticeUriError::Invalid)?;
    if parsed.scheme() != "lttc"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.fragment().is_some()
    {
        return Err(LatticeUriError::Invalid);
    }
    let host = parsed.host_str().ok_or(LatticeUriError::Invalid)?;
    let fqdn = if is_canonical_service_fqdn(host)
        || valid_coral_name(host)
        || valid_reef_name(host)
        || valid_lattice_fqdn(host)
    {
        host.to_owned()
    } else {
        if host.contains('.')
            || host
                .bytes()
                .any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'))
        {
            return Err(LatticeUriError::Invalid);
        }
        let fqdn = format!("{host}.lattice");
        if !valid_lattice_fqdn(&fqdn) {
            return Err(LatticeUriError::Invalid);
        }
        fqdn
    };
    let mut target =
        Url::parse(&format!("https://{fqdn}/")).map_err(|_| LatticeUriError::Invalid)?;
    target.set_path(parsed.path());
    target.set_query(parsed.query());
    Ok(target)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deep_link_preserves_path_and_query() {
        assert_eq!(
            lattice_uri_to_https("lttc://echo/a%20b?q=1")
                .unwrap()
                .as_str(),
            "https://echo.lattice/a%20b?q=1"
        );
    }

    #[test]
    fn dangerous_authorities_are_rejected() {
        for input in [
            "lttc://user@echo/path",
            "lttc://echo:443/path",
            "lttc://127.0.0.1/path",
            "lttc://echo/path#fragment",
        ] {
            assert!(lattice_uri_to_https(input).is_err(), "{input}");
        }
    }

    #[test]
    fn canonical_identity_deep_link_is_accepted_but_other_dotted_hosts_are_not() {
        let identity = crate::profile::canonical_service_fqdn(&"ab".repeat(32)).unwrap();
        assert_eq!(
            lattice_uri_to_https(&format!("lttc://{identity}/health"))
                .unwrap()
                .as_str(),
            format!("https://{identity}/health")
        );
        assert_eq!(
            lattice_uri_to_https("lttc://echo.lattice/health")
                .unwrap()
                .as_str(),
            "https://echo.lattice/health"
        );
        assert_eq!(
            lattice_uri_to_https("lttc://alice.coral/health")
                .unwrap()
                .as_str(),
            "https://alice.coral/health"
        );
        assert_eq!(
            lattice_uri_to_https("lttc://api.alice.coral/health")
                .unwrap()
                .as_str(),
            "https://api.alice.coral/health"
        );
        assert_eq!(
            lattice_uri_to_https("lttc://clipma.reef/health")
                .unwrap()
                .as_str(),
            "https://clipma.reef/health"
        );
        assert!(lattice_uri_to_https("lattice://echo/health").is_err());
    }
}
