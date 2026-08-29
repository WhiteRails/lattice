use thiserror::Error;
use url::Url;

use crate::profile::valid_lattice_fqdn;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LatticeUriError {
    #[error("invalid Lattice URI")]
    Invalid,
}

/// Converts a deep link into the only browser-safe form accepted by Lattice.
/// The authority is a single service slug; credentials, ports, fragments and
/// ambiguous percent-encoded hosts fail closed.
pub fn lattice_uri_to_https(input: &str) -> Result<Url, LatticeUriError> {
    let parsed = Url::parse(input).map_err(|_| LatticeUriError::Invalid)?;
    if parsed.scheme() != "lattice"
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.port().is_some()
        || parsed.fragment().is_some()
    {
        return Err(LatticeUriError::Invalid);
    }
    let host = parsed.host_str().ok_or(LatticeUriError::Invalid)?;
    if host.contains('.') || host.bytes().any(|b| !(b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')) {
        return Err(LatticeUriError::Invalid);
    }
    let fqdn = format!("{host}.lattice");
    if !valid_lattice_fqdn(&fqdn) {
        return Err(LatticeUriError::Invalid);
    }
    let mut target = Url::parse(&format!("https://{fqdn}/")).map_err(|_| LatticeUriError::Invalid)?;
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
            lattice_uri_to_https("lattice://echo/a%20b?q=1").unwrap().as_str(),
            "https://echo.lattice/a%20b?q=1"
        );
    }

    #[test]
    fn dangerous_authorities_are_rejected() {
        for input in [
            "lattice://user@echo/path",
            "lattice://echo:443/path",
            "lattice://127.0.0.1/path",
            "lattice://echo/path#fragment",
        ] {
            assert!(lattice_uri_to_https(input).is_err(), "{input}");
        }
    }
}

