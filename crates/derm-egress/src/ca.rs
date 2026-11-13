//! The local CA (`contracts/policy.md` section 8.3; note AZ C4, C5, C8;
//! AZ-9): created by the person from a terminal (`derm secret ca create`),
//! kept in `~/.derm/egress/` as three owner-only files in an owner-only
//! folder, and used by derm-egress to sign a leaf per host it terminates TLS
//! for. The CA can sign only leaves (path length 0); a leaf lives 8 days and is
//! never written to disk.
//!
//! The certificate is rebuilt from `ca.json` and the key at each load rather
//! than parsed: rcgen 0.14.10 parses a certificate only with its
//! `x509-parser` feature (`src/lib.rs:231-258`), which this crate does not
//! take. The rebuilt issuer has the same name and key identifier (rcgen's
//! SHA-256 method, a function of the key), so the leaves chain to `ca.pem`.
//!
//! Risk (the wave 6 plan's line): a CA every brokered client trusts is a strong
//! credential. Its key never leaves the 0600 file and the proxy's memory, and
//! the chain's start line names the chats that trust it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    Issuer, KeyPair, KeyUsagePurpose, SerialNumber,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};

/// How long a CA lives (renewed with `derm secret ca create --replace`).
pub const CA_DAYS: i64 = 365;
/// How long a leaf lives; leaves are made per host, in memory only.
pub const LEAF_DAYS: i64 = 8;
/// Leaves kept per CA before the oldest is dropped.
const MAX_LEAVES: usize = 1024;

/// What `ca.json` keeps: what the certificate is rebuilt from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Meta {
    pub version: u64,
    pub common_name: String,
    /// Days since the Unix epoch (UTC).
    pub not_before_day: i64,
    pub not_after_day: i64,
    /// The certificate's serial, hex.
    pub serial: String,
}

/// The CA in memory. Its `Debug` names the CA, never the key.
pub struct Ca {
    meta: Meta,
    key: KeyPair,
    params: CertificateParams,
    cert: CertificateDer<'static>,
    leaf_key: KeyPair,
    leaves: Mutex<HashMap<String, Arc<rustls::sign::CertifiedKey>>>,
}

impl std::fmt::Debug for Ca {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ca")
            .field("meta", &self.meta)
            .finish_non_exhaustive()
    }
}

/// The CA's folder under a home: `<home>/.derm/egress`.
pub fn dir_for(home: &Path) -> PathBuf {
    home.join(".derm").join("egress")
}

pub fn today() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64 / 86_400)
        .unwrap_or(0)
}

/// `(year, month, day)` for days since the epoch (H. Hinnant's
/// civil-from-days).
pub fn civil(days: i64) -> (i32, u8, u8) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u8;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u8;
    ((if m <= 2 { y + 1 } else { y }) as i32, m, d)
}

/// Set a certificate's validity to whole UTC days (rcgen's own date helper;
/// the `time` type it returns is not named here).
fn set_validity(p: &mut CertificateParams, from_day: i64, to_day: i64) {
    let (y, m, d) = civil(from_day);
    p.not_before = rcgen::date_time_ymd(y, m, d);
    let (y, m, d) = civil(to_day);
    p.not_after = rcgen::date_time_ymd(y, m, d);
}

fn random(n: usize) -> Result<Vec<u8>, String> {
    use ring::rand::SecureRandom;
    let mut b = vec![0u8; n];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .map_err(|_| "no random source".to_string())?;
    Ok(b)
}

/// The DER of a single `CERTIFICATE` block.
fn pem_der(pem: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let body = pem
        .trim()
        .strip_prefix("-----BEGIN CERTIFICATE-----")?
        .strip_suffix("-----END CERTIFICATE-----")?;
    let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

/// One DER element at the start of `b`: (header length, content length).
fn tlv(b: &[u8]) -> Option<(usize, usize)> {
    let first = *b.get(1)?;
    if first < 0x80 {
        return Some((2, first as usize));
    }
    let n = (first & 0x7f) as usize;
    if n == 0 || n > 4 {
        return None;
    }
    let mut len = 0usize;
    for i in 0..n {
        len = len << 8 | *b.get(2 + i)? as usize;
    }
    Some((2 + n, len))
}

/// A certificate's `tbsCertificate`, the first element of its outer SEQUENCE.
fn tbs(cert: &[u8]) -> Option<&[u8]> {
    if cert.first() != Some(&0x30) {
        return None;
    }
    let (h, len) = tlv(cert)?;
    let inner = cert.get(h..h + len)?;
    if inner.first() != Some(&0x30) {
        return None;
    }
    let (ih, ilen) = tlv(inner)?;
    inner.get(..ih + ilen)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(s.get(i..i + 2)?, 16).ok())
        .collect()
}

fn ca_params(meta: &Meta) -> Result<CertificateParams, String> {
    let mut p = CertificateParams::default();
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, meta.common_name.clone());
    p.distinguished_name = dn;
    p.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    p.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    set_validity(&mut p, meta.not_before_day, meta.not_after_day);
    p.serial_number = Some(SerialNumber::from_slice(
        &unhex(&meta.serial).ok_or("ca.json: a serial that is not hex")?,
    ));
    Ok(p)
}

impl Ca {
    /// A new CA in memory (`derm secret ca create`, and tests).
    pub fn generate() -> Result<Ca, String> {
        let key = KeyPair::generate().map_err(|e| format!("CA key: {e}"))?;
        let mut serial = random(16)?;
        serial[0] &= 0x7f;
        let tag = hex(&random(4)?);
        let day = today();
        let meta = Meta {
            version: 1,
            common_name: format!("derm local CA {tag}"),
            not_before_day: day - 1,
            not_after_day: day + CA_DAYS,
            serial: hex(&serial),
        };
        Ca::from_parts(meta, key, None)
    }

    /// The CA from its metadata and key. With `saved`, the certificate is
    /// the one clients were given (`ca.pem`), which must sign the same
    /// to-be-signed part as the rebuilt one: an ECDSA signature differs per
    /// signing, the part it signs does not.
    fn from_parts(
        meta: Meta,
        key: KeyPair,
        saved: Option<CertificateDer<'static>>,
    ) -> Result<Ca, String> {
        let params = ca_params(&meta)?;
        let built = params
            .self_signed(&key)
            .map_err(|e| format!("CA certificate: {e}"))?
            .der()
            .clone();
        let cert = match saved {
            None => built,
            Some(s) => {
                if tbs(s.as_ref()) != tbs(built.as_ref()) || tbs(s.as_ref()).is_none() {
                    return Err(
                        "ca.pem does not match ca-key.pem and ca.json; create the CA again".into(),
                    );
                }
                s
            }
        };
        let leaf_key = KeyPair::generate().map_err(|e| format!("leaf key: {e}"))?;
        Ok(Ca {
            meta,
            key,
            params,
            cert,
            leaf_key,
            leaves: Mutex::new(HashMap::new()),
        })
    }

    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// The CA certificate, DER.
    pub fn cert_der(&self) -> &CertificateDer<'static> {
        &self.cert
    }

    /// The CA certificate, PEM: what clients trust (C4's variables).
    pub fn cert_pem(&self) -> String {
        use base64::Engine;
        let b = base64::engine::general_purpose::STANDARD.encode(self.cert.as_ref());
        let mut s = String::from("-----BEGIN CERTIFICATE-----\n");
        for line in b.as_bytes().chunks(64) {
            s.push_str(std::str::from_utf8(line).unwrap_or_default());
            s.push('\n');
        }
        s.push_str("-----END CERTIFICATE-----\n");
        s
    }

    /// The SHA-256 of the certificate, hex: how a store or a start line names it.
    pub fn fingerprint(&self) -> String {
        hex(ring::digest::digest(&ring::digest::SHA256, self.cert.as_ref()).as_ref())
    }

    /// Whether the CA is still valid today, with at least `margin` days left.
    pub fn valid_for(&self, margin: i64) -> bool {
        let t = today();
        self.meta.not_before_day <= t && t + margin <= self.meta.not_after_day
    }

    /// Write `ca-key.pem`, `ca.json` and `ca.pem` into `dir` (made 0700),
    /// each 0600. Refuses to replace an existing CA unless `replace`.
    pub fn save(&self, dir: &Path, replace: bool) -> Result<(), String> {
        let key = dir.join("ca-key.pem");
        if key.exists() && !replace {
            return Err(format!("{} exists", key.display()));
        }
        let meta = serde_json::to_string_pretty(&self.meta).map_err(|e| e.to_string())? + "\n";
        crate::secrets::write_private(dir, &key, self.key.serialize_pem().as_bytes())?;
        crate::secrets::write_private(dir, &dir.join("ca.json"), meta.as_bytes())?;
        crate::secrets::write_private(dir, &dir.join("ca.pem"), self.cert_pem().as_bytes())
    }

    /// Load the CA from `dir`. `None` when none was created. Each file must be
    /// the user's alone (0600, not a link).
    pub fn load(dir: &Path) -> Result<Option<Ca>, String> {
        let key = match crate::secrets::read_private(&dir.join("ca-key.pem"), 64 * 1024)? {
            Some(k) => k,
            None => return Ok(None),
        };
        let meta = crate::secrets::read_private(&dir.join("ca.json"), 64 * 1024)?
            .ok_or("ca.json is missing beside ca-key.pem")?;
        let meta: Meta = serde_json::from_str(&meta).map_err(|e| format!("ca.json: {e}"))?;
        if meta.version != 1 {
            return Err(format!("ca.json: version {} is not 1", meta.version));
        }
        let key = KeyPair::from_pem(&key).map_err(|e| format!("ca-key.pem: {e}"))?;
        let pem = crate::secrets::read_private(&dir.join("ca.pem"), 64 * 1024)?
            .ok_or("ca.pem is missing beside ca-key.pem")?;
        let der = pem_der(&pem).ok_or("ca.pem is not one PEM certificate")?;
        Ca::from_parts(meta, key, Some(CertificateDer::from(der))).map(Some)
    }

    /// Remove the CA's files from `dir`. Returns what it removed.
    pub fn remove(dir: &Path) -> Result<Vec<PathBuf>, String> {
        let mut gone = Vec::new();
        for f in ["ca-key.pem", "ca.json", "ca.pem"] {
            let p = dir.join(f);
            match std::fs::remove_file(&p) {
                Ok(()) => gone.push(p),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", p.display())),
            }
        }
        Ok(gone)
    }

    /// A leaf for `host` (a DNS name or an IP literal), signed by this CA,
    /// with the CA in its chain. Made once per host and kept in memory.
    pub fn leaf(&self, host: &str) -> Result<Arc<rustls::sign::CertifiedKey>, String> {
        let host = crate::normal_host(host);
        if let Some(k) = self.leaves.lock().map_err(|_| "leaf cache")?.get(&host) {
            return Ok(k.clone());
        }
        let mut p = CertificateParams::new(vec![host.clone()])
            .map_err(|e| format!("leaf for {host}: {e}"))?;
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, host.clone());
        p.distinguished_name = dn;
        p.is_ca = IsCa::ExplicitNoCa;
        p.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        p.use_authority_key_identifier_extension = true;
        let mut serial = random(16)?;
        serial[0] &= 0x7f;
        p.serial_number = Some(SerialNumber::from_slice(&serial));
        let day = today();
        set_validity(
            &mut p,
            day - 1,
            (day + LEAF_DAYS).min(self.meta.not_after_day),
        );
        let issuer = Issuer::from_params(&self.params, &self.key);
        let cert = p
            .signed_by(&self.leaf_key, &issuer)
            .map_err(|e| format!("leaf for {host}: {e}"))?;
        let der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.leaf_key.serialize_der()));
        let signer = rustls::crypto::ring::sign::any_supported_type(&der)
            .map_err(|e| format!("leaf key: {e}"))?;
        let ck = Arc::new(rustls::sign::CertifiedKey::new(
            vec![cert.der().clone(), self.cert.clone()],
            signer,
        ));
        let mut cache = self.leaves.lock().map_err(|_| "leaf cache")?;
        if cache.len() >= MAX_LEAVES {
            cache.clear();
        }
        cache.insert(host, ck.clone());
        Ok(ck)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn civil_dates_match_known_days() {
        assert_eq!(civil(0), (1970, 1, 1));
        assert_eq!(civil(19_723), (2024, 1, 1));
        assert_eq!(civil(20_769), (2026, 11, 12));
        assert_eq!(civil(-1), (1969, 12, 31));
        assert_eq!(civil(11_016), (2000, 2, 29));
    }

    #[cfg(unix)]
    #[test]
    fn a_saved_ca_loads_back_with_the_same_certificate_and_files_stay_private() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let d = std::env::temp_dir().join(format!("derm-egress-ca-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let dir = d.join(".derm").join("egress");
        let ca = Ca::generate().unwrap();
        ca.save(&dir, false).unwrap();
        assert!(ca.save(&dir, false).is_err(), "no silent replace");
        for f in ["ca-key.pem", "ca.json", "ca.pem"] {
            assert_eq!(
                std::fs::metadata(dir.join(f)).unwrap().mode() & 0o777,
                0o600,
                "{f}"
            );
        }
        let back = Ca::load(&dir).unwrap().unwrap();
        assert_eq!(
            back.cert_der(),
            ca.cert_der(),
            "the saved certificate itself"
        );
        assert_eq!(back.fingerprint(), ca.fingerprint());
        assert!(back.valid_for(30));
        std::fs::set_permissions(
            dir.join("ca-key.pem"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(Ca::load(&dir).is_err(), "a key others can read is refused");
        std::fs::set_permissions(
            dir.join("ca-key.pem"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        // A ca.pem from another CA beside this key is refused.
        let other = Ca::generate().unwrap();
        let pem = dir.join("ca.pem");
        std::fs::write(&pem, other.cert_pem()).unwrap();
        assert!(Ca::load(&dir).unwrap_err().contains("does not match"));
        assert_eq!(Ca::remove(&dir).unwrap().len(), 3);
        assert!(Ca::load(&dir).unwrap().is_none());
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn a_leaf_chains_to_the_ca_and_is_cached_per_host() {
        let ca = Ca::generate().unwrap();
        let a = ca.leaf("API.GitHub.com.").unwrap();
        let b = ca.leaf("api.github.com").unwrap();
        assert!(Arc::ptr_eq(&a, &b));
        assert_eq!(a.cert.len(), 2);
        assert_eq!(&a.cert[1], ca.cert_der());
        // The chain verifies against the CA as a root, for that name only.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(ca.cert_der().clone()).unwrap();
        let v = rustls::client::WebPkiServerVerifier::builder_with_provider(
            Arc::new(roots),
            Arc::new(rustls::crypto::ring::default_provider()),
        )
        .build()
        .unwrap();
        use rustls::client::danger::ServerCertVerifier;
        let now = rustls::pki_types::UnixTime::now();
        let name = rustls::pki_types::ServerName::try_from("api.github.com").unwrap();
        assert!(v
            .verify_server_cert(&a.cert[0], &a.cert[1..], &name, &[], now)
            .is_ok());
        let other = rustls::pki_types::ServerName::try_from("evil.test").unwrap();
        assert!(v
            .verify_server_cert(&a.cert[0], &a.cert[1..], &other, &[], now)
            .is_err());
        assert!(ca.leaf("127.0.0.1").is_ok());
    }
}
