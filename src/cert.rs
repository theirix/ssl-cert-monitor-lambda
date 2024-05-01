use crate::error::MonitorError;
use chrono::{DateTime, Utc};
use lambda_runtime::tracing::info;
use rustls::pki_types::CertificateDer;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use x509_certificate::certificate::X509Certificate;

pub struct Validator {
    max_expiration: u64,
    now: DateTime<Utc>,
    rc_config: Arc<rustls::ClientConfig>,
}

impl Validator {
    pub fn new(now: DateTime<Utc>, max_expiration: u64) -> Self {
        let root_store =
            rustls::RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let rc_config = Arc::new(config);

        Self {
            max_expiration,
            now,
            rc_config,
        }
    }

    fn read_certificates(
        &self,
        domain: &str,
    ) -> Result<Vec<CertificateDer<'static>>, MonitorError> {
        let domain_name = domain.to_string().try_into().unwrap();
        let mut conn = rustls::ClientConnection::new(self.rc_config.clone(), domain_name)
            .map_err(|err| MonitorError::Network(err.to_string()))?;

        let mut sock = TcpStream::connect(format!("{}:443", domain)).unwrap();
        let mut tls = rustls::Stream::new(&mut conn, &mut sock);

        tls.write_all(
            format!(
                "GET / HTTP/1.1\r\nHost: {}\r\nConnection: close\r\nAccept: */*\r\n\r\n",
                domain
            )
            .as_bytes(),
        )
        .map_err(|err| MonitorError::Network(format!("Write err: {err}")))?;
        tls.flush()
            .map_err(|err| MonitorError::Network(format!("Flush err: {err}")))?;
        let mut plaintext = Vec::new();

        match tls.read_to_end(&mut plaintext) {
            Ok(_) => Ok(()),
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => Ok(()),
            Err(err) => Err(err),
        }
        .map_err(|err| MonitorError::Network(format!("Read err: {err}")))?;

        let certificates = tls
            .conn
            .peer_certificates()
            .ok_or(MonitorError::Certificate("No certificates".into()))?
            .to_vec();

        Ok(certificates)
    }

    fn validate_certificate(
        &self,
        certificate_blob: &CertificateDer<'static>,
    ) -> Result<bool, MonitorError> {
        let cert = X509Certificate::from_der(certificate_blob)
            .map_err(|err| MonitorError::Certificate(err.to_string()))?;
        info!(
            "Certificate: nb {:?}, na {:?}",
            cert.validity_not_before(),
            cert.validity_not_after()
        );
        let required_expiry_date = self.now + chrono::Days::new(self.max_expiration);
        info!("Checking against date {:?}", &required_expiry_date);
        if self.now < cert.validity_not_before() {
            Err(MonitorError::Certificate("Certificate is before".into()))
        } else if self.now > cert.validity_not_after() {
            Err(MonitorError::Certificate("Certificate is after".into()))
        } else if required_expiry_date >= cert.validity_not_after() {
            Ok(false)
        } else {
            Ok(true)
        }
    }

    fn validate_certificates(
        &self,
        certificate_blobs: Vec<CertificateDer<'static>>,
    ) -> Result<bool, MonitorError> {
        if certificate_blobs.len() < 2 {
            return Err(MonitorError::Certificate("No certificates in chain".into()));
        }
        let mut result = false;
        for cert in certificate_blobs.iter() {
            result = result && self.validate_certificate(cert)?;
        }
        Ok(result)
    }

    pub fn validate_domain(&self, domain: &str) -> Result<bool, MonitorError> {
        info!("Validating with {} days", self.max_expiration);
        let certificate_blobs = self.read_certificates(domain)?;
        self.validate_certificates(certificate_blobs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{NaiveDateTime, TimeZone};
    use test_log::test;

    fn validator(max_expiration: u64) -> Validator {
        let ndt: NaiveDateTime = chrono::NaiveDate::from_ymd_opt(2024, 5, 1)
            .and_then(|d| d.and_hms_opt(0, 0, 0))
            .unwrap();
        let fake_now: DateTime<Utc> = Utc.from_utc_datetime(&ndt);
        Validator::new(fake_now, max_expiration)
    }

    #[test]
    fn test_read_certificates_network() {
        let validator = Validator::new(Utc::now(), 0);
        let res = validator.read_certificates("google.com");
        info!("{:?}", &res);
        assert!(res.is_ok());
        let cert_blobs = res.unwrap();
        assert!(cert_blobs.len() > 1);
        let vres = validator.validate_certificates(cert_blobs);
        assert!(vres.is_ok());
    }

    #[test]
    fn test_valid_date() {
        let cert_der =
            CertificateDer::from(Vec::<u8>::from(include_bytes!("./data/cert-2031.der")));
        let vres = validator(0).validate_certificate(&cert_der);
        assert!(vres.is_ok());
        assert!(vres.unwrap());
    }

    #[test]
    fn test_expired_date() {
        let cert_der =
            CertificateDer::from(Vec::<u8>::from(include_bytes!("./data/cert-expired.der")));
        let vres = validator(0).validate_certificate(&cert_der);
        assert!(vres.is_err());
    }

    #[test]
    fn test_validate_close_date() {
        let cert_der =
            CertificateDer::from(Vec::<u8>::from(include_bytes!("./data/cert-2031.der")));
        let vres = validator(3000).validate_certificate(&cert_der);
        assert!(vres.is_ok());
        assert!(!vres.unwrap());
    }

    #[test]
    fn test_expired_pair() {
        let certs_der = vec![
            CertificateDer::from(Vec::<u8>::from(include_bytes!("./data/cert-2031.der"))),
            CertificateDer::from(Vec::<u8>::from(include_bytes!("./data/cert-expired.der"))),
        ];
        let vres = validator(0).validate_certificates(certs_der);
        assert!(vres.is_ok());
        assert!(!vres.unwrap());
    }
}
