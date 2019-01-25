use webpki;
use untrusted;
use sct;
use std;
use std::sync::Arc;

use crate::key::Certificate;
use crate::msgs::handshake::DigitallySignedStruct;
use crate::msgs::handshake::SCTList;
use crate::msgs::enums::SignatureScheme;
use crate::error::TLSError;
use crate::anchors::{DistinguishedNames, RootCertStore};
#[cfg(feature = "logging")]
use crate::log::{warn, debug};

type SignatureAlgorithms = &'static [&'static webpki::SignatureAlgorithm];

/// Which signature verification mechanisms we support.  No particular
/// order.
#[cfg(feature = "ecdsa")]
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[&webpki::ECDSA_P256_SHA256,
                                                   &webpki::ECDSA_P256_SHA384,
                                                   &webpki::ECDSA_P384_SHA256,
                                                   &webpki::ECDSA_P384_SHA384,
                                                   &webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                                                   &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                                                   &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                                                   &webpki::RSA_PKCS1_2048_8192_SHA256,
                                                   &webpki::RSA_PKCS1_2048_8192_SHA384,
                                                   &webpki::RSA_PKCS1_2048_8192_SHA512,
                                                   &webpki::RSA_PKCS1_3072_8192_SHA384];

#[cfg(not(feature = "ecdsa"))]
static SUPPORTED_SIG_ALGS: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY,
                                                   &webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY,
                                                   &webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY,
                                                   &webpki::RSA_PKCS1_2048_8192_SHA1,
                                                   &webpki::RSA_PKCS1_2048_8192_SHA256,
                                                   &webpki::RSA_PKCS1_2048_8192_SHA384,
                                                   &webpki::RSA_PKCS1_2048_8192_SHA512,
                                                   &webpki::RSA_PKCS1_3072_8192_SHA384];

/// Marker types.  These are used to bind the fact some verification
/// (certificate chain or handshake signature) has taken place into
/// protocol states.  We use this to have the compiler check that there
/// are no 'goto fail'-style elisions of important checks before we
/// reach the traffic stage.
///
/// These types are public, but cannot be directly constructed.  This
/// means their origins can be precisely determined by looking
/// for their `assertion` constructors.
pub struct HandshakeSignatureValid(());
impl HandshakeSignatureValid { pub fn assertion() -> Self { Self { 0: () } } }

pub struct FinishedMessageVerified(());
impl FinishedMessageVerified { pub fn assertion() -> Self { Self { 0: () } } }

/// Zero-sized marker type representing verification of a server cert chain.
pub struct ServerCertVerified(());
impl ServerCertVerified {
    /// Make a `ServerCertVerified`
    pub fn assertion() -> Self { Self { 0: () } }
}

/// Zero-sized marker type representing verification of a client cert chain.
pub struct ClientCertVerified(());
impl ClientCertVerified {
    /// Make a `ClientCertVerified`
    pub fn assertion() -> Self { Self { 0: () } }
}

/// Something that can verify a server certificate chain
pub trait ServerCertVerifier : Send + Sync {
    /// Verify a the certificate chain `presented_certs` against the roots
    /// configured in `roots`.  Make sure that `dns_name` is quoted by
    /// the top certificate in the chain.
    fn verify_server_cert(&self,
                          roots: &RootCertStore,
                          presented_certs: &[Certificate],
                          dns_name: webpki::DNSNameRef,
                          ocsp_response: &[u8]) -> Result<ServerCertVerified, TLSError>;
}

/// Something that can verify a client certificate chain
pub trait ClientCertVerifier : Send + Sync {
    /// Returns `true` to enable the server to request a client certificate and
    /// `false` to skip requesting a client certificate. Defaults to `true`.
    fn offer_client_auth(&self) -> bool { true }

    /// Returns `true` to require a client certificate and `false` to make client
    /// authentication optional. Defaults to `self.offer_client_auth()`.
    fn client_auth_mandatory(&self) -> bool { self.offer_client_auth() }

    /// Returns the subject names of the client authentication trust anchors to
    /// share with the client when requesting client authentication.
    fn client_auth_root_subjects(&self) -> DistinguishedNames;

    /// Verify a certificate chain `presented_certs` is rooted in `roots`.
    /// Does no further checking of the certificate.
    fn verify_client_cert(&self,
                          presented_certs: &[Certificate]) -> Result<ClientCertVerified, TLSError>;
}

/// WebPKIVerifier
pub struct WebPKIVerifier {
    /// time
    pub time: fn() -> Result<webpki::Time, TLSError>,
}

impl ServerCertVerifier for WebPKIVerifier {
    fn verify_server_cert(&self,
                          roots: &RootCertStore,
                          presented_certs: &[Certificate],
                          dns_name: webpki::DNSNameRef,
                          ocsp_response: &[u8]) -> Result<ServerCertVerified, TLSError> {
        let (cert, chain, trustroots) = prepare(roots, presented_certs)?;
        let now = (self.time)()?;
        let cert = cert.verify_is_valid_tls_server_cert(SUPPORTED_SIG_ALGS,
                &webpki::TLSServerTrustAnchors(&trustroots), &chain, now)
            .map_err(TLSError::WebPKIError)
            .map(|_| cert)?;

        if !ocsp_response.is_empty() {
            debug!("Unvalidated OCSP response: {:?}", ocsp_response.to_vec());
        }

        cert.verify_is_valid_for_dns_name(dns_name)
            .map_err(TLSError::WebPKIError)
            .map(|_| ServerCertVerified::assertion())
    }
}

impl WebPKIVerifier {
    /// new()
    pub fn new() -> WebPKIVerifier {
        WebPKIVerifier {
            time: try_now,
        }
    }
}

fn prepare<'a, 'b>(roots: &'b RootCertStore, presented_certs: &'a [Certificate])
                   -> Result<(webpki::EndEntityCert<'a>,
                              Vec<untrusted::Input<'a>>,
                              Vec<webpki::TrustAnchor<'b>>), TLSError> {
    if presented_certs.is_empty() {
        return Err(TLSError::NoCertificatesPresented);
    }

    // EE cert must appear first.
    let cert_der = untrusted::Input::from(&presented_certs[0].0);
    let cert =
        webpki::EndEntityCert::from(cert_der).map_err(TLSError::WebPKIError)?;

    let chain: Vec<untrusted::Input> = presented_certs.iter()
        .skip(1)
        .map(|cert| untrusted::Input::from(&cert.0))
        .collect();

    let trustroots: Vec<webpki::TrustAnchor> = roots.roots
        .iter()
        .map(|x| x.to_trust_anchor())
        .collect();

    Ok((cert, chain, trustroots))
}

fn try_now() -> Result<webpki::Time, TLSError> {
    webpki::Time::try_from(std::time::SystemTime::now())
        .map_err( |_ | TLSError::FailedToGetCurrentTime)
}

/// A `ClientCertVerifier` that will ensure that every client provides a trusted
/// certificate, without any name checking.
pub struct AllowAnyAuthenticatedClient {
    roots: RootCertStore,
}

impl AllowAnyAuthenticatedClient {
    /// Construct a new `AllowAnyAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    pub fn new(roots: RootCertStore) -> Arc<ClientCertVerifier> {
        Arc::new(AllowAnyAuthenticatedClient { roots })
    }
}

impl ClientCertVerifier for AllowAnyAuthenticatedClient {
    fn offer_client_auth(&self) -> bool { true }

    fn client_auth_mandatory(&self) -> bool { true }

    fn client_auth_root_subjects(&self) -> DistinguishedNames {
        self.roots.get_subjects()
    }

    fn verify_client_cert(&self, presented_certs: &[Certificate])
                          -> Result<ClientCertVerified, TLSError> {
        let (cert, chain, trustroots) = prepare(&self.roots, presented_certs)?;
        let now = try_now()?;
        cert.verify_is_valid_tls_client_cert(
                SUPPORTED_SIG_ALGS, &webpki::TLSClientTrustAnchors(&trustroots),
                &chain, now)
            .map_err(TLSError::WebPKIError)
            .map(|_| ClientCertVerified::assertion())
    }
}

/// A `ClientCertVerifier` that will allow both anonymous and authenticated
/// clients, without any name checking.
///
/// Client authentication will be requested during the TLS handshake. If the
/// client offers a certificate then this acts like
/// `AllowAnyAuthenticatedClient`, otherwise this acts like `NoClientAuth`.
pub struct AllowAnyAnonymousOrAuthenticatedClient {
    inner: AllowAnyAuthenticatedClient,
}

impl AllowAnyAnonymousOrAuthenticatedClient {
    /// Construct a new `AllowAnyAnonymousOrAuthenticatedClient`.
    ///
    /// `roots` is the list of trust anchors to use for certificate validation.
    pub fn new(roots: RootCertStore) -> Arc<ClientCertVerifier> {
        Arc::new(AllowAnyAnonymousOrAuthenticatedClient {
            inner: AllowAnyAuthenticatedClient { roots }
        })
    }
}

impl ClientCertVerifier for AllowAnyAnonymousOrAuthenticatedClient {
    fn offer_client_auth(&self) -> bool { self.inner.offer_client_auth() }

    fn client_auth_mandatory(&self) -> bool { false }

    fn client_auth_root_subjects(&self) -> DistinguishedNames {
        self.inner.client_auth_root_subjects()
    }

    fn verify_client_cert(&self, presented_certs: &[Certificate])
            -> Result<ClientCertVerified, TLSError> {
        self.inner.verify_client_cert(presented_certs)
    }
}

/// Turns off client authentication.
pub struct NoClientAuth;

impl NoClientAuth {
    /// Constructs a `NoClientAuth` and wraps it in an `Arc`.
    pub fn new() -> Arc<ClientCertVerifier> { Arc::new(NoClientAuth) }
}

impl ClientCertVerifier for NoClientAuth {
    fn offer_client_auth(&self) -> bool { false }

    fn client_auth_root_subjects(&self) -> DistinguishedNames {
        unimplemented!();
    }

    fn verify_client_cert(&self, _presented_certs: &[Certificate])
                          -> Result<ClientCertVerified, TLSError> {
        unimplemented!();
    }
}

#[cfg(feature = "ecdsa")]
static ECDSA_SHA256: SignatureAlgorithms = &[&webpki::ECDSA_P256_SHA256,
                                             &webpki::ECDSA_P384_SHA256];
#[cfg(feature = "ecdsa")]
static ECDSA_SHA384: SignatureAlgorithms = &[&webpki::ECDSA_P256_SHA384,
                                             &webpki::ECDSA_P384_SHA384];

static RSA_SHA256: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA256];
static RSA_SHA384: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA384];
static RSA_SHA512: SignatureAlgorithms = &[&webpki::RSA_PKCS1_2048_8192_SHA512];
static RSA_PSS_SHA256: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY];
static RSA_PSS_SHA384: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY];
static RSA_PSS_SHA512: SignatureAlgorithms = &[&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY];

fn convert_scheme(scheme: SignatureScheme) -> Result<SignatureAlgorithms, TLSError> {
    match scheme {
        // nb. for TLS1.2 the curve is not fixed by SignatureScheme.
        #[cfg(feature = "ecdsa")]
        SignatureScheme::ECDSA_NISTP256_SHA256 => Ok(ECDSA_SHA256),
        #[cfg(feature = "ecdsa")]
        SignatureScheme::ECDSA_NISTP384_SHA384 => Ok(ECDSA_SHA384),

        SignatureScheme::RSA_PKCS1_SHA256 => Ok(RSA_SHA256),
        SignatureScheme::RSA_PKCS1_SHA384 => Ok(RSA_SHA384),
        SignatureScheme::RSA_PKCS1_SHA512 => Ok(RSA_SHA512),

        SignatureScheme::RSA_PSS_SHA256 => Ok(RSA_PSS_SHA256),
        SignatureScheme::RSA_PSS_SHA384 => Ok(RSA_PSS_SHA384),
        SignatureScheme::RSA_PSS_SHA512 => Ok(RSA_PSS_SHA512),

        _ => {
            #[cfg(feature = "logging")]
            let error_msg = format!("received unadvertised sig scheme {:?}", scheme);
            #[cfg(not(feature = "logging"))]
            let error_msg = format!("received unadvertised sig scheme");
            Err(TLSError::PeerMisbehavedError(error_msg))
        }
    }
}

fn verify_sig_using_any_alg(cert: &webpki::EndEntityCert,
                            algs: SignatureAlgorithms,
                            message: &[u8],
                            sig: &[u8])
                            -> Result<(), webpki::Error> {
    // TLS doesn't itself give us enough info to map to a single webpki::SignatureAlgorithm.
    // Therefore, convert_algs maps to several and we try them all.
    for alg in algs {
        match cert.verify_signature(alg,
                                    untrusted::Input::from(message),
                                    untrusted::Input::from(sig)) {
            Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey) => continue,
            res => return res,
        }
    }

    Err(webpki::Error::UnsupportedSignatureAlgorithmForPublicKey)
}

/// Verify the signed `message` using the public key quoted in
/// `cert` and algorithm and signature in `dss`.
///
/// `cert` MUST have been authenticated before using this function,
/// typically using `verify_cert`.
pub fn verify_signed_struct(message: &[u8],
                            cert: &Certificate,
                            dss: &DigitallySignedStruct)
                            -> Result<HandshakeSignatureValid, TLSError> {

    let possible_algs = convert_scheme(dss.scheme)?;
    let cert_in = untrusted::Input::from(&cert.0);
    let cert = webpki::EndEntityCert::from(cert_in)
        .map_err(TLSError::WebPKIError)?;

    verify_sig_using_any_alg(&cert, possible_algs, message, &dss.sig.0)
        .map_err(TLSError::WebPKIError)
        .map(|_| HandshakeSignatureValid::assertion())
}

#[cfg(feature = "tls13")]
fn convert_alg_tls13(scheme: SignatureScheme)
                     -> Result<&'static webpki::SignatureAlgorithm, TLSError> {
    use crate::msgs::enums::SignatureScheme::*;

    match scheme {
        #[cfg(feature = "ecdsa")]
        ECDSA_NISTP256_SHA256 => Ok(&webpki::ECDSA_P256_SHA256),
        #[cfg(feature = "ecdsa")]
        ECDSA_NISTP384_SHA384 => Ok(&webpki::ECDSA_P384_SHA384),
        RSA_PSS_SHA256 => Ok(&webpki::RSA_PSS_2048_8192_SHA256_LEGACY_KEY),
        RSA_PSS_SHA384 => Ok(&webpki::RSA_PSS_2048_8192_SHA384_LEGACY_KEY),
        RSA_PSS_SHA512 => Ok(&webpki::RSA_PSS_2048_8192_SHA512_LEGACY_KEY),
        _ => {
            #[cfg(feature = "logging")]
            let error_msg = format!("received unsupported sig scheme {:?}", scheme);
            #[cfg(not(feature = "logging"))]
            let error_msg = format!("received unsupported sig scheme");
            Err(TLSError::PeerMisbehavedError(error_msg))
        }
    }
}

#[cfg(feature = "tls13")]
pub fn verify_tls13(cert: &Certificate,
                    dss: &DigitallySignedStruct,
                    handshake_hash: &[u8],
                    context_string_with_0: &[u8])
                    -> Result<HandshakeSignatureValid, TLSError> {
    let alg = convert_alg_tls13(dss.scheme)?;

    let mut msg = Vec::new();
    msg.resize(64, 0x20u8);
    msg.extend_from_slice(context_string_with_0);
    msg.extend_from_slice(handshake_hash);

    let cert_in = untrusted::Input::from(&cert.0);
    let cert = webpki::EndEntityCert::from(cert_in)
        .map_err(TLSError::WebPKIError)?;

    cert.verify_signature(alg,
                          untrusted::Input::from(&msg),
                          untrusted::Input::from(&dss.sig.0))
        .map_err(TLSError::WebPKIError)
        .map(|_| HandshakeSignatureValid::assertion())
}

fn unix_time_millis() -> Result<u64, TLSError> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|dur| dur.as_secs())
        .map_err(|_| TLSError::FailedToGetCurrentTime)
        .and_then(|secs| secs.checked_mul(1000)
                  .ok_or(TLSError::FailedToGetCurrentTime))
}

pub fn verify_scts(cert: &Certificate,
                   scts: &SCTList,
                   logs: &[&sct::Log]) -> Result<(), TLSError> {
    let mut valid_scts = 0;
    let now = unix_time_millis()?;
    let mut last_sct_error = None;

    for sct in scts {
        #[cfg_attr(not(feature = "logging"), allow(unused_variables))]
        match sct::verify_sct(&cert.0, &sct.0, now, logs) {
            Ok(index) => {
                debug!("Valid SCT signed by {} on {}",
                      logs[index].operated_by, logs[index].description);
                valid_scts += 1;
            }
            Err(e) => {
                if e.should_be_fatal() {
                    return Err(TLSError::InvalidSCT(e));
                }
                debug!("SCT ignored because {:?}", e);
                last_sct_error = Some(e);
            }
        }
    }

    /* If we were supplied with some logs, and some SCTs,
     * but couldn't verify any of them, fail the handshake. */
    if !logs.is_empty() && !scts.is_empty() && valid_scts == 0 {
        warn!("No valid SCTs provided");
        return Err(TLSError::InvalidSCT(last_sct_error.unwrap()));
    }

    Ok(())
}

#[cfg(feature = "sgx")]
pub mod sgx_verifier {
    use super::*;
    use crate::verify::{ServerCertVerifier, ServerCertVerified, try_now, SUPPORTED_SIG_ALGS};
    use crate::TLSError;
    use serde_json::{self, Value};
    use chrono::{DateTime, Duration};
    use webpki::Error;
    use ring::io::der;
    use sgx_types::{sgx_quote_t, sgx_measurement_t, sgx_report_body_t, sgx_report_data_t, sgx_attributes_t};
    use sgx_types::{SGX_FLAGS_DEBUG, SGX_HASH_SIZE, SGX_REPORT_DATA_SIZE};

    #[cfg(feature = "sgx")]
    use memoffset::offset_of;

    /// A builder structure used for creating an SgxVerifier
    pub struct SgxVerifierBuilder {
        mr_signer: [u8; 32],
        use_debug_launch: bool,
        allow_group_out_of_date: bool,
        allow_configuration_needed: bool,
        report_freshness_secs: i64,
    }

    impl SgxVerifierBuilder {

        /// Create a builder used for creating an SgxVerifier.
        ///
        /// # Examples
        /// ```
        /// let sgx_verifier = rustls::SgxVerifierBuilder::new(mr_signer_bytes)
        ///     .allow_configuration_needed()
        ///     .allow_group_out_of_date()
        ///     .finalize();
        /// let mut config = rustls::ClientConfig::new();
        /// config.dangerous().set_certificate_verifer(Arc::new(sgx_verifier));
        /// ```
        pub fn new(mr_signer: [u8; 32], debug_launch: bool) -> Self {
            SgxVerifierBuilder {
                mr_signer: mr_signer,
                use_debug_launch: debug_launch,
                allow_group_out_of_date: false,
                allow_configuration_needed: false,
                report_freshness_secs: 24*60*60, // 24 hrs
            }
        }

        /// Set the flag that it is OK to accept GROUP_OUT_OF_DATE
        pub fn allow_group_out_of_date(mut self) -> Self {
            self.allow_group_out_of_date = true;
            self
        }

        /// Set the flag that it is OK to accept CONFIGURATION_NEEDED
        pub fn allow_configuration_needed(mut self) -> Self {
            self.allow_configuration_needed = true;
            self
        }

        /// Set the seconds during which the attestation is accepted
        pub fn report_freshness_secs(mut self, secs: i64) -> Self {
            self.report_freshness_secs = secs;
            self
        }

        /// Create an SgxVerifier using the previously provided configuration
        pub fn finalize(self) -> SgxVerifier {
            SgxVerifier {
                time: try_now,
                mr_signer: self.mr_signer,
                use_debug_launch: self.use_debug_launch,
                allow_group_out_of_date: self.allow_group_out_of_date,
                allow_configuration_needed: self.allow_configuration_needed,
                report_freshness_secs: self.report_freshness_secs,
            }
        }
    }

    pub struct SgxVerifier {
        pub time: fn() -> Result<webpki::Time, TLSError>,
        mr_signer: [u8; 32],
        use_debug_launch: bool,
        allow_group_out_of_date: bool,
        allow_configuration_needed: bool,
        report_freshness_secs: i64,
    }

    impl ServerCertVerifier for SgxVerifier {
        fn verify_server_cert(&self,
                              _roots: &RootCertStore,
                              presented_certs: &[Certificate],
                              _dns_name: webpki::DNSNameRef,
                              _ocsp_response: &[u8]) -> Result<ServerCertVerified, TLSError> {
            let cert_der = untrusted::Input::from(&presented_certs[0].0);
            let cert = webpki::EndEntityCert::from(cert_der).map_err(TLSError::WebPKIError)?;
            let now = (self.time)()?;
            cert.verify_is_valid_sgx_attestation_report(SUPPORTED_SIG_ALGS, now, |cert, input| {
                let report_bytes = input.as_slice_less_safe();
                let report: Value = serde_json::from_slice(report_bytes)
                                    .map_err(|_| Error::ExtensionValueInvalid)?;

                // 1. Extract timestamp, quote_status, and quote_body from the attestation report
                let (timestamp, quote_status, quote_body) = match (
                    &report["timestamp"],
                    &report["isvEnclaveQuoteStatus"],
                    &report["isvEnclaveQuoteBody"],
                ) {
                    (Value::String(time), Value::String(quote_status), Value::String(quote_body))
                        => {
                        (time, quote_status, quote_body)
                    }
                    _ => return Err(Error::ExtensionValueInvalid),
                };

                // 2. Verify if the timestamp is fresh
                let timestamp = timestamp.clone() + "+0000";
                let not_before = DateTime::parse_from_str(&timestamp, "%Y-%m-%dT%H:%M:%S%.f%z")
                    .map_err(|_| Error::BadDER)?;
                let not_after = not_before
                    .clone()
                    .checked_add_signed(Duration::seconds(self.report_freshness_secs))
                    .ok_or(Error::BadDER)?;

                let not_before = webpki::Time::from_seconds_since_unix_epoch(not_before.timestamp() as u64);
                let not_after = webpki::Time::from_seconds_since_unix_epoch(not_after.timestamp() as u64);
                if now < not_before {
                    return Err(Error::CertNotValidYet);
                }
                if now > not_after {
                    return Err(Error::CertExpired);
                }

                // 3. Verify the quote status
                match quote_status.as_ref() {
                    "OK" => (),
                    "GROUP_OUT_OF_DATE" if self.allow_group_out_of_date => (),
                    "CONFIGURATION_NEEDED" if self.allow_configuration_needed => (),
                    _ => return Err(Error::NameConstraintViolation),
                }

                // 4. Continue to decode the quote body
                let quote_bytes = base64::decode(&quote_body).map_err(|_| Error::BadDER)?;

                // 5. Check if MR_SIGNER matches
                let mr_signer_offset = offset_of!(sgx_quote_t, report_body)
                                     + offset_of!(sgx_report_body_t, mr_signer)
                                     + offset_of!(sgx_measurement_t, m);
                if self.mr_signer != quote_bytes[mr_signer_offset..mr_signer_offset + SGX_HASH_SIZE] {
                    return Err(Error::CertNotValidForName);
                }

                // 6. Check the DEBUG_LAUNCH flag
                let sgx_flag_offset = offset_of!(sgx_quote_t, report_body)
                                    + offset_of!(sgx_report_body_t, attributes)
                                    + offset_of!(sgx_attributes_t, flags);
                let mut flag_u8_array = [0u8; 8];
                flag_u8_array.copy_from_slice(&quote_bytes[sgx_flag_offset..sgx_flag_offset + 8]);
                let is_debug_launch = SGX_FLAGS_DEBUG & u64::from_le_bytes(flag_u8_array) != 0;
                if self.use_debug_launch != is_debug_launch {
                    return Err(Error::ExtensionValueInvalid);
                }

                // 7.  Check if the public key matches
                let pub_key_offset = offset_of!(sgx_quote_t, report_body)
                                   + offset_of!(sgx_report_body_t, report_data)
                                   + offset_of!(sgx_report_data_t, d);
                let cert_pub_key = cert.spki.read_all(Error::BadDER, |input| {
                    let _ = der::expect_tag_and_get_value(input, der::Tag::Sequence).map_err(|_| Error::BadDER)?;
                    let pub_key_input = der::bit_string_with_no_unused_bits(input).map_err(|_| Error::BadDER)?;
                    Ok(pub_key_input)
                }).map_err(|_| Error::BadDER)?;
                let cert_pub_key_bytes = &cert_pub_key.as_slice_less_safe()[1..]; // skip the 0x04 tag byte
                if *cert_pub_key_bytes != quote_bytes[pub_key_offset..pub_key_offset + SGX_REPORT_DATA_SIZE] {
                    return Err(Error::InvalidCertValidity);
                }

                Ok(())
            })
                .map_err(TLSError::WebPKIError)
                .map(|_| ServerCertVerified::assertion())
        }
    }
}
