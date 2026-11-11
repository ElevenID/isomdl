//! Authorization of untrusted intermediate certificates for the supported chain walker.

use std::collections::BTreeSet;

use const_oid::AssociatedOid;
use x509_cert::{
    ext::pkix::{
        BasicConstraints, CertificatePolicies, ExtendedKeyUsage, InhibitAnyPolicy, KeyUsage,
        NameConstraints, PolicyConstraints, PolicyMappings, PrivateKeyUsagePeriod,
    },
    Certificate, Version,
};

/// RFC 5280 section 6.1.4 requires CA authorization, key usage and path-length checks
/// independently of the certificate's signature. This walker does not implement name,
/// policy or extended-key-usage constraint propagation, so it rejects those intermediate
/// extensions instead of silently ignoring their restrictions.
///
/// Explicit trust anchors are checked by the selected profile, not by this function.
pub(super) fn validate_intermediate(
    certificate: &Certificate,
    non_self_issued_ca_count_below: usize,
) -> Result<(), String> {
    let tbs = &certificate.tbs_certificate;
    if tbs.version != Version::V3 {
        return Err("untrusted intermediate must be a V3 CA certificate".to_string());
    }

    let mut seen = BTreeSet::new();
    for extension in tbs.extensions.iter().flatten() {
        if !seen.insert(extension.extn_id) {
            return Err(format!(
                "intermediate contains duplicate extension {}",
                extension.extn_id
            ));
        }
        let supported =
            extension.extn_id == BasicConstraints::OID || extension.extn_id == KeyUsage::OID;
        let unsupported_constraint = [
            NameConstraints::OID,
            CertificatePolicies::OID,
            PolicyMappings::OID,
            PolicyConstraints::OID,
            InhibitAnyPolicy::OID,
            ExtendedKeyUsage::OID,
            PrivateKeyUsagePeriod::OID,
        ]
        .contains(&extension.extn_id);
        if !supported && (extension.critical || unsupported_constraint) {
            return Err(format!(
                "intermediate contains unsupported constraint or critical extension {}",
                extension.extn_id
            ));
        }
    }

    let (_, constraints) = tbs
        .get::<BasicConstraints>()
        .map_err(|e| format!("intermediate BasicConstraints cannot be decoded: {e}"))?
        .ok_or_else(|| "intermediate requires BasicConstraints CA:true".to_string())?;
    if !constraints.ca {
        return Err("intermediate requires BasicConstraints CA:true".to_string());
    }
    if let Some(limit) = constraints.path_len_constraint {
        if non_self_issued_ca_count_below > usize::from(limit) {
            return Err(format!(
                "intermediate pathLenConstraint {limit} exceeded by \
                 {non_self_issued_ca_count_below} subordinate CAs"
            ));
        }
    }

    if let Some((_, usage)) = tbs
        .get::<KeyUsage>()
        .map_err(|e| format!("intermediate KeyUsage cannot be decoded: {e}"))?
    {
        if !usage.key_cert_sign() {
            return Err("intermediate KeyUsage does not permit keyCertSign".to_string());
        }
    }
    Ok(())
}
