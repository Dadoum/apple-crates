mod constants;

use crate::{ActivationSignature, ActivationSigner, activation::sign_sha1};
use constants::{CERTIFICATE_AUTHORITY_CHAIN, IDENTITIES, PUBLIC_EXPONENT};
use rsa::{
    BigUint, RsaPrivateKey,
    rand_core::{OsRng, RngCore},
};

/// Signs activation requests using the embedded Windows activation identities.
pub struct WindowsActivationSigner {
    private_key: RsaPrivateKey,
    certificate_chain: Vec<u8>,
}

impl WindowsActivationSigner {
    /// Selects one of the ten identities, as Apple's Windows client does.
    pub fn new() -> Self {
        let identity = &IDENTITIES[OsRng.next_u32() as usize % IDENTITIES.len()];
        let private_key = RsaPrivateKey::from_p_q(
            BigUint::from_bytes_be(&identity.p),
            BigUint::from_bytes_be(&identity.q),
            PUBLIC_EXPONENT.into(),
        )
        .expect("embedded activation primes must form a valid RSA key");
        let mut certificate_chain =
            Vec::with_capacity(identity.certificate.len() + CERTIFICATE_AUTHORITY_CHAIN.len());
        certificate_chain.extend_from_slice(identity.certificate);
        certificate_chain.extend_from_slice(CERTIFICATE_AUTHORITY_CHAIN);
        Self {
            private_key,
            certificate_chain,
        }
    }
}

impl Default for WindowsActivationSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl ActivationSigner for WindowsActivationSigner {
    type Error = rsa::Error;

    fn sign(&self, xml: &[u8]) -> Result<ActivationSignature, Self::Error> {
        Ok(ActivationSignature {
            signature: sign_sha1(&self.private_key, xml)?,
            certificate_chain: self.certificate_chain.clone(),
        })
    }
}
