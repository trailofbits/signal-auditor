#[cfg(feature = "kms-gcp")]
mod kms;

#[cfg(not(feature = "kms-gcp"))]
mod local;

#[cfg(feature = "kms-gcp")]
pub use kms::*;

#[cfg(not(feature = "kms-gcp"))]
pub use local::*;

use crate::Hash;
use ed25519_dalek::VerifyingKey;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DeploymentMode {
    ContactMonitoring,
    ThirdPartyManagement,
    ThirdPartyAuditing,
}

impl From<DeploymentMode> for u8 {
    fn from(mode: DeploymentMode) -> u8 {
        match mode {
            DeploymentMode::ContactMonitoring => 1,
            DeploymentMode::ThirdPartyManagement => 2,
            DeploymentMode::ThirdPartyAuditing => 3,
        }
    }
}

impl TryFrom<u8> for DeploymentMode {
    type Error = u8;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(DeploymentMode::ContactMonitoring),
            2 => Ok(DeploymentMode::ThirdPartyManagement),
            3 => Ok(DeploymentMode::ThirdPartyAuditing),
            _ => Err(value),
        }
    }
}

/// Static public configuration for the transparency log.
pub struct PublicConfig {
    pub mode: DeploymentMode,
    /// The Ed25519 signing public key owned by the log operator.
    pub sig_key: VerifyingKey,
    /// The Ed25519 ECVRF public key owned by the log operator.
    pub vrf_key: VerifyingKey,
    /// The Ed25519 signing public key owned by the auditor.
    pub auditor_key: VerifyingKey,
}

impl PublicConfig {
    /// Encode a log head for signing at a given time.
    fn encode_at_time(&self, head: Hash, size: u64, time: i64) -> Vec<u8> {
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0, 0]); //Ciphersuite
        msg.extend_from_slice(&[self.mode.into()]); // Audit mode

        let vk_len: u16 = self.sig_key.as_bytes().len() as u16;

        msg.extend_from_slice(&vk_len.to_be_bytes());
        msg.extend_from_slice(self.sig_key.as_bytes());

        let vrf_len: u16 = self.vrf_key.as_bytes().len() as u16;

        msg.extend_from_slice(&vrf_len.to_be_bytes());
        msg.extend_from_slice(self.vrf_key.as_bytes());

        if self.mode == DeploymentMode::ThirdPartyAuditing {
            let key_len: u16 = self.auditor_key.as_bytes().len() as u16;

            msg.extend_from_slice(&key_len.to_be_bytes());
            msg.extend_from_slice(self.auditor_key.as_bytes());
        }

        msg.extend_from_slice(&size.to_be_bytes());

        msg.extend_from_slice(&time.to_be_bytes());

        msg.extend_from_slice(head.as_slice());

        msg
    }
}
