//! The Auditor module implements the signing functionality
//! for a third party auditor.
//!
//! Log tracking is not included in this module

use crate::proto::transparency::AuditorTreeHead;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::VerifyingKey as Ed25519PublicKey;

use crate::Hash;
use std::time::{SystemTime, UNIX_EPOCH};

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
    pub sig_key: Ed25519PublicKey,
    /// The Ed25519 ECVRF public key owned by the log operator.
    pub vrf_key: Ed25519PublicKey, // Signal uses Ed25519 ECVRF
}

/// `Auditor` holds a signing key and a public configuration.
pub struct Auditor {
    pub config: PublicConfig,
    pub key: Ed25519SigningKey,
}

impl Auditor {
    pub fn new(config: PublicConfig, key: Ed25519SigningKey) -> Self {
        Self { config, key }
    }

    /// Sign a log head at a given time.
    pub fn sign_at_time(&self, head: Hash, size: u64, time: i64) -> AuditorTreeHead {
        let config = &self.config;
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0, 0]); //Ciphersuite
        msg.extend_from_slice(&[config.mode.into()]); // Audit mode

        let vk_len: u16 = config.sig_key.as_bytes().len() as u16;

        msg.extend_from_slice(&vk_len.to_be_bytes());
        msg.extend_from_slice(config.sig_key.as_bytes());

        let vrf_len: u16 = config.vrf_key.as_bytes().len() as u16;

        msg.extend_from_slice(&vrf_len.to_be_bytes());
        msg.extend_from_slice(config.vrf_key.as_bytes());

        if config.mode == DeploymentMode::ThirdPartyAuditing {
            let key_len: u16 = self.key.verifying_key().as_bytes().len() as u16;

            msg.extend_from_slice(&key_len.to_be_bytes());
            msg.extend_from_slice(self.key.verifying_key().as_bytes());
        }

        msg.extend_from_slice(&size.to_be_bytes());

        msg.extend_from_slice(&time.to_be_bytes());

        msg.extend_from_slice(head.as_slice());

        let sig = self.key.sign(&msg);

        AuditorTreeHead {
            tree_size: size,
            signature: sig.to_vec(),
            timestamp: time,
        }
    }

    /// Sign a log head at the current time.
    pub fn sign_head(&self, head: Hash, size: u64) -> AuditorTreeHead {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis();
        self.sign_at_time(head, size, ts as i64)
    }
}
