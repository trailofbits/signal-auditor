use ed25519_dalek::VerifyingKey as Ed25519PublicKey;
use ed25519_dalek::SigningKey as Ed25519SigningKey;
use ed25519_dalek::{Signer};


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

pub struct PublicConfig {
    pub mode: DeploymentMode,
    pub sig_key: Ed25519PublicKey,
    pub vrf_key: Ed25519PublicKey, // Signal uses Ed25519 ECVRF
}

pub struct Auditor {
    config: PublicConfig,
    key: Ed25519SigningKey,
}

impl Auditor {
    pub fn new(config: PublicConfig, key: Ed25519SigningKey) -> Self {
        Self { config, key}
    }

    pub fn sign_at_time(&self, head: Hash, size: u64, time: u64) -> Result<Vec<u8>, String> {
        let config = &self.config;
        let mut msg = Vec::new();
        msg.extend_from_slice(&[0, 0]); //Ciphersuite
        msg.extend_from_slice(&[config.mode.into()]); // Audit mode

        let vk_len: u16 = config.sig_key.as_bytes().len()
                .try_into().map_err(|_| "signing key too long")?;

        msg.extend_from_slice(&vk_len.to_be_bytes());
        msg.extend_from_slice(config.sig_key.as_bytes());

        let vrf_len: u16 = config.vrf_key.as_bytes().len()
                .try_into().map_err(|_| "vrf key too long")?;

        msg.extend_from_slice(&vrf_len.to_be_bytes());
        msg.extend_from_slice(config.vrf_key.as_bytes());

        if config.mode == DeploymentMode::ThirdPartyAuditing {
            let key_len: u16 = self.key.verifying_key().as_bytes().len()
                .try_into().map_err(|_| "audit key too long")?;

            msg.extend_from_slice(&key_len.to_be_bytes());
            msg.extend_from_slice(self.key.verifying_key().as_bytes());
        }

        msg.extend_from_slice(&size.to_be_bytes());

        msg.extend_from_slice(&time.to_be_bytes());

        msg.extend_from_slice(head.as_slice());

        let sig = self.key.try_sign(&msg).map_err(|_| "failed to sign")?;
        Ok(sig.to_vec())
    }

    pub fn sign_head(&self, head: Hash, size: u64) -> Result<Vec<u8>, String> {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.sign_at_time(head, size, ts)
    }
}