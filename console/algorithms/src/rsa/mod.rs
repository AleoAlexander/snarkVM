// Copyright (c) 2019-2025 Provable Inc.
// This file is part of the snarkVM library.

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:

// http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#[cfg(test)]
pub mod rsa_tests;

mod serialize;

use super::*;
use snarkvm_utilities::bytes_from_bits_le;

use ::rsa::{
    RsaPublicKey,
    pss::{Signature, VerifyingKey},
    sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256},
    signature::{SignatureEncoding, hazmat::PrehashVerifier},
};

#[derive(Clone, PartialEq, Eq)]
pub enum SHA2HashAlgorithm {
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha512_224,
    Sha512_256,
}

/// An RSA Signature
#[derive(Clone, PartialEq, Eq)]
pub struct RSASignature {
    pub signature: Signature,
}

impl RSASignature {
    /// Verify `(n,e)` against `verifying_key` using *your* hasher on `message`.
    pub fn verify<H: Hash<Output = Vec<bool>>>(
        &self,
        rsa_public_key: RsaPublicKey,
        hash_algorithm: &SHA2HashAlgorithm,
        hasher: &H,
        message: &[H::Input],
    ) -> Result<()> {
        // Hash the message.
        let hash_bits = hasher.hash(message)?;

        // Verify the signature using the prehash.
        self.verify_with_digest(rsa_public_key, hash_algorithm, &hash_bits)
    }

    /// Verify `(n,e)` against `verifying_key` using the provided `digest`.
    pub fn verify_with_digest(
        &self,
        rsa_public_key: RsaPublicKey,
        hash_algorithm: &SHA2HashAlgorithm,
        digest_bits: &[bool],
    ) -> Result<()> {
        // Convert the digest output to bytes.
        let digest = bytes_from_bits_le(digest_bits);

        match hash_algorithm {
            SHA2HashAlgorithm::Sha224 => {
                let verifying_key = VerifyingKey::<Sha224>::from(rsa_public_key);
                // Verify the signature using the prehash digest.
                verifying_key
                    .verify_prehash(&digest, &self.signature)
                    .map_err(|e| anyhow!("Failed to verify signature: {e:?}"))
            }
            SHA2HashAlgorithm::Sha256 => {
                let verifying_key = VerifyingKey::<Sha256>::from(rsa_public_key);
                // Verify the signature using the prehash digest.
                verifying_key
                    .verify_prehash(&digest, &self.signature)
                    .map_err(|e| anyhow!("Failed to verify signature: {e:?}"))
            }
            SHA2HashAlgorithm::Sha384 => {
                let verifying_key = VerifyingKey::<Sha384>::from(rsa_public_key);
                // Verify the signature using the prehash digest.
                verifying_key
                    .verify_prehash(&digest, &self.signature)
                    .map_err(|e| anyhow!("Failed to verify signature: {e:?}"))
            }
            SHA2HashAlgorithm::Sha512 => {
                let verifying_key = VerifyingKey::<Sha512>::from(rsa_public_key);
                // Verify the signature using the prehash digest.
                verifying_key
                    .verify_prehash(&digest, &self.signature)
                    .map_err(|e| anyhow!("Failed to verify signature: {e:?}"))
            }
            SHA2HashAlgorithm::Sha512_224 => {
                let verifying_key = VerifyingKey::<Sha512_224>::from(rsa_public_key);
                // Verify the signature using the prehash digest.
                verifying_key
                    .verify_prehash(&digest, &self.signature)
                    .map_err(|e| anyhow!("Failed to verify signature: {e:?}"))
            }
            SHA2HashAlgorithm::Sha512_256 => {
                let verifying_key = VerifyingKey::<Sha512_256>::from(rsa_public_key);
                // Verify the signature using the prehash digest.
                verifying_key
                    .verify_prehash(&digest, &self.signature)
                    .map_err(|e| anyhow!("Failed to verify signature: {e:?}"))
            }
        }
    }
}

impl ToBytes for RSASignature {
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Write the signature bytes.
        self.signature.to_bytes().to_vec().write_le(&mut writer)
    }
}

impl FromBytes for RSASignature {
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Read the signature bytes.
        let mut bytes = Vec::new();
        reader.read_to_end(&mut bytes)?;
        // Construct the signature from the bytes.
        let signature = Signature::try_from(&bytes[..]).map_err(error)?;

        Ok(Self { signature })
    }
}

impl FromStr for RSASignature {
    type Err = Error;

    /// Parses a hex-encoded string into an RSASignature.
    fn from_str(signature: &str) -> Result<Self, Self::Err> {
        let mut s = signature.trim();

        // Accept optional 0x prefix
        if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
            s = rest;
        }

        // Decode the hex string into bytes.
        let bytes = hex::decode(s)?;

        // Construct the signature from the bytes.
        Self::from_bytes_le(&bytes)
    }
}

impl Debug for RSASignature {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for RSASignature {
    /// Writes the signature as a hex string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode(self.to_bytes_le().map_err(|_| fmt::Error)?))
    }
}

#[cfg(test)]
mod test_helpers {
    use super::*;

    use ::rsa::{RsaPrivateKey, pss::BlindedSigningKey, signature::hazmat::RandomizedPrehashSigner};

    pub(crate) type DefaultHasher = Sha2_256;

    /// Samples a random RSA signature.
    pub(super) fn sample_rsa_signature<H: Hash<Output = Vec<bool>, Input = bool>>(
        num_bytes: usize,
        hasher: &H,
        rng: &mut TestRng,
        hash_algorithm: &SHA2HashAlgorithm,
        signature_size: usize,
    ) -> (RsaPrivateKey, Vec<u8>, RSASignature) {
        let private_key = RsaPrivateKey::new(rng, signature_size).expect("failed to generate a key");

        match hash_algorithm {
            SHA2HashAlgorithm::Sha224 => {
                let signing_key = BlindedSigningKey::<Sha224>::new(private_key.clone());
                // Sample a random message.
                let message: Vec<u8> = (0..num_bytes).map(|_| rng.r#gen()).collect::<Vec<_>>();

                //Hash the message
                let hash = hasher.hash(&message.to_bits_le()).unwrap();

                // Sign the message.
                let signature = signing_key.sign_prehash_with_rng(rng, &bytes_from_bits_le(&hash)).unwrap();
                let rsa_signature: RSASignature = RSASignature { signature };

                // Return the signing key, message, and signature.
                (private_key, message, rsa_signature)
            }
            SHA2HashAlgorithm::Sha256 => {
                let signing_key = BlindedSigningKey::<Sha256>::new(private_key.clone());
                let message: Vec<u8> = (0..num_bytes).map(|_| rng.r#gen()).collect::<Vec<_>>();
                let hash = hasher.hash(&message.to_bits_le()).unwrap();
                let signature = signing_key.sign_prehash_with_rng(rng, &bytes_from_bits_le(&hash)).unwrap();
                let rsa_signature: RSASignature = RSASignature { signature };

                // Return the signing key, message, and signature.
                (private_key, message, rsa_signature)
            }
            SHA2HashAlgorithm::Sha384 => {
                let signing_key = BlindedSigningKey::<Sha384>::new(private_key.clone());
                let message: Vec<u8> = (0..num_bytes).map(|_| rng.r#gen()).collect::<Vec<_>>();
                let hash = hasher.hash(&message.to_bits_le()).unwrap();
                let signature = signing_key.sign_prehash_with_rng(rng, &bytes_from_bits_le(&hash)).unwrap();
                let rsa_signature: RSASignature = RSASignature { signature };

                // Return the signing key, message, and signature.
                (private_key, message, rsa_signature)
            }
            SHA2HashAlgorithm::Sha512 => {
                let signing_key = BlindedSigningKey::<Sha512>::new(private_key.clone());
                let message: Vec<u8> = (0..num_bytes).map(|_| rng.r#gen()).collect::<Vec<_>>();
                let hash = hasher.hash(&message.to_bits_le()).unwrap();
                let signature = signing_key.sign_prehash_with_rng(rng, &bytes_from_bits_le(&hash)).unwrap();
                let rsa_signature: RSASignature = RSASignature { signature };

                // Return the signing key, message, and signature.
                (private_key, message, rsa_signature)
            }
            SHA2HashAlgorithm::Sha512_224 => {
                let signing_key = BlindedSigningKey::<Sha512_224>::new(private_key.clone());
                let message: Vec<u8> = (0..num_bytes).map(|_| rng.r#gen()).collect::<Vec<_>>();
                let hash = hasher.hash(&message.to_bits_le()).unwrap();
                let signature = signing_key.sign_prehash_with_rng(rng, &bytes_from_bits_le(&hash)).unwrap();
                let rsa_signature: RSASignature = RSASignature { signature };

                // Return the signing key, message, and signature.
                (private_key, message, rsa_signature)
            }
            SHA2HashAlgorithm::Sha512_256 => {
                let signing_key = BlindedSigningKey::<Sha512_256>::new(private_key.clone());
                let message: Vec<u8> = (0..num_bytes).map(|_| rng.r#gen()).collect::<Vec<_>>();
                let hash = hasher.hash(&message.to_bits_le()).unwrap();
                let signature = signing_key.sign_prehash_with_rng(rng, &bytes_from_bits_le(&hash)).unwrap();
                let rsa_signature: RSASignature = RSASignature { signature };

                // Return the signing key, message, and signature.
                (private_key, message, rsa_signature)
            }
        }
    }
}
