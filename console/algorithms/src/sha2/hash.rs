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

use super::*;
use snarkvm_utilities::{bits_from_bytes_le, bytes_from_bits_le};

use sha2::{Digest, Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};

impl<const VARIANT: usize, const TRUNCATION: usize> Hash for SHA2<VARIANT, TRUNCATION> {
    type Input = bool;
    type Output = Vec<bool>;

    /// Returns the SHA2 hash of the given input as bits.
    #[inline]
    fn hash(&self, input: &[Self::Input]) -> Result<Self::Output> {
        let result = match (VARIANT, TRUNCATION) {
            (224, 0) => bits_from_bytes_le(&sha2_224_native(&bytes_from_bits_le(input))).collect(),
            (256, 0) => bits_from_bytes_le(&sha2_256_native(&bytes_from_bits_le(input))).collect(),
            (384, 0) => bits_from_bytes_le(&sha2_384_native(&bytes_from_bits_le(input))).collect(),
            (512, 0) => bits_from_bytes_le(&sha2_512_native(&bytes_from_bits_le(input))).collect(),
            (512, 224) => bits_from_bytes_le(&sha2_512_224_native(&bytes_from_bits_le(input))).collect(),
            (512, 256) => bits_from_bytes_le(&sha2_512_256_native(&bytes_from_bits_le(input))).collect(),
            _ => unreachable!("Invalid SHA2 variant"),
        };
        Ok(result)
    }
}

/// Computes the SHA2-224 hash of the given preimage as bytes.
fn sha2_224_native(preimage: &[u8]) -> [u8; 28] {
    // create a Sha224 object
    let mut sha224 = Sha224::new();
    // write input message
    sha224.update(preimage);
    //Try casting in array of 28 bytes (should work even though size is "not known at compile time" because hash output is always fixed size)
    let hash: [u8; 28] = sha224.finalize()[..].try_into().expect("Error casting to result");
    hash
}

/// Computes the SHA2-256 hash of the given preimage as bytes.
fn sha2_256_native(preimage: &[u8]) -> [u8; 32] {
    // create a Sha256 object
    let mut sha256 = Sha256::new();
    // write input message
    sha256.update(preimage);
    //Try casting in array of 32 bytes (should work even though size is "not known at compile time" because hash output is always fixed size)
    let hash: [u8; 32] = sha256.finalize()[..].try_into().expect("Error casting to result");
    hash
}

/// Computes the SHA2-384 hash of the given preimage as bytes.
fn sha2_384_native(preimage: &[u8]) -> [u8; 48] {
    // create a Sha384 object
    let mut sha384 = Sha384::new();
    // write input message
    sha384.update(preimage);
    //Try casting in array of 48 bytes (should work even though size is "not known at compile time" because hash output is always fixed size)
    let hash: [u8; 48] = sha384.finalize()[..].try_into().expect("Error casting to result");
    hash
}

/// Computes the SHA2-512 hash of the given preimage as bytes.
fn sha2_512_native(preimage: &[u8]) -> [u8; 64] {
    // create a Sha512 object
    let mut sha512 = Sha512::new();
    // write input message
    sha512.update(preimage);
    //Try casting in array of 64 bytes (should work even though size is "not known at compile time" because hash output is always fixed size)
    let hash: [u8; 64] = sha512.finalize()[..].try_into().expect("Error casting to result");
    hash
}

/// Computes the SHA2-512_224 hash of the given preimage as bytes.
fn sha2_512_224_native(preimage: &[u8]) -> [u8; 28] {
    // create a Sha512_224 object
    let mut sha512_224 = Sha512_224::new();
    // write input message
    sha512_224.update(preimage);
    //Try casting in array of 28 bytes (should work even though size is "not known at compile time" because hash output is always fixed size)
    let hash: [u8; 28] = sha512_224.finalize()[..].try_into().expect("Error casting to result");
    hash
}

/// Computes the SHA2-512_256 hash of the given preimage as bytes.
fn sha2_512_256_native(preimage: &[u8]) -> [u8; 32] {
    // create a Sha512_224 object
    let mut sha512_256 = Sha512_256::new();
    // write input message
    sha512_256.update(preimage);
    //Try casting in array of 32 bytes (should work even though size is "not known at compile time" because hash output is always fixed size)
    let hash: [u8; 32] = sha512_256.finalize()[..].try_into().expect("Error casting to result");
    hash
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Rng;
    use snarkvm_utilities::{bits_from_bytes_le, bytes_from_bits_le};

    macro_rules! check_equivalence {
        ($console:expr, $native:expr) => {
            let rng = &mut TestRng::default();

            let mut input_sizes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 32, 64, 128, 256, 512, 1024];
            input_sizes.extend((0..100).map(|_| rng.gen_range(1..1024)));

            for num_inputs in input_sizes {
                println!("Checking equivalence for {num_inputs} inputs");

                // Prepare the preimage.
                let input = (0..num_inputs).map(|_| Uniform::rand(rng)).collect::<Vec<bool>>();

                // Compute the native hash.
                let expected = $native(&bytes_from_bits_le(&input));
                let expected = bits_from_bytes_le(&expected).collect::<Vec<_>>();

                // Compute the console hash.
                let candidate = $console.hash(&input).unwrap();
                assert_eq!(expected, candidate);
            }
        };
    }

    #[test]
    fn test_sha_224_equivalence() {
        check_equivalence!(Sha2_224::default(), sha2_224_native);
    }

    #[test]
    fn test_sha_256_equivalence() {
        check_equivalence!(Sha2_256::default(), sha2_256_native);
    }

    #[test]
    fn test_sha_384_equivalence() {
        check_equivalence!(Sha2_384::default(), sha2_384_native);
    }

    #[test]
    fn test_sha_512_equivalence() {
        check_equivalence!(Sha2_512::default(), sha2_512_native);
    }
    #[test]
    fn test_sha_512_224_equivalence() {
        check_equivalence!(Sha2_512_224::default(), sha2_512_224_native);
    }
    #[test]
    fn test_sha_512_256_equivalence() {
        check_equivalence!(Sha2_512_256::default(), sha2_512_256_native);
    }
}
