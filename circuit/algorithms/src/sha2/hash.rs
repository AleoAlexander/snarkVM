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

impl<E: Environment, const TYPE: u8, const VARIANT: usize> Hash for Sha2<E, TYPE, VARIANT> {
    type Input = Boolean<E>;
    type Output = Vec<Boolean<E>>;

    /// Returns the Keccak hash of the given input as bits.
    #[inline]
    fn hash(&self, input: &[Self::Input]) -> Self::Output {
        // Ensure the input is not empty.
        if input.is_empty() {
            E::halt("The input to the hash function must not be empty")
        }
        // The padded blocks
        let padded_blocks = Self::pad_sha2(input);

        match TYPE {
            SHA256_ID => {
                let h_array = self.sha256_initial_hash_values.clone().expect("e");
                let mut h0 = h_array[0].clone();
                let mut h1 = h_array[1].clone();
                let mut h2 = h_array[2].clone();
                let mut h3 = h_array[3].clone();
                let mut h4 = h_array[4].clone();
                let mut h5 = h_array[5].clone();
                let mut h6 = h_array[6].clone();
                let mut h7 = h_array[7].clone();

                let k = self.sha256_round_constants.clone().expect("error");

                for block in padded_blocks {
                    // Initalize message schedule
                    let mut w = vec![];
                    //Convert block into sixteen 32-bit words
                    for word in block.chunks(32) {
                        w.push(U32::from_bits_be(word))
                    }
                    // Resize w to include forty eight additional 32-bit words, each initialized to zero
                    w.resize(64, U32::constant(console::U32::new(0)));

                    for i in 16..64 {
                        let s0 = Self::rotate_right_u32(&w[i - 15], 7)
                            ^ Self::rotate_right_u32(&w[i - 15], 18)
                            ^ Self::shift_right_u32(&w[i - 15], 3);
                        let s1 = Self::rotate_right_u32(&w[i - 2], 17)
                            ^ Self::rotate_right_u32(&w[i - 2], 19)
                            ^ Self::shift_right_u32(&w[i - 2], 10);
                        w[i] = w[i - 16].add_wrapped(&s0).add_wrapped(&w[i - 7]).add_wrapped(&s1);
                    }

                    //Initialize working variables to current hash value:
                    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = [
                        h0.clone(),
                        h1.clone(),
                        h2.clone(),
                        h3.clone(),
                        h4.clone(),
                        h5.clone(),
                        h6.clone(),
                        h7.clone(),
                    ];

                    // Compression function main loop:
                    for i in 0..64 {
                        let sigma1 = Self::rotate_right_u32(&e, 6)
                            ^ Self::rotate_right_u32(&e, 11)
                            ^ Self::rotate_right_u32(&e, 25);
                        let ch = (&e & &f) ^ ((!&e) & &g);
                        let temp1 = h.add_wrapped(&sigma1).add_wrapped(&ch).add_wrapped(&k[i]).add_wrapped(&w[i]);
                        let sigma0 = Self::rotate_right_u32(&a, 2)
                            ^ Self::rotate_right_u32(&a, 13)
                            ^ Self::rotate_right_u32(&a, 22);
                        let maj = (&a & &b) ^ (&a & &c) ^ (&b & &c);
                        let temp2 = sigma0.add_wrapped(&maj);

                        h = g;
                        g = f;
                        f = e;
                        e = d.add_wrapped(&temp1);
                        d = c;
                        c = b;
                        b = a;
                        a = temp1.add_wrapped(&temp2);
                    }

                    h0 = h0.add_wrapped(&a);
                    h1 = h1.add_wrapped(&b);
                    h2 = h2.add_wrapped(&c);
                    h3 = h3.add_wrapped(&d);
                    h4 = h4.add_wrapped(&e);
                    h5 = h5.add_wrapped(&f);
                    h6 = h6.add_wrapped(&g);
                    h7 = h7.add_wrapped(&h);
                }

                let mut digest = h0.to_bits_be();
                digest.append(&mut h1.to_bits_be());
                digest.append(&mut h2.to_bits_be());
                digest.append(&mut h3.to_bits_be());
                digest.append(&mut h4.to_bits_be());
                digest.append(&mut h5.to_bits_be());
                digest.append(&mut h6.to_bits_be());
                match VARIANT {
                    224 => {}
                    256 => {
                        digest.append(&mut h7.to_bits_be());
                    }
                    _ => {
                        self::panic!("Error: invalid SHA function type")
                    }
                }
                digest
            }
            SHA512_ID => {
                let h_array = self.sha512_initial_hash_values.clone().expect("e");
                let mut h0 = h_array[0].clone();
                let mut h1 = h_array[1].clone();
                let mut h2 = h_array[2].clone();
                let mut h3 = h_array[3].clone();
                let mut h4 = h_array[4].clone();
                let mut h5 = h_array[5].clone();
                let mut h6 = h_array[6].clone();
                let mut h7 = h_array[7].clone();

                let k = self.sha512_round_constants.clone().expect("error");

                for block in padded_blocks {
                    // Initalize message schedule
                    let mut w = vec![];
                    //Convert block into sixteen 64-bit words
                    for word in block.chunks(64) {
                        w.push(U64::from_bits_be(word))
                    }
                    // Resize w to include sixty four additional 32-bit words, each initialized to zero
                    w.resize(80, U64::constant(console::U64::new(0)));

                    for i in 16..80 {
                        let s0 = Self::rotate_right_u64(&w[i - 15], 1)
                            ^ Self::rotate_right_u64(&w[i - 15], 8)
                            ^ Self::shift_right_u64(&w[i - 15], 7);
                        let s1 = Self::rotate_right_u64(&w[i - 2], 19)
                            ^ Self::rotate_right_u64(&w[i - 2], 61)
                            ^ Self::shift_right_u64(&w[i - 2], 6);
                        w[i] = w[i - 16].add_wrapped(&s0).add_wrapped(&w[i - 7]).add_wrapped(&s1);
                    }

                    //Initialize working variables to current hash value:
                    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = [
                        h0.clone(),
                        h1.clone(),
                        h2.clone(),
                        h3.clone(),
                        h4.clone(),
                        h5.clone(),
                        h6.clone(),
                        h7.clone(),
                    ];

                    // Compression function main loop:
                    for i in 0..80 {
                        let sigma1 = Self::rotate_right_u64(&e, 14)
                            ^ Self::rotate_right_u64(&e, 18)
                            ^ Self::rotate_right_u64(&e, 41);
                        let ch = (&e & &f) ^ ((!&e) & &g);
                        let temp1 = h.add_wrapped(&sigma1).add_wrapped(&ch).add_wrapped(&k[i]).add_wrapped(&w[i]);
                        let sigma0 = Self::rotate_right_u64(&a, 28)
                            ^ Self::rotate_right_u64(&a, 34)
                            ^ Self::rotate_right_u64(&a, 39);
                        let maj = (&a & &b) ^ (&a & &c) ^ (&b & &c);
                        let temp2 = sigma0.add_wrapped(&maj);

                        h = g;
                        g = f;
                        f = e;
                        e = d.add_wrapped(&temp1);
                        d = c;
                        c = b;
                        b = a;
                        a = temp1.add_wrapped(&temp2);
                    }

                    h0 = h0.add_wrapped(&a);
                    h1 = h1.add_wrapped(&b);
                    h2 = h2.add_wrapped(&c);
                    h3 = h3.add_wrapped(&d);
                    h4 = h4.add_wrapped(&e);
                    h5 = h5.add_wrapped(&f);
                    h6 = h6.add_wrapped(&g);
                    h7 = h7.add_wrapped(&h);
                }

                let mut digest = h0.to_bits_be();
                digest.append(&mut h1.to_bits_be());
                digest.append(&mut h2.to_bits_be());
                digest.append(&mut h3.to_bits_be());
                digest.append(&mut h4.to_bits_be());
                digest.append(&mut h5.to_bits_be());
                match VARIANT {
                    384 => {}
                    512 => {
                        digest.append(&mut h6.to_bits_be());
                        digest.append(&mut h7.to_bits_be());
                    }
                    224 => {
                        digest.append(&mut h6.to_bits_be());
                        digest.append(&mut h7.to_bits_be());
                        digest.truncate(224);
                    }
                    256 => {
                        digest.append(&mut h6.to_bits_be());
                        digest.append(&mut h7.to_bits_be());
                        digest.truncate(256);
                    }

                    _ => {
                        self::panic!("Error: invalid SHA function type")
                    }
                }
                digest
            }
            _ => {
                self::panic!("Error: invalid SHA function type")
            }
        }
    }
}

impl<E: Environment, const TYPE: u8, const VARIANT: usize> Sha2<E, TYPE, VARIANT> {
    fn pad_sha2(input: &[Boolean<E>]) -> Vec<Vec<Boolean<E>>> {
        match TYPE {
            SHA256_ID => Self::pad_sha256(input),
            SHA512_ID => Self::pad_sha512(input),
            _ => {
                self::panic!("Invalid SHA2 function type")
            }
        }
    }

    fn pad_sha256(input: &[Boolean<E>]) -> Vec<Vec<Boolean<E>>> {
        let mut input_vec = input.to_vec();

        // Resize the input to a multiple of 8.
        let length_delta = input.len().div_ceil(8) * 8 - input.len();
        let mut padded_input: Vec<Boolean<E>> = vec![Boolean::constant(false); length_delta];
        padded_input.append(&mut input_vec);

        let message_length: u128 = padded_input.len() as u128;

        // Step 1: Append the bit "1" to the message.
        padded_input.push(Boolean::constant(true));

        // Step 2: Append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 64) is a multiple of 512
        while ((padded_input.len() + 64) % 512) != 0 {
            padded_input.push(Boolean::constant(false));
        }
        // Step 3: Append L as a 64-bit big-endian integer
        for i in (0..u64::BITS).rev() {
            // Iterate for the number of bits in u64
            let bit = (message_length >> i) & 1; // Shift right and mask to get the i-th bit
            match bit {
                0 => {
                    padded_input.push(Boolean::constant(false));
                }
                1 => {
                    padded_input.push(Boolean::constant(true));
                }
                _ => {
                    self::panic!("Bit shifting error");
                }
            }
        }

        // Construct the padded blocks.
        let mut result = Vec::new();
        for block in padded_input.chunks(512) {
            result.push(block.to_vec());
        }
        result
    }

    fn pad_sha512(input: &[Boolean<E>]) -> Vec<Vec<Boolean<E>>> {
        let mut input_vec = input.to_vec();

        // Resize the input to a multiple of 8.
        let length_delta = input.len().div_ceil(8) * 8 - input.len();
        let mut padded_input: Vec<Boolean<E>> = vec![Boolean::constant(false); length_delta];
        padded_input.append(&mut input_vec);

        let message_length: u128 = padded_input.len() as u128;

        // Step 1: Append the bit "1" to the message.
        padded_input.push(Boolean::constant(true));

        // Step 2: Append K '0' bits, where K is the minimum number >= 0 such that (L + 1 + K + 128) is a multiple of 1024
        while ((padded_input.len() + 128) % 1024) != 0 {
            padded_input.push(Boolean::constant(false));
        }

        // Step 3: Append L as a 128-bit big-endian integer
        for i in (0..u128::BITS).rev() {
            // Iterate for the number of bits in u128
            let bit = (message_length >> i) & 1; // Shift right and mask to get the i-th bit
            match bit {
                0 => {
                    padded_input.push(Boolean::constant(false));
                }
                1 => {
                    padded_input.push(Boolean::constant(true));
                }
                _ => {
                    self::panic!("Bit shifting error");
                }
            }
        }

        // Construct the padded blocks.
        let mut result = Vec::new();
        for block in padded_input.chunks(1024) {
            result.push(block.to_vec());
        }
        result
    }

    /// Performs a rotate right operation on the given `u32` value.
    fn rotate_right_u32(value: &U32<E>, n: usize) -> U32<E> {
        // Perform the rotation.
        let mut bits_be = value.to_bits_be();
        bits_be.rotate_right(n);
        // Return the rotated value.
        U32::from_bits_be(&bits_be)
    }

    /// Performs a shift right operation on the given `u32` value.
    fn shift_right_u32(value: &U32<E>, n: usize) -> U32<E> {
        // Perform the shift.
        let mut bits_be = value.to_bits_be();
        assert!(n < bits_be.len());
        // Trunacate the bits that would be removed by a shift
        bits_be.truncate(bits_be.len() - n);
        // Initialize a vector of zeros
        let mut shifted = vec![Boolean::constant(false); n];
        // Append shifted initial vector to the vector of zeros
        shifted.append(&mut bits_be);
        // Return the shifted value.
        U32::from_bits_be(&shifted)
    }

    /// Performs a rotate right operation on the given `u64` value.
    fn rotate_right_u64(value: &U64<E>, n: usize) -> U64<E> {
        // Perform the rotation.
        let mut bits_be = value.to_bits_be();
        bits_be.rotate_right(n);
        // Return the rotated value.
        U64::from_bits_be(&bits_be)
    }

    /// Performs a shift right operation on the given `u64` value.
    fn shift_right_u64(value: &U64<E>, n: usize) -> U64<E> {
        // Perform the shift.
        let mut bits_be = value.to_bits_be();
        assert!(n < bits_be.len());
        // Trunacate the bits that would be removed by a shift
        bits_be.truncate(bits_be.len() - n);
        // Initialize a vector of zeros
        let mut shifted = vec![Boolean::constant(false); n];
        // Append shifted initial vector to the vector of zeros
        shifted.append(&mut bits_be);
        // Return the shifted value.
        U64::from_bits_be(&shifted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::Rng;
    use snarkvm_circuit_types::environment::Circuit;

    const ITERATIONS: usize = 3;

    macro_rules! check_equivalence {
        ($console:expr, $circuit:expr) => {
            use console::Hash as H;

            let rng = &mut TestRng::default();

            let mut input_sizes = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 16, 32, 64, 128, 256, 512, 1024];
            input_sizes.extend((0..5).map(|_| rng.gen_range(1..1024)));

            for num_inputs in input_sizes {
                println!("Checking equivalence for {num_inputs} inputs");

                // Prepare the preimage.

                // let native_input = bits_from_bytes_be(&bytes_from_bits_be(&(0..num_inputs).map(|_| Uniform::rand(rng)).collect::<Vec<bool>>())).collect::<Vec<bool>>();
                let native_input = (0..num_inputs).map(|_| Uniform::rand(rng)).collect::<Vec<bool>>();
                let input = native_input.iter().map(|v| Boolean::<Circuit>::new(Mode::Private, *v)).collect::<Vec<_>>();

                // Compute the console hash.
                let expected = $console.hash(&native_input).expect("Failed to hash console input");

                // Compute the circuit hash.
                let candidate = $circuit.hash(&input);
                assert_eq!(expected, candidate.eject_value());
                Circuit::reset();
            }
        };
    }

    fn check_hash(
        mode: Mode,
        num_inputs: usize,
        num_constants: u64,
        num_public: u64,
        num_private: u64,
        num_constraints: u64,
        rng: &mut TestRng,
    ) {
        use console::Hash as H;

        let native = console::Sha2_256::default();
        let sha2_256 = Sha2_256::<Circuit>::new();

        for i in 0..ITERATIONS {
            // Prepare the preimage.  It's necessary to have a byte-aligned input, or else the output will differ between the circuit and the native hash
            //let native_input = bits_from_bytes_be(&bytes_from_bits_be(&(0..num_inputs).map(|_| Uniform::rand(rng)).collect::<Vec<bool>>())).collect::<Vec<bool>>();
            let native_input = (0..num_inputs).map(|_| Uniform::rand(rng)).collect::<Vec<bool>>();
            let input = native_input.iter().map(|v| Boolean::<Circuit>::new(mode, *v)).collect::<Vec<_>>();

            // Compute the native hash.
            let expected = native.hash(&native_input).expect("Failed to hash native input");

            // Compute the circuit hash.
            Circuit::scope(format!("Sha2 {mode} {i}"), || {
                let candidate = sha2_256.hash(&input);
                assert_eq!(expected, candidate.eject_value());
                let case = format!("(mode = {mode}, num_inputs = {num_inputs})");
                assert_scope!(case, num_constants, num_public, num_private, num_constraints);
            });
            Circuit::reset();
        }
    }

    #[test]
    fn test_sha2_hash_constant() {
        let mut rng = TestRng::default();

        check_hash(Mode::Constant, 1, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 2, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 3, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 4, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 5, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 6, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 7, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 8, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 16, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 32, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 64, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 128, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 256, 19232, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 511, 38464, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 512, 38464, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 513, 38464, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 1023, 57696, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 1024, 57696, 0, 0, 0, &mut rng);
        check_hash(Mode::Constant, 1025, 57696, 0, 0, 0, &mut rng);
    }

    #[test]
    fn test_sha2_hash_public() {
        let mut rng = TestRng::default();

        check_hash(Mode::Public, 1, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Public, 2, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Public, 3, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Public, 4, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Public, 5, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Public, 6, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Public, 7, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Public, 8, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Public, 16, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Public, 32, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Public, 64, 736, 0, 47440, 48018, &mut rng);
        check_hash(Mode::Public, 128, 608, 0, 47694, 48276, &mut rng);
        check_hash(Mode::Public, 256, 384, 0, 48169, 48758, &mut rng);
        check_hash(Mode::Public, 512, 4800, 0, 88620, 89672, &mut rng);
        check_hash(Mode::Public, 1024, 4832, 0, 138516, 140168, &mut rng);
    }

    #[test]
    fn test_sha2_hash_private() {
        let mut rng = TestRng::default();

        check_hash(Mode::Private, 1, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Private, 2, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Private, 3, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Private, 4, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Private, 5, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Private, 6, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Private, 7, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Private, 8, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Private, 16, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Private, 32, 992, 0, 46770, 47340, &mut rng);
        check_hash(Mode::Private, 64, 736, 0, 47440, 48018, &mut rng);
        check_hash(Mode::Private, 128, 608, 0, 47694, 48276, &mut rng);
        check_hash(Mode::Private, 256, 384, 0, 48169, 48758, &mut rng);
        check_hash(Mode::Private, 512, 4800, 0, 88620, 89672, &mut rng);
        check_hash(Mode::Private, 1024, 4832, 0, 138516, 140168, &mut rng);
    }

    #[test]
    fn test_sha2_224_equivalence() {
        check_equivalence!(console::Sha2_224::default(), Sha2_224::<Circuit>::new());
    }

    #[test]
    fn test_sha2_256_equivalence() {
        check_equivalence!(console::Sha2_256::default(), Sha2_256::<Circuit>::new());
    }

    #[test]
    fn test_sha2_384_equivalence() {
        check_equivalence!(console::Sha2_384::default(), Sha2_384::<Circuit>::new());
    }

    #[test]
    fn test_sha2_512_equivalence() {
        check_equivalence!(console::Sha2_512::default(), Sha2_512::<Circuit>::new());
    }

    #[test]
    fn test_sha2_512_224_equivalence() {
        check_equivalence!(console::Sha2_512_224::default(), Sha2_512_224::<Circuit>::new());
    }

    #[test]
    fn test_sha2_512_256_equivalence() {
        check_equivalence!(console::Sha2_512_256::default(), Sha2_512_256::<Circuit>::new());
    }
}
