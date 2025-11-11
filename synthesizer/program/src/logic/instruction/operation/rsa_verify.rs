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

use crate::{Opcode, Operand, RegistersCircuit, RegistersTrait, StackTrait};
use console::{
    algorithms::{RSASignature, SHA2HashAlgorithm, Sha2_224, Sha2_256, Sha2_384, Sha2_512, Sha2_512_224, Sha2_512_256},
    network::prelude::*,
    program::{Boolean, Literal, LiteralType, PlaintextType, Register, RegisterType, Value},
};
use rsa::{BigUint, RsaPublicKey};
use snarkvm_utilities::{bits_from_bytes_be, bytes_from_bits_le, bytes_switch_endianness};

/// The RSA signature verification instruction using SHA-224.
pub type RSAVerifySha2_224<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_224 as u8 }>;
/// The RSA signature verification instruction using SHA-224 with raw inputs.
pub type RSAVerifySha2_224Raw<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_224Raw as u8 }>;
/// The RSA signature verification instruction using a precomputed SHA-224 digest.
pub type RSAVerifySha2_224Digest<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_224Digest as u8 }>;

/// The RSA signature verification instruction using SHA-256.
pub type RSAVerifySha2_256<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_256 as u8 }>;
/// The RSA signature verification instruction using SHA-256 with raw inputs.
pub type RSAVerifySha2_256Raw<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_256Raw as u8 }>;
/// The RSA signature verification instruction using a precomputed SHA-224 digest.
pub type RSAVerifySha2_256Digest<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_256Digest as u8 }>;

/// The RSA signature verification instruction using SHA-384.
pub type RSAVerifySha2_384<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_384 as u8 }>;
/// The RSA signature verification instruction using SHA-384 with raw inputs.
pub type RSAVerifySha2_384Raw<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_384Raw as u8 }>;
/// The RSA signature verification instruction using a precomputed SHA-224 digest.
pub type RSAVerifySha2_384Digest<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_384Digest as u8 }>;

/// The RSA signature verification instruction using SHA-512.
pub type RSAVerifySha2_512<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_512 as u8 }>;
/// The RSA signature verification instruction using SHA-512 with raw inputs.
pub type RSAVerifySha2_512Raw<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_512Raw as u8 }>;
/// The RSA signature verification instruction using a precomputed SHA-224 digest.
pub type RSAVerifySha2_512Digest<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_512Digest as u8 }>;

/// The RSA signature verification instruction using SHA-512_224.
pub type RSAVerifySha2_512_224<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_512_224 as u8 }>;
/// The RSA signature verification instruction using SHA-512_224 with raw inputs.
pub type RSAVerifySha2_512_224Raw<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_512_224Raw as u8 }>;
/// The RSA signature verification instruction using a precomputed SHA-224 digest.
pub type RSAVerifySha2_512_224Digest<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_512_224Digest as u8 }>;

/// The RSA signature verification instruction using SHA-512_256.
pub type RSAVerifySha2_512_256<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_512_256 as u8 }>;
/// The RSA signature verification instruction using SHA-512_256 with raw inputs.
pub type RSAVerifySha2_512_256Raw<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_512_256Raw as u8 }>;
/// The RSA signature verification instruction using a precomputed SHA-224 digest.
pub type RSAVerifySha2_512_256Digest<N> = RSAVerify<N, { RSAVerifyVariant::HashSha2_512_256Digest as u8 }>;

/// Which hash function to use.
#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RSAVerifyVariant {
    HashSha2_224,
    HashSha2_224Raw,
    HashSha2_224Digest,
    HashSha2_256,
    HashSha2_256Raw,
    HashSha2_256Digest,
    HashSha2_384,
    HashSha2_384Raw,
    HashSha2_384Digest,
    HashSha2_512,
    HashSha2_512Raw,
    HashSha2_512Digest,
    HashSha2_512_224,
    HashSha2_512_224Raw,
    HashSha2_512_224Digest,
    HashSha2_512_256,
    HashSha2_512_256Raw,
    HashSha2_512_256Digest,
}

impl RSAVerifyVariant {
    // Initializes a new `RSAVerifyVariant`.
    pub const fn new(variant: u8) -> Self {
        match variant {
            0 => Self::HashSha2_224,
            1 => Self::HashSha2_224Raw,
            2 => Self::HashSha2_224Digest,
            3 => Self::HashSha2_256,
            4 => Self::HashSha2_256Raw,
            5 => Self::HashSha2_256Digest,
            6 => Self::HashSha2_384,
            7 => Self::HashSha2_384Raw,
            8 => Self::HashSha2_384Digest,
            9 => Self::HashSha2_512,
            10 => Self::HashSha2_512Raw,
            11 => Self::HashSha2_512Digest,
            12 => Self::HashSha2_512_224,
            13 => Self::HashSha2_512_224Raw,
            14 => Self::HashSha2_512_224Digest,
            15 => Self::HashSha2_512_256,
            16 => Self::HashSha2_512_256Raw,
            17 => Self::HashSha2_512_256Digest,
            _ => panic!("Invalid 'rsa.verify' instruction opcode"),
        }
    }

    // Returns the opcode associated with the variant.
    pub const fn opcode(&self) -> &'static str {
        match self {
            Self::HashSha2_224 => "rsa.verify.sha2_224",
            Self::HashSha2_224Raw => "rsa.verify.sha2_224.raw",
            Self::HashSha2_224Digest => "rsa.verify.sha2_224.digest",
            Self::HashSha2_256 => "rsa.verify.sha2_256",
            Self::HashSha2_256Raw => "rsa.verify.sha2_256.raw",
            Self::HashSha2_256Digest => "rsa.verify.sha2_256.digest",
            Self::HashSha2_384 => "rsa.verify.sha2_384",
            Self::HashSha2_384Raw => "rsa.verify.sha2_384.raw",
            Self::HashSha2_384Digest => "rsa.verify.sha2_384.digest",
            Self::HashSha2_512 => "rsa.verify.sha2_512.raw",
            Self::HashSha2_512Raw => "rsa.verify.sha2_512.raw",
            Self::HashSha2_512Digest => "rsa.verify.sha2_512.digest",
            Self::HashSha2_512_224 => "rsa.verify.sha2_512_224.raw",
            Self::HashSha2_512_224Raw => "rsa.verify.sha2_512_224.raw",
            Self::HashSha2_512_224Digest => "rsa.verify.sha2_512_224.digest",
            Self::HashSha2_512_256 => "rsa.verify.sha2_512_256",
            Self::HashSha2_512_256Raw => "rsa.verify.sha2_512_256.raw",
            Self::HashSha2_512_256Digest => "rsa.verify.sha2_512_256.digest",
        }
    }

    // Returns true if the variant requires byte alignment.
    pub const fn requires_byte_alignment(&self) -> bool {
        match self {
            Self::HashSha2_224 => false,
            Self::HashSha2_224Raw => false,
            Self::HashSha2_224Digest => true,
            Self::HashSha2_256 => false,
            Self::HashSha2_256Raw => false,
            Self::HashSha2_256Digest => true,
            Self::HashSha2_384 => false,
            Self::HashSha2_384Raw => false,
            Self::HashSha2_384Digest => true,
            Self::HashSha2_512 => false,
            Self::HashSha2_512Raw => false,
            Self::HashSha2_512Digest => true,
            Self::HashSha2_512_224 => false,
            Self::HashSha2_512_224Raw => false,
            Self::HashSha2_512_224Digest => true,
            Self::HashSha2_512_256 => false,
            Self::HashSha2_512_256Raw => false,
            Self::HashSha2_512_256Digest => true,
        }
    }

    // Returns `true` if the variant uses raw bits.
    pub const fn is_raw(&self) -> bool {
        match self {
            Self::HashSha2_224 => false,
            Self::HashSha2_224Raw => true,
            Self::HashSha2_224Digest => true,
            Self::HashSha2_256 => false,
            Self::HashSha2_256Raw => true,
            Self::HashSha2_256Digest => true,
            Self::HashSha2_384 => false,
            Self::HashSha2_384Raw => true,
            Self::HashSha2_384Digest => true,
            Self::HashSha2_512 => false,
            Self::HashSha2_512Raw => true,
            Self::HashSha2_512Digest => true,
            Self::HashSha2_512_224 => false,
            Self::HashSha2_512_224Raw => true,
            Self::HashSha2_512_224Digest => true,
            Self::HashSha2_512_256 => false,
            Self::HashSha2_512_256Raw => true,
            Self::HashSha2_512_256Digest => true,
        }
    }
}

/// Computes whether `signature` is valid for the given `address` and `message`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RSAVerify<N: Network, const VARIANT: u8> {
    /// The operands.
    operands: Vec<Operand<N>>,
    /// The destination register.
    destination: Register<N>,
}

impl<N: Network, const VARIANT: u8> RSAVerify<N, VARIANT> {
    /// Initializes a new `rsa.verify` instruction.
    #[inline]
    pub fn new(operands: Vec<Operand<N>>, destination: Register<N>) -> Result<Self> {
        // Sanity check the number of operands.
        ensure!(operands.len() == 4, "Instruction '{}' must have four operands", Self::opcode());
        // Return the instruction.
        Ok(Self { operands, destination })
    }

    /// Returns the opcode.
    #[inline]
    pub const fn opcode() -> Opcode {
        Opcode::RSA(RSAVerifyVariant::new(VARIANT).opcode())
    }

    /// Returns the operands in the operation.
    #[inline]
    pub fn operands(&self) -> &[Operand<N>] {
        // Sanity check that there are exactly three operands.
        debug_assert!(self.operands.len() == 4, "Instruction '{}' must have four operands", Self::opcode());
        // Return the operands.
        &self.operands
    }

    /// Returns the destination register.
    #[inline]
    pub fn destinations(&self) -> Vec<Register<N>> {
        vec![self.destination.clone()]
    }
}

// Perform the RSA verification based on the variant.
#[rustfmt::skip]
macro_rules! do_rsa_verification {
    ($variant: expr, $signature: expr, $pubkey_modulus: expr, $pubkey_exponent: expr, $message: expr) => {{
        let bits = || bits_from_bytes_be(&bytes_switch_endianness(&bytes_from_bits_le(&$message.to_bits_le())).collect::<Vec<u8>>()).collect::<Vec<bool>>();
        let bits_raw = || bits_from_bytes_be(&bytes_switch_endianness(&bytes_from_bits_le(&$message.to_bits_raw_le())).collect::<Vec<u8>>()).collect::<Vec<bool>>();

        let n = BigUint::from_bytes_le(&bytes_from_bits_le(&$pubkey_modulus.to_bits_raw_le()));
        let e = BigUint::from_bytes_le(&bytes_from_bits_le(&$pubkey_exponent.to_bits_raw_le()));

        let pub_key = RsaPublicKey::new(n,e).expect("Error casting to RsaPublicKey");

        let signature_bytes = bytes_from_bits_le(&$signature.to_bits_raw_le());
        let rsa_signature = RSASignature::from_bytes_le(&signature_bytes)?;

        let output = match $variant {
            RSAVerifyVariant::HashSha2_224 => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha224, &Sha2_224::default(), &bits(), None),
            RSAVerifyVariant::HashSha2_224Raw => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha224, &Sha2_224::default(), &bits_raw(), None),
            RSAVerifyVariant::HashSha2_224Digest => rsa_signature.verify_with_digest(&pub_key, &SHA2HashAlgorithm::Sha224 ,&bits_raw(), None),
            RSAVerifyVariant::HashSha2_256 => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha256, &Sha2_256::default(), &bits(), None),
            RSAVerifyVariant::HashSha2_256Raw => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha256, &Sha2_256::default(), &bits_raw(), None),
            RSAVerifyVariant::HashSha2_256Digest => rsa_signature.verify_with_digest(&pub_key, &SHA2HashAlgorithm::Sha256 ,&bits_raw(), None),
            RSAVerifyVariant::HashSha2_384 => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha384, &Sha2_384::default(), &bits(), None),
            RSAVerifyVariant::HashSha2_384Raw => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha384, &Sha2_384::default(), &bits_raw(), None),
            RSAVerifyVariant::HashSha2_384Digest => rsa_signature.verify_with_digest(&pub_key, &SHA2HashAlgorithm::Sha384 ,&bits_raw(), None),
            RSAVerifyVariant::HashSha2_512 => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha512, &Sha2_512::default(), &bits(), None),
            RSAVerifyVariant::HashSha2_512Raw => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha512, &Sha2_512::default(), &bits_raw(), None),
            RSAVerifyVariant::HashSha2_512Digest => rsa_signature.verify_with_digest(&pub_key, &SHA2HashAlgorithm::Sha512 ,&bits_raw(), None),
            RSAVerifyVariant::HashSha2_512_224 => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha512_224, &Sha2_512_224::default(), &bits(), None),
            RSAVerifyVariant::HashSha2_512_224Raw => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha512_224, &Sha2_512_224::default(), &bits_raw(), None),
            RSAVerifyVariant::HashSha2_512_224Digest => rsa_signature.verify_with_digest(&pub_key, &SHA2HashAlgorithm::Sha512_224 ,&bits_raw(), None),
            RSAVerifyVariant::HashSha2_512_256 => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha512_256, &Sha2_512_256::default(), &bits(), None),
            RSAVerifyVariant::HashSha2_512_256Raw => rsa_signature.verify(&pub_key, &SHA2HashAlgorithm::Sha512_256, &Sha2_512_256::default(), &bits_raw(), None),
            RSAVerifyVariant::HashSha2_512_256Digest => rsa_signature.verify_with_digest(&pub_key, &SHA2HashAlgorithm::Sha512_256 ,&bits_raw(), None),
        };

        output.is_ok()
    }};
}

/// Evaluate an RSA verification operation.
///
/// This allows running the verification without the machinery of stacks and registers.
/// This is necessary for the Leo interpreter.
pub fn evaluate_rsa_verification<N: Network>(
    variant: RSAVerifyVariant,
    signature: &Value<N>,
    public_key_modulus: &Value<N>,
    public_key_exponent: &Value<N>,
    message: &Value<N>,
) -> Result<bool> {
    evaluate_rsa_verification_internal(variant, signature, public_key_modulus, public_key_exponent, message)
}

fn evaluate_rsa_verification_internal<N: Network>(
    variant: RSAVerifyVariant,
    signature: &Value<N>,
    public_key_modulus: &Value<N>,
    public_key_exponent: &Value<N>,
    message: &Value<N>,
) -> Result<bool> {
    Ok(do_rsa_verification!(variant, signature, public_key_modulus, public_key_exponent, message))
}

impl<N: Network, const VARIANT: u8> RSAVerify<N, VARIANT> {
    /// Evaluates the instruction.
    #[inline]
    pub fn evaluate(&self, _stack: &impl StackTrait<N>, _registers: &mut impl RegistersTrait<N>) -> Result<()> {
        bail!("Instruction '{}' is currently only supported in finalize", Self::opcode());
    }

    /// Executes the instruction.
    #[inline]
    pub fn execute<A: circuit::Aleo<Network = N>>(
        &self,
        _stack: &impl StackTrait<N>,
        _registers: &mut impl RegistersCircuit<N, A>,
    ) -> Result<()> {
        bail!("Instruction '{}' is currently only supported in finalize", Self::opcode());
    }

    /// Finalizes the instruction.
    #[inline]
    pub fn finalize(&self, stack: &impl StackTrait<N>, registers: &mut impl RegistersTrait<N>) -> Result<()> {
        // Ensure the number of operands is correct.
        if self.operands.len() != 3 {
            bail!("Instruction '{}' expects 4 operands, found {} operands", Self::opcode(), self.operands.len())
        }

        // Retrieve the inputs.
        // Note: There is no need to check the types here, as this is done in `output_types`.
        let signature = registers.load(stack, &self.operands[0])?;
        let public_key_modulus = registers.load(stack, &self.operands[1])?;
        let public_key_exponent = registers.load(stack, &self.operands[2])?;
        let message = registers.load(stack, &self.operands[3])?;

        // Perform the verification.
        let output = evaluate_rsa_verification_internal(
            RSAVerifyVariant::new(VARIANT),
            &signature,
            &public_key_modulus,
            &public_key_exponent,
            &message,
        )?;
        let output = Literal::Boolean(Boolean::new(output));

        // Store the output.
        registers.store_literal(stack, &self.destination, output)
    }

    /// Returns the output type from the given program and input types.
    #[inline]
    pub fn output_types(
        &self,
        _stack: &impl StackTrait<N>,
        input_types: &[RegisterType<N>],
    ) -> Result<Vec<RegisterType<N>>> {
        // Ensure the number of input types is correct.
        if input_types.len() != 4 {
            bail!("Instruction '{}' expects 4 inputs, found {} inputs", Self::opcode(), input_types.len())
        }

        // Public Key size should either be array of same size as modulus, or just assume that its u8?

        // Enforce that both the signature and modulus inputs is an array of either 256-bytes (2048 bits), 384-bytes (3072 bits), or 512-bytes (4096 bits).
        match &input_types[0] {
            RegisterType::Plaintext(PlaintextType::Array(array_type)) => {
                if array_type.base_element_type() == &PlaintextType::Literal(LiteralType::U8)
                    && (**array_type.length() as usize == 32)
                {
                    match &input_types[1] {
                        RegisterType::Plaintext(PlaintextType::Array(array_type))
                            if array_type.base_element_type() == &PlaintextType::Literal(LiteralType::U8)
                                && (**array_type.length() as usize == 32) =>
                        {
                            // Valid Signature and Modulus
                        }
                        _ => bail!(
                            "Instruction '{}' expects the first input size to match the second input size. Found inputs of type '{}' and '{}'",
                            Self::opcode(),
                            input_types[0],
                            input_types[1]
                        ),
                    }
                } else if array_type.base_element_type() == &PlaintextType::Literal(LiteralType::U8)
                    && (**array_type.length() as usize == 48)
                {
                    match &input_types[1] {
                        RegisterType::Plaintext(PlaintextType::Array(array_type))
                            if array_type.base_element_type() == &PlaintextType::Literal(LiteralType::U8)
                                && (**array_type.length() as usize == 48) =>
                        {
                            // Valid Signature and Modulus
                        }
                        _ => bail!(
                            "Instruction '{}' expects the first input size to match the second input size. Found inputs of type '{}' and '{}'",
                            Self::opcode(),
                            input_types[0],
                            input_types[1]
                        ),
                    }
                } else if array_type.base_element_type() == &PlaintextType::Literal(LiteralType::U8)
                    && (**array_type.length() as usize == 64)
                {
                    match &input_types[1] {
                        RegisterType::Plaintext(PlaintextType::Array(array_type))
                            if array_type.base_element_type() == &PlaintextType::Literal(LiteralType::U8)
                                && (**array_type.length() as usize == 64) =>
                        {
                            // Valid Signature and Modulus
                        }
                        _ => bail!(
                            "Instruction '{}' expects the first input size to match the second input size. Found inputs of type '{}' and '{}'",
                            Self::opcode(),
                            input_types[0],
                            input_types[1]
                        ),
                    }
                } else {
                    bail!(
                        "Instruction '{}' expects the input size to be a 256-byte, 384-byte, or 512-byte array, and the first input size match the second input size. Found inputs of type '{}' and '{}'",
                        Self::opcode(),
                        input_types[0],
                        input_types[1]
                    )
                }
            }
            _ => bail!(
                "Instruction '{}' expects the first input to be a 256-byte, 384-byte, or 512-byte array. Found input of type '{}'",
                Self::opcode(),
                input_types[0]
            ),
        }

        // Get the variant.
        let variant = RSAVerifyVariant::new(VARIANT);

        // If the variant uses a precomputed digest, ensure the message is a matches the output size of the corresponding hash function.
        if matches!(
            variant,
            RSAVerifyVariant::HashSha2_224Digest
                | RSAVerifyVariant::HashSha2_256Digest
                | RSAVerifyVariant::HashSha2_384Digest
                | RSAVerifyVariant::HashSha2_512_224Digest
                | RSAVerifyVariant::HashSha2_512_256Digest
        ) {
            // Expected byte length for the digest input.
            let expected_message_length: usize = match variant {
                RSAVerifyVariant::HashSha2_224Digest => 28,
                RSAVerifyVariant::HashSha2_256Digest => 32,
                RSAVerifyVariant::HashSha2_384Digest => 48,
                RSAVerifyVariant::HashSha2_512Digest => 64,
                RSAVerifyVariant::HashSha2_512_224Digest => 28,
                RSAVerifyVariant::HashSha2_512_256Digest => 32,
                _ => {
                    bail!("Unreachable error: RSA variant matching")
                }
            };

            match &input_types[3] {
                RegisterType::Plaintext(PlaintextType::Array(array_type))
                    if array_type.base_element_type() == &PlaintextType::Literal(LiteralType::U8)
                        && expected_message_length == **array_type.length() as usize => {}

                invalid_input_type => bail!(
                    "Instruction '{}' expects the third input to be a {}-byte array. Found '{}'",
                    Self::opcode(),
                    expected_message_length,
                    invalid_input_type
                ),
            }
        }
        // // Otherwise if the variant needs to be byte aligned, check that its size in bits is a multiple of 8.
        // else if variant.requires_byte_alignment() {
        //     // A helper to get a struct declaration.
        //     let get_struct = |identifier: &Identifier<N>| stack.program().get_struct(identifier).cloned();

        //     // A helper to get a record declaration.
        //     let get_record = |identifier: &Identifier<N>| stack.program().get_record(identifier).cloned();

        //     // A helper to get an external record declaration.
        //     let get_external_record = |locator: &Locator<N>| {
        //         stack.get_external_stack(locator.program_id())?.program().get_record(locator.resource()).cloned()
        //     };

        //     // A helper to get the argument types of a future.
        //     let get_future = |locator: &Locator<N>| {
        //         Ok(match stack.program_id() == locator.program_id() {
        //             true => stack
        //                 .program()
        //                 .get_function_ref(locator.resource())?
        //                 .finalize_logic()
        //                 .ok_or_else(|| anyhow!("'{locator}' does not have a finalize scope"))?
        //                 .input_types(),
        //             false => stack
        //                 .get_external_stack(locator.program_id())?
        //                 .program()
        //                 .get_function_ref(locator.resource())?
        //                 .finalize_logic()
        //                 .ok_or_else(|| anyhow!("Failed to find function '{locator}'"))?
        //                 .input_types(),
        //         })
        //     };

        //     // Get the size in bits of the message.
        //     let size_in_bits = match variant.is_raw() {
        //         false => input_types[3].size_in_bits(&get_struct, &get_record, &get_external_record, &get_future)?,
        //         true => input_types[3].size_in_bits_raw(&get_struct, &get_record, &get_external_record, &get_future)?,
        //     };
        //     // Check the number of bits.
        //     ensure!(
        //         size_in_bits % 8 == 0,
        //         "Expected a multiple of 8 bits for '{}', found '{size_in_bits}'",
        //         variant.opcode()
        //     );
        // }

        Ok(vec![RegisterType::Plaintext(PlaintextType::Literal(LiteralType::Boolean))])
    }
}

impl<N: Network, const VARIANT: u8> Parser for RSAVerify<N, VARIANT> {
    /// Parses a string into an operation.
    #[inline]
    fn parse(string: &str) -> ParserResult<Self> {
        // Parse the opcode from the string.
        let (string, _) = tag(*Self::opcode())(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the first operand from the string.
        let (string, first) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the second operand from the string.
        let (string, second) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the third operand from the string.
        let (string, third) = Operand::parse(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the "into" from the string.
        let (string, _) = tag("into")(string)?;
        // Parse the whitespace from the string.
        let (string, _) = Sanitizer::parse_whitespaces(string)?;
        // Parse the destination register from the string.
        let (string, destination) = Register::parse(string)?;

        Ok((string, Self { operands: vec![first, second, third], destination }))
    }
}

impl<N: Network, const VARIANT: u8> FromStr for RSAVerify<N, VARIANT> {
    type Err = Error;

    /// Parses a string into an operation.
    #[inline]
    fn from_str(string: &str) -> Result<Self> {
        match Self::parse(string) {
            Ok((remainder, object)) => {
                // Ensure the remainder is empty.
                ensure!(remainder.is_empty(), "Failed to parse string. Found invalid character in: \"{remainder}\"");
                // Return the object.
                Ok(object)
            }
            Err(error) => bail!("Failed to parse string. {error}"),
        }
    }
}

impl<N: Network, const VARIANT: u8> Debug for RSAVerify<N, VARIANT> {
    /// Prints the operation as a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        Display::fmt(self, f)
    }
}

impl<N: Network, const VARIANT: u8> Display for RSAVerify<N, VARIANT> {
    /// Prints the operation to a string.
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        // Ensure the number of operands is 4.
        if self.operands.len() != 4 {
            return Err(fmt::Error);
        }
        // Print the operation.
        write!(f, "{} ", Self::opcode())?;
        self.operands.iter().try_for_each(|operand| write!(f, "{operand} "))?;
        write!(f, "into {}", self.destination)
    }
}

impl<N: Network, const VARIANT: u8> FromBytes for RSAVerify<N, VARIANT> {
    /// Reads the operation from a buffer.
    fn read_le<R: Read>(mut reader: R) -> IoResult<Self> {
        // Initialize the vector for the operands.
        let mut operands = Vec::with_capacity(4);
        // Read the operands.
        for _ in 0..4 {
            operands.push(Operand::read_le(&mut reader)?);
        }
        // Read the destination register.
        let destination = Register::read_le(&mut reader)?;

        // Return the operation.
        Ok(Self { operands, destination })
    }
}

impl<N: Network, const VARIANT: u8> ToBytes for RSAVerify<N, VARIANT> {
    /// Writes the operation to a buffer.
    fn write_le<W: Write>(&self, mut writer: W) -> IoResult<()> {
        // Ensure the number of operands is 4.
        if self.operands.len() != 4 {
            return Err(error(format!("The number of operands must be 4, found {}", self.operands.len())));
        }
        // Write the operands.
        self.operands.iter().try_for_each(|operand| operand.write_le(&mut writer))?;
        // Write the destination register.
        self.destination.write_le(&mut writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use console::network::MainnetV0;

    type CurrentNetwork = MainnetV0;

    #[test]
    fn test_parse() {
        let (string, is) =
            RSAVerifySha2_256::<CurrentNetwork>::parse("rsa.verify.sha2_256 r0 r1 r2 r3 into r4").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(is.operands.len(), 4, "The number of operands is incorrect");
        assert_eq!(is.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(is.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(is.operands[2], Operand::Register(Register::Locator(2)), "The third operand is incorrect");
        assert_eq!(is.operands[3], Operand::Register(Register::Locator(3)), "The third operand is incorrect");
        assert_eq!(is.destination, Register::Locator(4), "The destination register is incorrect");

        let (string, is) =
            RSAVerifySha2_256Raw::<CurrentNetwork>::parse("rsa.verify.sha2_256.raw r0 r1 r2 r3 into r4").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(is.operands.len(), 4, "The number of operands is incorrect");
        assert_eq!(is.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(is.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(is.operands[2], Operand::Register(Register::Locator(2)), "The third operand is incorrect");
        assert_eq!(is.operands[3], Operand::Register(Register::Locator(3)), "The third operand is incorrect");
        assert_eq!(is.destination, Register::Locator(4), "The destination register is incorrect");

        let (string, is) =
            RSAVerifySha2_256Digest::<CurrentNetwork>::parse("rsa.verify.sha2_256.digest r0 r1 r2 r3 into r4").unwrap();
        assert!(string.is_empty(), "Parser did not consume all of the string: '{string}'");
        assert_eq!(is.operands.len(), 4, "The number of operands is incorrect");
        assert_eq!(is.operands[0], Operand::Register(Register::Locator(0)), "The first operand is incorrect");
        assert_eq!(is.operands[1], Operand::Register(Register::Locator(1)), "The second operand is incorrect");
        assert_eq!(is.operands[2], Operand::Register(Register::Locator(2)), "The third operand is incorrect");
        assert_eq!(is.operands[3], Operand::Register(Register::Locator(3)), "The third operand is incorrect");
        assert_eq!(is.destination, Register::Locator(4), "The destination register is incorrect");
    }
}
