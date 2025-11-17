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

use console::{
    algorithms::{SHA2HashAlgorithm, RSASignature, Sha2_224, Sha2_256, Sha2_384, Sha2_512, Sha2_512_224, Sha2_512_256},
    network::MainnetV0,
    prelude::*,
    program::{ArrayType, Identifier, Literal, LiteralType, Plaintext, PlaintextType, Register, Value},
    types::{Boolean, U8, U32},
};
use snarkvm_synthesizer_process::{FinalizeRegisters, Process, Stack};
use snarkvm_synthesizer_program::{
    RSAVerify,
    RSAVerifySha2_224,
    RSAVerifySha2_224Raw,
    RSAVerifySha2_224Digest,
    RSAVerifySha2_256,
    RSAVerifySha2_256Raw,
    RSAVerifySha2_256Digest,
    RSAVerifySha2_384,
    RSAVerifySha2_384Raw,
    RSAVerifySha2_384Digest,
    RSAVerifySha2_512,
    RSAVerifySha2_512Raw,
    RSAVerifySha2_512Digest,
    RSAVerifySha2_512_224,
    RSAVerifySha2_512_224Raw,
    RSAVerifySha2_512_224Digest,
    RSAVerifySha2_512_256,
    RSAVerifySha2_512_256Raw,
    RSAVerifySha2_512_256Digest,
    RSAVerifyVariant,
    FinalizeGlobalState,
    Opcode,
    Operand,
    Program,
    RegistersTrait as _,
};

use rsa::{
    RsaPublicKey,
    RsaPrivateKey,
    pss::{SigningKey},
    sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256},
    signature::{SignatureEncoding, hazmat::RandomizedPrehashSigner},
    traits::PublicKeyParts
};

use snarkvm_utilities::bytes_from_bits_be;

type CurrentNetwork = MainnetV0;

const ITERATIONS: usize = 25;

fn sample_valid_input_types<N: Network>(variant: RSAVerifyVariant) -> Vec<PlaintextType<N>> {
    match variant {
        RSAVerifyVariant::HashSha2_224Digest => vec![PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(u32::try_from(28).unwrap())])
                .unwrap(),
        )],
        RSAVerifyVariant::HashSha2_256Digest => vec![PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(u32::try_from(32).unwrap())])
                .unwrap(),
        )],
        RSAVerifyVariant::HashSha2_384Digest => vec![PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(u32::try_from(48).unwrap())])
                .unwrap(),
        )],
        RSAVerifyVariant::HashSha2_512Digest => vec![PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(u32::try_from(64).unwrap())])
                .unwrap(),
        )],
        RSAVerifyVariant::HashSha2_512_224Digest => vec![PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(u32::try_from(28).unwrap())])
                .unwrap(),
        )],
        RSAVerifyVariant::HashSha2_512_256Digest => vec![PlaintextType::Array(
            ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(u32::try_from(32).unwrap())])
                .unwrap(),
        )],
        RSAVerifyVariant::HashSha2_224Raw
        | RSAVerifyVariant::HashSha2_256Raw
        | RSAVerifyVariant::HashSha2_384Raw
        | RSAVerifyVariant::HashSha2_512Raw
        | RSAVerifyVariant::HashSha2_512_224Raw
        | RSAVerifyVariant::HashSha2_512_256Raw => vec![
            PlaintextType::Array(
                ArrayType::new(PlaintextType::Literal(LiteralType::Address), vec![U32::new(8)]).unwrap(),
            ),
            PlaintextType::Array(
                ArrayType::new(PlaintextType::Literal(LiteralType::Field), vec![U32::new(8)]).unwrap(),
            ),
            PlaintextType::Array(
                ArrayType::new(PlaintextType::Literal(LiteralType::Group), vec![U32::new(8)]).unwrap(),
            ),
            PlaintextType::Literal(LiteralType::I8),
            PlaintextType::Literal(LiteralType::I16),
            PlaintextType::Literal(LiteralType::I32),
            PlaintextType::Literal(LiteralType::I64),
            PlaintextType::Literal(LiteralType::I128),
            PlaintextType::Literal(LiteralType::U8),
            PlaintextType::Literal(LiteralType::U16),
            PlaintextType::Literal(LiteralType::U32),
            PlaintextType::Literal(LiteralType::U64),
            PlaintextType::Literal(LiteralType::U128),
            PlaintextType::Array(
                ArrayType::new(PlaintextType::Literal(LiteralType::Scalar), vec![U32::new(8)]).unwrap(),
            ),
        ],
        _ => vec![
            PlaintextType::Literal(LiteralType::Address),
            PlaintextType::Literal(LiteralType::Field),
            PlaintextType::Literal(LiteralType::Group),
            PlaintextType::Literal(LiteralType::I8),
            PlaintextType::Literal(LiteralType::I16),
            PlaintextType::Literal(LiteralType::I32),
            PlaintextType::Literal(LiteralType::I64),
            PlaintextType::Literal(LiteralType::I128),
            PlaintextType::Literal(LiteralType::U8),
            PlaintextType::Literal(LiteralType::U16),
            PlaintextType::Literal(LiteralType::U32),
            PlaintextType::Literal(LiteralType::U64),
            PlaintextType::Literal(LiteralType::U128),
            PlaintextType::Literal(LiteralType::Scalar),
        ],
    }
}

/// Samples the stack. Note: Do not replicate this for real program use, it is insecure.
#[allow(clippy::type_complexity)]
fn sample_stack(
    opcode: Opcode,
    type_0: PlaintextType<CurrentNetwork>,
    type_1: PlaintextType<CurrentNetwork>,
    type_2: PlaintextType<CurrentNetwork>,
    type_3: PlaintextType<CurrentNetwork>,
    mode: circuit::Mode,
) -> Result<(Stack<CurrentNetwork>, Vec<Operand<CurrentNetwork>>, Register<CurrentNetwork>)> {
    // Initialize the opcode.
    let opcode = opcode.to_string();

    // Initialize the function name.
    let function_name = Identifier::<CurrentNetwork>::from_str("run")?;

    // Initialize the registers.
    let r0 = Register::Locator(0);
    let r1 = Register::Locator(1);
    let r2 = Register::Locator(2);
    let r3 = Register::Locator(3);
    let r4 = Register::Locator(4);

    // Initialize the program.
    let program = Program::from_str(&format!(
        "program testing.aleo;
            function {function_name}:
                input {r0} as {type_0}.{mode};
                input {r1} as {type_1}.{mode};
                input {r2} as {type_2}.{mode};
                input {r3} as {type_3}.{mode};
                async {function_name} {r0} {r1} {r2} {r3} into r4;
                output r4 as testing.aleo/{function_name}.future;
            finalize {function_name}:
                input {r0} as {type_0}.public;
                input {r1} as {type_1}.public;
                input {r2} as {type_2}.public;
                input {r3} as {type_3}.public;
                {opcode} {r0} {r1} {r2} {r3} into {r4};
        "
    ))?;

    // Initialize the operands.
    let operands = vec![Operand::Register(r0), Operand::Register(r1), Operand::Register(r2), Operand::Register(r3)];

    // Initialize the stack.
    let stack = Stack::new(&Process::load()?, &program)?;

    Ok((stack, operands, r4))
}

/// Samples the finalize registers. Note: Do not replicate this for real program use, it is insecure.
pub fn sample_rsa_finalize_registers(
    stack: &Stack<CurrentNetwork>,
    function_name: &Identifier<CurrentNetwork>,
    signature: &[u8],
    pub_key_mod: &[u8],
    pub_key_exp: &[u8],
    expected_length: usize,
    message: Plaintext<CurrentNetwork>,
) -> Result<FinalizeRegisters<CurrentNetwork>> {
    // Initialize the registers.
    let mut finalize_registers = FinalizeRegisters::<CurrentNetwork>::new(
        FinalizeGlobalState::from(1, 1, [0; 32]),
        <CurrentNetwork as Network>::TransitionID::default(),
        *function_name,
        stack.get_finalize_types(function_name)?.clone(),
        0u64,
    );

    // Initialize the signature.
    let signature_bytes = signature.iter().copied().map(U8::<CurrentNetwork>::new).collect::<Vec<_>>();
    let plaintext_signature = match expected_length {
        256 => {
            let signature: [U8<CurrentNetwork>; 256] = signature_bytes.try_into().unwrap();
            Plaintext::<CurrentNetwork>::from(signature)
        }
        384 => {
            let signature: [U8<CurrentNetwork>; 384] = signature_bytes.try_into().unwrap();
            Plaintext::<CurrentNetwork>::from(signature)
        }
        512 => {
            let signature: [U8<CurrentNetwork>; 512] = signature_bytes.try_into().unwrap();
            Plaintext::<CurrentNetwork>::from(signature)
        }
        invalid_length => bail!("Invalid public key length: {invalid_length}"),
    };

    // Initialize the public key modulus.
    let pub_key_mod_bytes = pub_key_mod.iter().copied().map(U8::<CurrentNetwork>::new).collect::<Vec<_>>();
    let plaintext_pub_key_mod = match expected_length {
        256 => {
            let pub_key_mod: [U8<CurrentNetwork>; 256] = pub_key_mod_bytes.try_into().unwrap();
            Plaintext::<CurrentNetwork>::from(pub_key_mod)
        }
        384 => {
            let pub_key_mod: [U8<CurrentNetwork>; 384] = pub_key_mod_bytes.try_into().unwrap();
            Plaintext::<CurrentNetwork>::from(pub_key_mod)
        }
        512 => {
            let pub_key_mod: [U8<CurrentNetwork>; 512] = pub_key_mod_bytes.try_into().unwrap();
            Plaintext::<CurrentNetwork>::from(pub_key_mod)
        }
        invalid_length => bail!("Invalid public key length: {invalid_length}"),
    };

    // Initialize the public key exponent.
    let mut pub_key_exp_bytes = pub_key_exp.iter().copied().map(U8::<CurrentNetwork>::new).collect::<Vec<_>>();
    let plaintext_pub_key_exp = match expected_length {
        256 => {
            pub_key_exp_bytes.reverse();
            pub_key_exp_bytes.resize(256,U8::<CurrentNetwork>::new(0));
            pub_key_exp_bytes.reverse();
            let pub_key_exp: [U8<CurrentNetwork>; 256] = pub_key_exp_bytes.try_into().unwrap();
            Plaintext::<CurrentNetwork>::from(pub_key_exp)
        }
        384 => {
            pub_key_exp_bytes.reverse();
            pub_key_exp_bytes.resize(384,U8::<CurrentNetwork>::new(0));
            pub_key_exp_bytes.reverse();
            let pub_key_exp: [U8<CurrentNetwork>; 384] = pub_key_exp_bytes.try_into().unwrap();
            Plaintext::<CurrentNetwork>::from(pub_key_exp)
        }
        512 => {
            pub_key_exp_bytes.reverse();
            pub_key_exp_bytes.resize(512,U8::<CurrentNetwork>::new(0));
            pub_key_exp_bytes.reverse();
            let pub_key_exp: [U8<CurrentNetwork>; 512] = pub_key_exp_bytes.try_into().unwrap();
            Plaintext::<CurrentNetwork>::from(pub_key_exp)
        }
        invalid_length => bail!("Invalid public key length: {invalid_length}"),
    };

    // Initialize the registers
    let register_0 = Register::Locator(0);
    let register_1 = Register::Locator(1);
    let register_2 = Register::Locator(2);
    let register_3 = Register::Locator(3);
    // Initialize the console value.
    let value_0 = Value::Plaintext(plaintext_signature);
    let value_1 = Value::Plaintext(plaintext_pub_key_mod);
    let value_2 = Value::Plaintext(plaintext_pub_key_exp);
    let value_3 = Value::Plaintext(message);
    // Store the value in the console registers.
    finalize_registers.store(stack, &register_0, value_0)?;
    finalize_registers.store(stack, &register_1, value_1)?;
    finalize_registers.store(stack, &register_2, value_2)?;
    finalize_registers.store(stack, &register_3, value_3)?;

    Ok(finalize_registers)
}

fn check_rsa<const VARIANT: u8, H: Hash<Input = bool, Output = Vec<bool>>>(
    operation: impl FnOnce(Vec<Operand<CurrentNetwork>>, Register<CurrentNetwork>) -> RSAVerify<CurrentNetwork, VARIANT>,
    hasher: &H,
    opcode: Opcode,
    message_type: &PlaintextType<CurrentNetwork>,
    mode: &circuit::Mode,
    rng: &mut TestRng,
) {
    // Generate the RSA signing keys.
    let bits = 2048;
    let private_key = RsaPrivateKey::new(rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(private_key.clone());

    let (expected_length, n,e) = {
        let byte_length = bits / 8;
        let n = pub_key.n().to_bytes_be();
        let e = pub_key.e().to_bytes_be();
        (byte_length, n, e)
    };

    // let signing_key = match VARIANT {
    //     (0..3) => {SigningKey::<Sha224>::new(private_key)},
    //     (3..6) => {SigningKey::<Sha256>::new(private_key)},
    //     (6..9) => {SigningKey::<Sha384>::new(private_key)},
    //     (9..12) => {SigningKey::<Sha512>::new(private_key)},
    //     (12..15) => {SigningKey::<Sha512_224>::new(private_key)},
    //     (15..18) => {SigningKey::<Sha512_256>::new(private_key)},
    // };
    // let verifying_key = signing_key.verifying_key();

    println!("Checking '{opcode}' for message type '{message_type}.{mode}'");

    // Initialize the types.
    let type_0 =
        PlaintextType::Array(ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(expected_length as u32)]).unwrap());
    let type_1 = 
        PlaintextType::Array(ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(expected_length as u32)]).unwrap());
    let type_2 = 
        PlaintextType::Array(ArrayType::new(PlaintextType::Literal(LiteralType::U8), vec![U32::new(expected_length as u32)]).unwrap());
    // Initialize the stack.
    let (stack, operands, destination) = sample_stack(opcode, type_0, type_1, type_2, message_type.clone(), *mode).unwrap();

    // Sample the input.
    let message = stack.sample_plaintext(message_type, rng).unwrap();

    // Initialize the operation.
    let operation = operation(operands, destination.clone());
    // Initialize the function name.
    let function_name = Identifier::from_str("run").unwrap();
    // Initialize a destination operand.
    let destination_operand = Operand::Register(destination);

    // Construct the signature.
    let message_bits = match opcode.ends_with(".raw") || opcode.ends_with(".digest") {
        true => message.to_bits_raw_be(),
        false => message.to_bits_be(),
    };


    let signature = match VARIANT {
            0 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha224, &private_key, hasher, &message_bits, rng).unwrap(),
            1 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha224, &private_key, hasher, &message_bits, rng).unwrap(),
            2 => SigningKey::<Sha224>::new(private_key)
                .sign_prehash_with_rng(rng, &bytes_from_bits_be(&message_bits))
                .map(|signature| {
                    RSASignature { signature }
                })
                .unwrap(),
            3 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha256, &private_key, hasher, &message_bits, rng).unwrap(),
            4 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha256, &private_key, hasher, &message_bits, rng).unwrap(),
            5 => SigningKey::<Sha256>::new(private_key)
                .sign_prehash_with_rng(rng, &bytes_from_bits_be(&message_bits))
                .map(|signature| {
                    RSASignature { signature }
                })
                .unwrap(),
            6 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha384, &private_key, hasher, &message_bits, rng).unwrap(),
            7 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha384, &private_key, hasher, &message_bits, rng).unwrap(),
            8 => SigningKey::<Sha384>::new(private_key)
                .sign_prehash_with_rng(rng, &bytes_from_bits_be(&message_bits))
                .map(|signature| {
                    RSASignature { signature }
                })
                .unwrap(),
            9 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha512, &private_key, hasher, &message_bits, rng).unwrap(),
            10 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha512, &private_key, hasher, &message_bits, rng).unwrap(),
            11 => SigningKey::<Sha512>::new(private_key)
                .sign_prehash_with_rng(rng, &bytes_from_bits_be(&message_bits))
                .map(|signature| {
                    RSASignature { signature }
                })
                .unwrap(),
            12 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha512_224, &private_key, hasher, &message_bits, rng).unwrap(),
            13 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha512_224, &private_key, hasher, &message_bits, rng).unwrap(),
            14 => SigningKey::<Sha512_224>::new(private_key)
                .sign_prehash_with_rng(rng, &bytes_from_bits_be(&message_bits))
                .map(|signature| {
                    RSASignature { signature }
                })
                .unwrap(),
            15 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha512_256, &private_key, hasher, &message_bits, rng).unwrap(),
            16 => RSASignature::sign::<H>(&SHA2HashAlgorithm::Sha512_256, &private_key, hasher, &message_bits, rng).unwrap(),
            _ => SigningKey::<Sha512_256>::new(private_key)
                .sign_prehash_with_rng(rng, &bytes_from_bits_be(&message_bits))
                .map(|signature| {
                    RSASignature { signature }
                })
                .unwrap(),
    };
    let signature_bytes = signature.signature.to_bytes();

    // Attempt to finalize the valid operand case.
    let mut finalize_registers = sample_rsa_finalize_registers(
        &stack,
        &function_name,
        &signature_bytes,
        &n,
        &e,
        expected_length,
        message.clone(),
    ).unwrap();
    let result_a = operation.finalize(&stack, &mut finalize_registers);
    // Enforce that the signature verifies successfully.
    assert!(result_a.is_ok(), "The finalization should succeed for a valid operand");
    let output = finalize_registers.load(&stack, &destination_operand).unwrap();
    assert_eq!(
        output,
        Value::Plaintext(Plaintext::from(Literal::Boolean(Boolean::new(true)))),
        "The output should be true for a valid operand"
    );

    // // Create an invalid signature by using a different signature.
    // let invalid_signature =
    //     RSASignature::sign::<H>(&signing_key, hasher, &[message_bits, vec![true]].concat()).unwrap();


    // let invalid_signature_bytes = invalid_signature.signature.to_bytes_be().unwrap();
    // let mut finalize_registers = sample_rsa_finalize_registers(
    //     &stack,
    //     &function_name,
    //     &invalid_signature_bytes,
    //     &n,
    //     &e,
    //     expected_length,
    //     message,
    // )
    // .unwrap();
    // let result_b = operation.finalize(&stack, &mut finalize_registers);
    // // Enforce that the signature verification fails.
    // assert!(result_b.is_ok(), "The finalization should succeed for the operand");
    // let output = finalize_registers.load(&stack, &destination_operand).unwrap();
    // assert_eq!(
    //     output,
    //     Value::Plaintext(Plaintext::from(Literal::Boolean(Boolean::new(false)))),
    //     "The output should be false for an invalid message"
    // );
}

macro_rules! test_rsa {
    ($name: tt, $hash:ident, $rsa:ident, $variant:ident,  $iterations:expr) => {
        paste::paste! {
            #[test]
            fn [<test _ $name _ is _ correct>]() {
                // Initialize the operation.
                let operation = |operands, destination| $rsa::<CurrentNetwork>::new(operands, destination).unwrap();
                // Initialize the opcode.
                let opcode = $rsa::<CurrentNetwork>::opcode();

                // Prepare the rng.
                let rng = &mut TestRng::default();

                // Prepare the hasher.
                let hasher = $hash::default();

                // Prepare the test.
                let modes = [circuit::Mode::Public, circuit::Mode::Private];

                for _ in 0..$iterations {
                    for input_type in sample_valid_input_types(RSAVerifyVariant::$variant) {
                        for mode in modes.iter() {
                            check_rsa(
                                operation,
                                &hasher,
                                opcode,
                                &input_type,
                                mode,
                                rng,
                            );
                        }
                    }
                }
            }
        }
    };
}

test_rsa!(rsa_verify_sha2_224, Sha2_224, RSAVerifySha2_224, HashSha2_224, ITERATIONS);
test_rsa!(rsa_verify_sha2_224_raw, Sha2_224, RSAVerifySha2_224Raw, HashSha2_224Raw, ITERATIONS);
test_rsa!(rsa_verify_sha2_224_digest, Sha2_224, RSAVerifySha2_224Digest, HashSha2_224Digest, ITERATIONS);

test_rsa!(rsa_verify_sha2_256, Sha2_256, RSAVerifySha2_256, HashSha2_256, ITERATIONS);
test_rsa!(rsa_verify_sha2_256_raw, Sha2_256, RSAVerifySha2_256Raw, HashSha2_256Raw, ITERATIONS);
test_rsa!(rsa_verify_sha2_256_digest, Sha2_256, RSAVerifySha2_256Digest, HashSha2_256Digest, ITERATIONS);

test_rsa!(rsa_verify_sha2_384, Sha2_384, RSAVerifySha2_384, HashSha2_384, ITERATIONS);
test_rsa!(rsa_verify_sha2_384_raw, Sha2_384, RSAVerifySha2_384Raw, HashSha2_384Raw, ITERATIONS);
test_rsa!(rsa_verify_sha2_384_digest, Sha2_384, RSAVerifySha2_384Digest, HashSha2_384Digest, ITERATIONS);

test_rsa!(rsa_verify_sha2_512, Sha2_512, RSAVerifySha2_512, HashSha2_512, ITERATIONS);
test_rsa!(rsa_verify_sha2_512_raw, Sha2_512, RSAVerifySha2_512Raw, HashSha2_512Raw, ITERATIONS);
test_rsa!(rsa_verify_sha2_512_digest, Sha2_512, RSAVerifySha2_512Digest, HashSha2_512Digest, ITERATIONS);

test_rsa!(rsa_verify_sha2_512_224, Sha2_512_224, RSAVerifySha2_512_224, HashSha2_512_224, ITERATIONS);
test_rsa!(rsa_verify_sha2_512_224_raw, Sha2_512_224, RSAVerifySha2_512_224Raw, HashSha2_512_224Raw, ITERATIONS);
test_rsa!(rsa_verify_sha2_512_224_digest, Sha2_512_224, RSAVerifySha2_512_224Digest, HashSha2_512_224Digest, ITERATIONS);

test_rsa!(rsa_verify_sha2_512_256, Sha2_512_256, RSAVerifySha2_512_256, HashSha2_512_256, ITERATIONS);
test_rsa!(rsa_verify_sha2_512_256_raw, Sha2_512_256, RSAVerifySha2_512_256Raw, HashSha2_512_256Raw, ITERATIONS);
test_rsa!(rsa_verify_sha2_512_256_digest, Sha2_512_256, RSAVerifySha2_512_256Digest, HashSha2_512_256Digest, ITERATIONS);