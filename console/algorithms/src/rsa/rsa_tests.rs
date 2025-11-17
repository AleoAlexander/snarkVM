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

use ::rsa::BigUint;

// Set to 5 due long signature generation time.  Can be sped up by compiling with --release flag.
const ITERATIONS: usize = 5;

fn test_rsa<H: Hash<Output = Vec<bool>, Input = bool>>(
    hasher: &H,
    rng: &mut TestRng,
    hash_algorithm: SHA2HashAlgorithm,
) {
    let lengths = [2048, 3072, 4096];

    for signature_length in lengths {
        for i in 1..ITERATIONS {
            let (private_key, message, signature) =
                test_helpers::sample_rsa_signature(i, hasher, rng, &hash_algorithm, signature_length);

            let rsa_public_key = RsaPublicKey::from(private_key.clone());

            assert!(signature.verify(&rsa_public_key, &hash_algorithm, hasher, &message.to_bits_be(), None).is_ok());

            // Verify the signature using the digest.
            let message_digest = hasher.hash(&message.to_bits_be()).unwrap();
            assert!(signature.verify_with_digest(&rsa_public_key, &hash_algorithm, &message_digest, None).is_ok());
        }
    }
}

#[test]
fn test_rsa_signature() {
    let rng = &mut TestRng::default();

    test_rsa(&Sha2_224::default(), rng, SHA2HashAlgorithm::Sha224);
    test_rsa(&Sha2_256::default(), rng, SHA2HashAlgorithm::Sha256);
    test_rsa(&Sha2_384::default(), rng, SHA2HashAlgorithm::Sha384);
    test_rsa(&Sha2_512::default(), rng, SHA2HashAlgorithm::Sha512);
    test_rsa(&Sha2_512_224::default(), rng, SHA2HashAlgorithm::Sha512_224);
    test_rsa(&Sha2_512_256::default(), rng, SHA2HashAlgorithm::Sha512_256);
}

#[test]
fn test_rsa_signature_vector() {
    let hasher = Sha2_256::default();

    // Declare the test vector values.
    let data_string = "0x2bcc5ce70000000100000000000000000000000000000000000000000000000000000000000f424000002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b000000000000000000000000742d35cc6e4c6e42e2a6e1b6d6e19d3bb14d3d1a000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000c350bfab0940d5a2410c007e06c8b1bb24e34391ddc5298e18840df438e8e05b9ac800000000";
    //Signature String below has already been converted to little endian
    let signature_string = "0xD833821FFA533697E84FA47C820B369A864FA98791D724596A43E7326913C428CAB6C25F2919F51CD1A4EEC4C82797EAA024E80ACC7943E8697F7330F7A5C1ADAA24DA2002F48F39F61B86B50AC519164B46929EE33933AF06675055130F8B4E76162F0F888115A9FE0A0831FDD728B94148592BF730CBB1816BCD9C80125B4E830532086BC424803CE822DDCE4F64C546987B92903EC2EE27C8A54684ACC014FF1811BCCA4FFB6336D8BCA5EE194D6082AF0A8F012CC84B016275741D167BF94A143177178E61F47F0B042B124EE79FB2703C07B3DE29849370050267022B68DEA89D6A9EB86CF72CD6D435E9D9CD42951E2BBBC23839C0020F1F8EFF021E2A";
    let modulus = "0x00ae943e660bbfa483950eb89f74879a46d27af6044df1a27c68e22266ffe46d2856859d9a7d7b84b9f00147ae8cc7dd7e0fa16438f7de05e3567e0ddac8cbf88da0558fc075a23c1f3d457f7e9b862ae928fc0cb0b315863eacfe5c34b0949c42e5a50f11334ff84172404971e21d33b514ca88c5c166e8642c7ca3f62199afb9db5299c398c5a6a5263f7645075cde71741f5d1453a28ab58bd847c6a1c8417bb12fe384e2565d59ca16d9e7304e10364d5c5580f77fd5600e2ab91789108b37803335f1c08137713be20770a8e2dee0c3e6d031cf79920606ae978eeeb46240f3127c00306888b3d6988c47fe6accd27f4d9f7abc0c4ee29eb3e47be6177ac5";
    let exponent = "0x010001";

    //Initialize Public Key
    let modulus_bytes = hex::decode(&modulus[2..]).unwrap();
    let exponent_bytes = hex::decode(&exponent[2..]).unwrap();
    let modulus_big = BigUint::from_bytes_be(&modulus_bytes);
    let exponent_big = BigUint::from_bytes_be(&exponent_bytes);
    let rsa_public_key = RsaPublicKey::new(modulus_big, exponent_big).unwrap();

    // Convert the test vector values to bytes.
    let data_bytes = hex::decode(&data_string[2..]).unwrap();
    let signature_bytes = hex::decode(&signature_string[2..]).unwrap();

    // Recover the signature from bytes
    let signature = RSASignature::from_bytes_le(&signature_bytes).unwrap();

    // Check that the signature verifies against the recovered public key.
    assert!(
        (signature.verify(&rsa_public_key, &SHA2HashAlgorithm::Sha256, &hasher, &data_bytes.to_bits_be(), None))
            .is_ok()
    );

    // Check that the signature verifies using the digest.
    let message_digest = hasher.hash(&data_bytes.to_bits_be()).unwrap();
    assert!(signature.verify_with_digest(&rsa_public_key, &SHA2HashAlgorithm::Sha256, &message_digest, None).is_ok());

    // Check that the signature does not verify against modified data.
    let wrong_data = data_bytes[6..].to_vec();
    assert!(
        (signature.verify(&rsa_public_key, &SHA2HashAlgorithm::Sha256, &hasher, &wrong_data.to_bits_be(), None))
            .is_err()
    );
}

// #[test]
// fn test_rsa_signature_generation() {
//     let hasher = Sha2_256::default();

//     let rng = &mut TestRng::default();

//     // Declare the test vector values.
//     let data_string = "0x2bcc5ce70000000100000000000000000000000000000000000000000000000000000000000f424000002712000000000000000000000000a0b86a33e6f8ec61cc62f1b0cb2ad6dfe3c10e8b000000000000000000000000742d35cc6e4c6e42e2a6e1b6d6e19d3bb14d3d1a000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb480000000000000000000000002222222222222222222222222222222222222222000000000000000000000000000000000000000000000000000000000000c350bfab0940d5a2410c007e06c8b1bb24e34391ddc5298e18840df438e8e05b9ac800000000";
//     let modulus = "0x00ae943e660bbfa483950eb89f74879a46d27af6044df1a27c68e22266ffe46d2856859d9a7d7b84b9f00147ae8cc7dd7e0fa16438f7de05e3567e0ddac8cbf88da0558fc075a23c1f3d457f7e9b862ae928fc0cb0b315863eacfe5c34b0949c42e5a50f11334ff84172404971e21d33b514ca88c5c166e8642c7ca3f62199afb9db5299c398c5a6a5263f7645075cde71741f5d1453a28ab58bd847c6a1c8417bb12fe384e2565d59ca16d9e7304e10364d5c5580f77fd5600e2ab91789108b37803335f1c08137713be20770a8e2dee0c3e6d031cf79920606ae978eeeb46240f3127c00306888b3d6988c47fe6accd27f4d9f7abc0c4ee29eb3e47be6177ac5";
//     let private_exponent = "0x11090029befdbd54e5a7a116562da13d45ee9fb0fdd6154fe48024713e8910a9bdff9dc86474381858b617438e1336a6c569af38ebdeeb5e2aa37440a4155b349eaf9aae620c29a7b6b7e05fff57113add37f3190ef08bbff3eb821dd6193a4240dc61630149cd64bd7c4e6e616d0e0d9e70c0f5e310629edbc471cf63a9f67e9806da8d92ff1500e69e7f778adc3fe9f715e2ec210f6b1f53dfa281cf54acebc668fd65d6c2de63e5ecfd286381be74765395404d85734d6fba0710592bfa60f757870aebedb19d26252d9dea8b0fb1dca814e5da16085dd23b422359609ec37c75435dbeeea1e3d3049871ef481fa05297f050144952b7d03b58c342f9e4c1";
//     let public_exponent = "0x00010001";
//     let prime1 = "0x00d7e2ddf34ce3a93423ba46e8632fa552267eaf6207316be8e62811a55ff596b9590d02f17d7fec9c6dc6707c471a6ae64358020dbd0be8473246338b1ef3221b8b1938743e5c130f54103f9c2dbb1f5dd1091857a357a5a3521d4c18d576572e8395121cd10f31cf86583311fac5b3e3a40b8312d0ea3b0f3a6a1f7ca40993b5";
//     let prime2 = "0x00cf0481b60dcedae527da7cfb1cadda479320bcfce0a7e0335e1d294d568a290a2fea0a6011439980385edc17944a43d407eef757bc677bc5e9b993959cbdcb3a6472e25f0175be4f19b9b0f7e7001b8be6d1a5854446a76ae347e7141f169117abb4fbec01dc5e7081b695139928cdd1063dca94cf4157791f8c4d3d3ca4d4d1";

//     //Initialize Public Key
//     let modulus_bytes = hex::decode(&modulus[2..]).unwrap();
//     let private_exponent_bytes = hex::decode(&private_exponent[2..]).unwrap();
//     let public_exponent_bytes = hex::decode(&public_exponent[2..]).unwrap();
//     let prime1_bytes = hex::decode(&prime1[2..]).unwrap();
//     let prime2_bytes = hex::decode(&prime2[2..]).unwrap();
//     let n = BigUint::from_bytes_be(&modulus_bytes);
//     let d = BigUint::from_bytes_be(&private_exponent_bytes);
//     let e = BigUint::from_bytes_be(&public_exponent_bytes);
//     let p = BigUint::from_bytes_be(&prime1_bytes);
//     let q = BigUint::from_bytes_be(&prime2_bytes);

//     let rsa_private_key = RsaPrivateKey::from_components(n,e,d,vec![p,q]).unwrap();
//     let signing_key = BlindedSigningKey::<Sha256>::new(rsa_private_key);

//     // Convert the test vector values to bytes.
//     let data_bytes = hex::decode(&data_string[2..]).unwrap();
//     //Hash the message
//     let hash = hasher.hash(&data_bytes.to_bits_le()).unwrap();

//     // Sign the message.
//     let signature = signing_key.sign_prehash_with_rng(rng, &bytes_from_bits_le(&hash)).unwrap();
//     println!("{:?}", signature);
// }
