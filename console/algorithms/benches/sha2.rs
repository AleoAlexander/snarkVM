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

#[macro_use]
extern crate criterion;

use snarkvm_console_algorithms::{Sha2_224, Sha2_256, Sha2_384, Sha2_512, Sha2_512_224, Sha2_512_256};
use snarkvm_console_types::prelude::*;
use snarkvm_utilities::{TestRng, Uniform};

use criterion::Criterion;

fn sha224(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = Sha2_224::default();

    let input = (0..256).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("Sha2_224 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));
}

fn sha256(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = Sha2_256::default();

    let input = (0..256).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("Sha2_256 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));
}
fn sha384(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = Sha2_384::default();

    let input = (0..256).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("Sha2_384 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));
}
fn sha512(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = Sha2_512::default();

    let input = (0..256).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("Sha2_512 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));
}
fn sha512_224(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = Sha2_512_224::default();

    let input = (0..256).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("Sha2_512_224 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));
}
fn sha512_256(c: &mut Criterion) {
    let rng = &mut TestRng::default();
    let hash = Sha2_512_256::default();

    let input = (0..256).map(|_| bool::rand(rng)).collect::<Vec<_>>();
    c.bench_function(&format!("Sha2_512_256 Hash - input size {}", input.len()), |b| b.iter(|| hash.hash(&input)));
}

criterion_group! {
    name = sha2;
    config = Criterion::default().sample_size(1000);
    targets = sha224, sha256, sha384, sha512, sha512_224, sha512_256
}

criterion_main!(sha2);
