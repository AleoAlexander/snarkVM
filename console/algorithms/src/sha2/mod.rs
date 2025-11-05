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

mod hash;

#[cfg(test)]
use snarkvm_utilities::Uniform;

use crate::Hash;
use snarkvm_console_types::environment::prelude::*;



/// The SHA2-224 hash function.
pub type Sha2_224 = SHA2<224,0>;
/// The SHA2-256 hash function.
pub type Sha2_256 = SHA2<256,0>;
/// The SHA2-384 hash function.
pub type Sha2_384 = SHA2<384,0>;
/// The SHA2-512 hash function.
pub type Sha2_512 = SHA2<512,0>;
/// The SHA2-512_224 hash function.
pub type Sha2_512_224 = SHA2<512,224>;
/// The SHA2-512_256 hash function.
pub type Sha2_512_256 = SHA2<512,256>;



#[derive(Copy, Clone, Debug, Default, PartialEq)]
pub struct SHA2<const VARIANT: usize, const TRUNCATE:usize>;
