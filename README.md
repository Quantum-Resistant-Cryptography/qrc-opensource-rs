<br />
<p>
  <a href="https://www.qrcrypto.ch/">
    <img src="https://www.qrcrypto.ch/images/logo-quantum-resistant.svg" alt="Logo" width="350">
  </a>

<h3>qrc-opensource-rs</h3>
<p>
The free opensource version of the Quantum Secure Cryptographic library in Rust (QSC)
<br />
<br />
<a href="https://github.com/Quantum-Resistant-Cryptography/qrc-opensource-rs">Source Code</a>
|
<a href="https://crates.io/crates/qrc-opensource-rs">Crates.io</a>
|
<a href="https://www.qrcrypto.ch/">QRCrypto.ch</a>
|
<a href="https://www.linkedin.com/company/qrcryptography">LinkedIn</a>
</p>

<summary><h2 style="display: inline-block">Table of Contents</h2></summary>
<ol>
  <li><a href="#outline">Outline</a></li>
  <li><a href="#usage">Usage</a></li>
  <li><a href="#roadmap">Roadmap</a></li>
  <li><a href="#license">License</a></li>
</ol>


## Outline

This is intended to facilitate the deployment of quantum-resistant cryptography as per the Quantum Computing Cybersecurity Preparedness Act (12/22) of the United States of America. Note it does not include our enhanced designs, which are subject to patents, and available separately as commercial packages.


## Usage

First add the ```qrc-opensource-rs``` crate to your ```Cargo.toml```:
```sh
[dependencies]
qrc-opensource-rs = "0.2"
```

  <summary><h4 style="display: inline-block">Examples</h4></summary>
  <ul>
    <li>
        <summary><p style="display: inline-block">Asymmetric</p></summary>
        <ul>
          <li>
              <summary><p style="display: inline-block">Cipher</p></summary>
              <ul>
                <li><a href="#kyber">Kyber</a></li>
                <li><a href="#mceliece">McEliece</a></li>
              </ul>
          </li>
          <li>
              <summary><p style="display: inline-block">Signature</p></summary>
              <ul>
                <li><a href="#sphincsplus">SphincsPlus</a></li>
              </ul>
          </li>
        </ul>
    </li>
    <li>
        <summary><p style="display: inline-block">Cipher</p></summary>
        <ul>
          <li><a href="#aes">AES</a></li>
        </ul>
    </li>
    <li>
        <summary><p style="display: inline-block">Digest</p></summary>
        <ul>
          <li><a href="#sha2">Sha2</a></li>
          <li><a href="#sha3">Sha3</a></li>
        </ul>
    </li>
    <li>
        <summary><p style="display: inline-block">Mac</p></summary>
        <ul>
          <li><a href="#poly1305">Poly1305</a></li>
        </ul>
    </li>
  </ul>


### Asymmetric
#### Cipher
##### Kyber
Based on the C reference branch of PQ-Crystals Kyber; including base code, comments, and api.
Removed the K=2 parameter, and added a K=5. The NIST '512' parameter has fallen below the threshold
required by NIST PQ S1 minimum.
The new K5 parameter may have a better chance of long-term security, with only a small increase in cost.

The NIST Post Quantum Competition [Round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions) Finalists.
The [Kyber](https://pq-crystals.org/kyber/index.shtml) website.
The Kyber [Algorithm](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf) Specification.

Date: January 10, 2018
Updated: July 2, 2021
Rust Translation: 2024

The primary public api for the Kyber CCA-secure Key Encapsulation Mechanism implementation:
```rust
use qrc_opensource_rs::{
  asymmetric::cipher::kyber::{
    qsc_kyber_generate_keypair, qsc_kyber_encrypt, qsc_kyber_decrypt,
    QSC_KYBER_SEED_SIZE, QSC_KYBER_PUBLICKEY_SIZE, QSC_KYBER_PRIVATEKEY_SIZE, QSC_KYBER_SHAREDSECRET_SIZE, QSC_KYBER_CIPHERTEXT_SIZE
  },
  provider::rcrng::qsc_rcrng_generate,
};

let mut seed = [0u8; QSC_KYBER_SEED_SIZE];
qsc_rcrng_generate(&mut seed, QSC_KYBER_SEED_SIZE);

let publickey = &mut vec![0u8; QSC_KYBER_PUBLICKEY_SIZE];
let privatekey = &mut vec![0u8; QSC_KYBER_PRIVATEKEY_SIZE];

let secret1 = &mut [0u8; QSC_KYBER_SHAREDSECRET_SIZE];
let secret2 = &mut [0u8; QSC_KYBER_SHAREDSECRET_SIZE];

let ciphertext = &mut [0u8; QSC_KYBER_CIPHERTEXT_SIZE];

qsc_kyber_generate_keypair(publickey, privatekey, seed);
qsc_kyber_encrypt(secret1, ciphertext, publickey, seed);
qsc_kyber_decrypt(secret2, ciphertext, privatekey);
```

##### McEliece
Classic McEliece is a KEM designed for IND-CCA2 security at a very high security level, even against quantum computers.
The KEM is built conservatively from a PKE designed for OW-CPA security, namely Niederreiter's dual version of McEliece's PKE using binary Goppa codes.
Every level of the construction is designed so that future cryptographic auditors can be confident in the long-term security of post-quantum public-key encryption.

Based entirely on the C reference branch of Dilithium taken from the NIST Post Quantum Competition Round 3 submission.
The NIST Post Quantum Competition [Round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions) Finalists.
The [McEliece](https://classic.mceliece.org/) website.
The McEliece [Algorithm](https://classic.mceliece.org/nist/mceliece-20201010.pdf) Specification.

Authors: Daniel J. Bernstein, Tung Chou, Tanja Lange, and Peter Schwabe.
Updated: John Underhill - June 28 2021
Rust Translation: 2024

The primary public api for the Niederreiter dual form of the McEliece asymmetric cipher implementation:
```rust
use qrc_opensource_rs::{
  asymmetric::cipher::mceliece::{
    qsc_mceliece_generate_keypair, qsc_mceliece_encrypt, qsc_mceliece_decrypt,
    QSC_MCELIECE_CIPHERTEXT_SIZE, QSC_MCELIECE_PRIVATEKEY_SIZE, QSC_MCELIECE_PUBLICKEY_SIZE, QSC_MCELIECE_SHAREDSECRET_SIZE, QSC_MCELIECE_SEED_SIZE,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let mut seed = [0u8; QSC_MCELIECE_SEED_SIZE];
qsc_rcrng_generate(&mut seed, QSC_MCELIECE_SEED_SIZE);

let publickey = &mut vec![0u8; QSC_MCELIECE_PUBLICKEY_SIZE];
let privatekey = &mut vec![0u8; QSC_MCELIECE_PRIVATEKEY_SIZE];

let secret1 = &mut [0u8; QSC_MCELIECE_SHAREDSECRET_SIZE];
let secret2 = &mut [0u8; QSC_MCELIECE_SHAREDSECRET_SIZE];

let ciphertext = &mut [0u8; QSC_MCELIECE_CIPHERTEXT_SIZE];

qsc_mceliece_generate_keypair(publickey, privatekey, seed);	
qsc_mceliece_encrypt(secret1, ciphertext, publickey, seed);
qsc_mceliece_decrypt(secret2, ciphertext, privatekey);
```

#### Signature
##### SphincsPlus
Based entirely on the C reference branch of SPHINCS+ taken from the NIST Post Quantum Competition Round 3 submission.
The NIST Post Quantum Competition [Round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions) Finalists.
The [SPHINCS+](https://sphincs.org/) website.
The SPHINCS+ [Algorithm](https://sphincs.org/data/sphincs+-specification.pdf) Specification.

Date: June 14, 2018
Updated: July 2, 2021
Rust Translation: 2024

The primary public api for the Sphincs+ asymmetric signature scheme implementation:
```rust
use qrc_opensource_rs::{
  asymmetric::signature::sphincsplus::{
    qsc_sphincsplus_generate_keypair, qsc_sphincsplus_sign, qsc_sphincsplus_verify,
    QSC_SPHINCSPLUS_PRIVATEKEY_SIZE, QSC_SPHINCSPLUS_PUBLICKEY_SIZE, QSC_SPHINCSPLUS_SIGNATURE_SIZE, QRCS_CRYPTO_HASH_SIZE,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let privatekey = &mut [0u8; QSC_SPHINCSPLUS_PRIVATEKEY_SIZE];
let publickey = &mut [0u8; QSC_SPHINCSPLUS_PUBLICKEY_SIZE];
let hash = &mut [0u8; QRCS_CRYPTO_HASH_SIZE];
qsc_rcrng_generate(hash, QRCS_CRYPTO_HASH_SIZE);
let mut hashlen = 0;
let sig = &mut [0u8; QSC_SPHINCSPLUS_SIGNATURE_SIZE + QRCS_CRYPTO_HASH_SIZE];
let mut siglen = 0;

qsc_sphincsplus_generate_keypair(publickey, privatekey, qsc_rcrng_generate);
qsc_sphincsplus_sign(sig, &mut siglen, hash, QRCS_CRYPTO_HASH_SIZE, privatekey, qsc_rcrng_generate);
qsc_sphincsplus_verify(hash, &mut hashlen, sig, siglen, publickey);
```

### Cipher
#### AES
Rust Translation: 2024

The primary public api for the AES implementation:
```rust
use qrc_opensource_rs::{
    cipher::aes::{
        qsc_aes_initialize, qsc_aes_dispose, qsc_aes_ctrbe_transform,
        QSC_AES_BLOCK_SIZE, QSC_AES256_KEY_SIZE,
        QscAesKeyparams, QscAesState, QscAesCipherType, 
    },
    provider::rcrng::qsc_rcrng_generate,
};

let ctx = &mut QscAesState::default();
let msg = &mut [0u8; QSC_AES_BLOCK_SIZE];
qsc_rcrng_generate(msg, QSC_AES_BLOCK_SIZE);
let plain = &mut [0u8; QSC_AES_BLOCK_SIZE];
let nonce = &mut [0u8; QSC_AES_BLOCK_SIZE];
qsc_rcrng_generate(nonce, QSC_AES_BLOCK_SIZE);
let cipher = &mut [0u8; QSC_AES_BLOCK_SIZE];
let key = &mut [0u8; QSC_AES256_KEY_SIZE];
qsc_rcrng_generate(key, QSC_AES256_KEY_SIZE);

let nonce2 = &mut nonce.clone();
let kp = QscAesKeyparams {
  key: key.to_vec(), 
  keylen: QSC_AES256_KEY_SIZE,
  nonce: nonce2.to_vec(),
  info: [].to_vec(),
  infolen: 0,
};

qsc_aes_initialize(ctx, kp.clone(), QscAesCipherType::AES256);
qsc_aes_ctrbe_transform(ctx, cipher, msg, QSC_AES_BLOCK_SIZE);

qsc_aes_initialize(ctx, kp, QscAesCipherType::AES256);
qsc_aes_ctrbe_transform(ctx, plain, cipher, QSC_AES_BLOCK_SIZE);
qsc_aes_dispose(ctx);
```
```rust
use qrc_opensource_rs::{
    cipher::aes::{
        qsc_aes_hba256_initialize, qsc_aes_hba256_set_associated, qsc_aes_hba256_transform,
        QSC_AES_BLOCK_SIZE, QSC_AES256_KEY_SIZE, QSC_HBA256_MAC_LENGTH,
        QscAesKeyparams, QscAesHba256State, 
    },
    provider::rcrng::qsc_rcrng_generate,
};

let ctx = &mut QscAesHba256State::default();
let msg = &mut [0u8; QSC_AES_BLOCK_SIZE];
qsc_rcrng_generate(msg, QSC_AES_BLOCK_SIZE);
let plain = &mut [0u8; QSC_AES_BLOCK_SIZE];
let nonce = &mut [0u8; QSC_AES_BLOCK_SIZE];
qsc_rcrng_generate(nonce, QSC_AES_BLOCK_SIZE);
let cipher = &mut [0u8; QSC_AES_BLOCK_SIZE + QSC_HBA256_MAC_LENGTH];
let key = &mut [0u8; QSC_AES256_KEY_SIZE];
qsc_rcrng_generate(key, QSC_AES256_KEY_SIZE);
let aad = &mut [0u8; 20];
qsc_rcrng_generate(aad, 20);

let nonce2 = &mut nonce.clone();
let kp = QscAesKeyparams {
  key: key.to_vec(), 
  keylen: QSC_AES256_KEY_SIZE,
  nonce: nonce2.to_vec(),
  info: [].to_vec(),
  infolen: 0,
};

qsc_aes_hba256_initialize(ctx, kp.clone(), true);
qsc_aes_hba256_set_associated(ctx, aad, 20);
qsc_aes_hba256_transform(ctx, cipher, msg, QSC_AES_BLOCK_SIZE);

qsc_aes_hba256_initialize(ctx, kp, false);
qsc_aes_hba256_set_associated(ctx, aad, 20);
qsc_aes_hba256_transform(ctx, plain, cipher, QSC_AES_BLOCK_SIZE);
```
```rust
use qrc_opensource_rs::{
    cipher::aes::{
        qsc_aes_initialize, qsc_aes_dispose,
        qsc_aes_cbc_encrypt_block, qsc_aes_cbc_decrypt_block,
        qsc_aes_ecb_encrypt_block, qsc_aes_ecb_decrypt_block,
        QSC_AES_BLOCK_SIZE, QSC_AES256_KEY_SIZE,
        QscAesKeyparams, QscAesState, QscAesCipherType, 
    },
    provider::rcrng::qsc_rcrng_generate,
};

let ctx = &mut QscAesState::default();
let msg = &mut [0u8; QSC_AES_BLOCK_SIZE];
qsc_rcrng_generate(msg, QSC_AES_BLOCK_SIZE);
let plain = &mut [0u8; QSC_AES_BLOCK_SIZE];
let iv = &mut [0u8; QSC_AES_BLOCK_SIZE];
qsc_rcrng_generate(iv, QSC_AES_BLOCK_SIZE);
let cipher = &mut [0u8; QSC_AES_BLOCK_SIZE];
let key = &mut [0u8; QSC_AES256_KEY_SIZE];
qsc_rcrng_generate(key, QSC_AES256_KEY_SIZE);

let iv2 = &mut iv.clone();
let kp = QscAesKeyparams {
    key: key.to_vec(), 
    keylen: QSC_AES256_KEY_SIZE,
    nonce: iv2.to_vec(),
    info: [].to_vec(),
    infolen: 0,
};

qsc_aes_initialize(ctx, kp.clone(), QscAesCipherType::AES256);
/* cbc api */
qsc_aes_cbc_encrypt_block(ctx, cipher, msg);
/* ecb api */
qsc_aes_ecb_encrypt_block(ctx.to_owned(), cipher, msg);

qsc_aes_initialize(ctx, kp, QscAesCipherType::AES256);
/* cbc api */
qsc_aes_cbc_decrypt_block(ctx, plain, cipher);
/* ecb api */
qsc_aes_ecb_decrypt_block(ctx.to_owned(), plain, cipher);
qsc_aes_dispose(ctx);
```

### Digest
#### Sha2
The SHA2 and HMAC implementations use two different forms of api: short-form and long-form.
The short-form api, which initializes the state, processes a message, and finalizes by producing output, all in a single function call, for example; qsc_sha512_compute(), the entire message array is processed and the hash code is written to the output array.
The long-form api uses an initialization call to prepare the state, a update call to process the message, and the finalize call, which finalizes the state and generates a hash or mac-code.
The HKDF key derivation functions HKDF(HMAC(SHA2-256/512)), use only the short-form api, single-call functions, to generate pseudo-random to an output array.
Each of the function families (SHA2, HMAC, HKDF), have a corresponding set of reference constants associated with that member, example; QSC_HKDF_256_KEY_SIZE is the minimum expected HKDF-256 key size in bytes, QSC_HMAC_512_MAC_SIZE is the minimum size of the HMAC-512 output mac-code output array.

NIST: [The SHA-2 Standard](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf)
[Analysis of SIMD Applicability to SHA Algorithms](https://software.intel.com/sites/default/files/m/b/9/b/aciicmez.pdf)

Author: John Underhill - May 23, 2019
Updated: September 12, 2020
Rust Translation: 2024

The primary public api for SHA2 Implementation:
```rust
use qrc_opensource_rs::{
  digest::sha2::{
    qsc_hmac512_compute,
    QSC_SHA2_512_HASH, QSC_SHA2_512_RATE,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let hash = &mut [0u8; QSC_SHA2_512_HASH];
let msg = &mut [0u8; QSC_SHA2_512_RATE];
qsc_rcrng_generate(msg, QSC_SHA2_512_RATE);
let key = &mut [0u8; 50];
qsc_rcrng_generate(key, 50);

/* compact api */
qsc_hmac512_compute(hash, msg, QSC_SHA2_512_RATE, key, 50);
```
```rust
use qrc_opensource_rs::{
  digest::sha2::{
    qsc_sha512_initialize, qsc_sha512_blockupdate, qsc_sha512_finalize,
    QSC_SHA2_512_HASH, QSC_SHA2_512_RATE,
    QscSha512State,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let hash = &mut [0u8; QSC_SHA2_512_HASH];
let msg = &mut [0u8; QSC_SHA2_512_RATE];
qsc_rcrng_generate(msg, QSC_SHA2_512_RATE);

/* long-form api */
let ctx = &mut QscSha512State::default();
qsc_sha512_initialize(ctx);
qsc_sha512_blockupdate(ctx, msg, 1);
qsc_sha512_finalize(ctx, hash, msg, QSC_SHA2_512_RATE);
```

#### Sha3
The SHA3, SHAKE, cSHAKE, and KMAC implementations all share two forms of api: short-form and long-form.
The short-form api, which initializes the state, processes a message, and finalizes by producing output, all in a single function call, for example; qsc_sha3_compute512(), the entire message array is processed and the hash code is written to the output array.
The long-form api uses an initialization call to prepare the state, a blockupdate call if the message is longer than a single message block, and the finalize call, which finalizes the state and generates a hash, mac-code, or an array of pseudo-random.
Each of the function families (SHA3, SHAKE, KMAC), have a corresponding set of reference constants associated with that member, example; SHAKE_256_KEY is the minimum expected SHAKE-256 key size in bytes, QSC_KMAC_512_MAC_SIZE is the minimum size of the KMAC-512 output mac-code output array, and QSC_KECCAK_512_RATE is the SHA3-512 message absorption rate.

NIST: [SHA3 Fips202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)
NIST: [SP800-185](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)
NIST: [SHA3 Keccak Submission](http://keccak.noekeon.org/Keccak-submission-3.pdf)
NIST: [SHA3 Keccak Slides](http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf)
NIST: [SHA3 Third-Round Report](http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf)
Team Keccak: [Specifications summary](https://keccak.team/keccak_specs_summary.html)

Author: John Underhill - October 27, 2019
Updated: 19, 2021
Rust Translation: 2024

The primary public api for SHA3 digest, SHAKE, cSHAKE, and KMAC implementation:
```rust
use qrc_opensource_rs::{
  digest::sha3::{
    qsc_sha3_compute512, qsc_sha3_initialize, qsc_sha3_update, qsc_sha3_finalize, qsc_keccak_dispose,
    QSC_SHA3_512_HASH_SIZE,
    QscKeccakState, QscKeccakRate,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let hash = &mut [0u8; QSC_SHA3_512_HASH_SIZE];
let msg = &mut [0u8; 200];
qsc_rcrng_generate(msg, 200);

/* compact api */
qsc_sha3_compute512(hash, msg, 200);

/* long-form api */
let ctx = &mut QscKeccakState::default();
qsc_sha3_initialize(ctx);
qsc_sha3_update(ctx, QscKeccakRate::QscKeccakRate512 as usize, msg, 200);
qsc_sha3_finalize(ctx, QscKeccakRate::QscKeccakRate512 as usize, hash);
qsc_keccak_dispose(ctx);
```
```rust
use qrc_opensource_rs::{
  digest::sha3::{
    qsc_kmac512_compute, qsc_kmac_initialize, qsc_kmac_update, qsc_kmac_finalize,
    qsc_keccak_dispose, 
    QSC_SHA3_512_HASH_SIZE,
    QscKeccakState, QscKeccakRate,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let hash = &mut [0u8; QSC_SHA3_512_HASH_SIZE];
let msg = &mut [0u8; 200];
qsc_rcrng_generate(msg, 200);
let key = &mut [0u8; 50];
qsc_rcrng_generate(key, 50);
let cust = &mut [0u8; 100];
qsc_rcrng_generate(cust, 100);

/* compact api */
qsc_kmac512_compute(hash, QSC_SHA3_512_HASH_SIZE, msg, 200, key, 50, cust, 100);

/* long-form api */
let ctx = &mut QscKeccakState::default();
qsc_kmac_initialize(ctx, QscKeccakRate::QscKeccakRate512 as usize, key, 50, cust, 100);
qsc_kmac_update(ctx, QscKeccakRate::QscKeccakRate512 as usize, msg, 200);
qsc_kmac_finalize(ctx, QscKeccakRate::QscKeccakRate512 as usize, hash, QSC_SHA3_512_HASH_SIZE);
qsc_keccak_dispose(ctx);
```
```rust
use qrc_opensource_rs::{
  digest::sha3::{
    qsc_cshake512_compute, qsc_cshake_initialize, qsc_cshake_squeezeblocks, qsc_keccak_dispose, 
    QSC_KECCAK_512_RATE,
    QscKeccakState, QscKeccakRate,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let hash = &mut [0u8; QSC_KECCAK_512_RATE];
let msg = &mut [0u8; 200];
qsc_rcrng_generate(msg, 200);
let cust = &mut [0u8; 15];
qsc_rcrng_generate(cust, 15);

/* compact api */
qsc_cshake512_compute(hash, QSC_KECCAK_512_RATE, msg, 200, &[], 0, cust, 15);

/* long-form api */
let ctx = &mut QscKeccakState::default();
qsc_cshake_initialize(ctx, QscKeccakRate::QscKeccakRate512 as usize, msg, 200, &[], 0, cust, 15);
qsc_cshake_squeezeblocks(ctx, QscKeccakRate::QscKeccakRate512 as usize, hash, 1);
qsc_keccak_dispose(ctx);
```
```rust
use qrc_opensource_rs::{
  digest::sha3::{
    qsc_shake512_compute, qsc_shake_initialize, qsc_shake_squeezeblocks, qsc_keccak_dispose, 
    QscKeccakState, QscKeccakRate,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let hash = &mut [0u8; 512];
let msg = &mut [0u8; 200];
qsc_rcrng_generate(msg, 200);

/* compact api */
qsc_shake512_compute(hash, 512, msg, 200);

/* long-form api */
let ctx = &mut QscKeccakState::default();
qsc_shake_initialize(ctx, QscKeccakRate::QscKeccakRate512 as usize, msg, 200);
qsc_shake_squeezeblocks(ctx, QscKeccakRate::QscKeccakRate512 as usize, hash, 1);
qsc_keccak_dispose(ctx);
```

### Mac
#### Poly1305
Rust Translation: 2024

The primary public api for the Poly1305 implementation:
```rust
use qrc_opensource_rs::{
  mac::poly1305::{
    qsc_poly1305_compute, qsc_poly1305_initialize, qsc_poly1305_update, qsc_poly1305_finalize, 
    QscPoly1305State,
  },
  provider::rcrng::qsc_rcrng_generate,
};

let key = &mut [0u8; 32];
qsc_rcrng_generate(key, 32);
let mac = &mut [0u8; 16];
let msg = &mut [0u8; 64];
qsc_rcrng_generate(msg, 64);

/* compact api */
qsc_poly1305_compute(mac, msg, 64, key); 

/* long-form api */
let ctx = &mut QscPoly1305State::default();
qsc_poly1305_initialize(ctx, key);
qsc_poly1305_update(ctx, msg, 64);
qsc_poly1305_finalize(ctx, mac);
```

## Roadmap

NOTE The package is under active development. As such, it is likely to
remain volatile until a 1.0.0 release.

Todo:
<ul>
  <li>Asymmetric/Cipher/ECDH</li>
  <li>Asymmetric/Cipher/NTRU</li>
  <li>Asymmetric/Signature/Dilithium</li>
  <li>Asymmetric/Signature/ECDSA</li>
  <li>Asymmetric/Signature/Falcon</li>
  <li>Cipher/ChaCha20</li>
  <li>Numerics/Donna128</li>
<ul>
</ul>
  <li>Missing Functions Of Modules Added (Sha2/3, Aes, etc)</li>
  <li>Final Format Update</li>
</ul>


## License

The contents of this repository are licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3.
See [LICENSE](LICENSE) for more information on the license.