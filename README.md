<br />
<p>
  <a href="https://www.qrcrypto.ch/">
    <img src="https://www.qrcrypto.ch/images/logo-quantum-resistant.svg" alt="Logo" width="350">
  </a>

<h3>qrc-opensource-rs</h3>
<p>
The free opensource version of the Quantum Secure Cryptographic library in Rust (QRC)
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

First add the ``qrc-opensource-rs`` crate to your ``Cargo.toml``:

```sh
[dependencies]
qrc-opensource-rs = "0.3"
```

### Features

###### Feature List

<table>
  <tr>
    <td>
      Name
    </td>
    <td>
      Dependencies
    </td>
    <td>
      Target
    </td>
    <td>
      Description
    </td>
  </tr>
  <tr>
    <td>
      std
    </td>
    <td>-</td>
    <td>
      STD
    </td>
    <td>
      Default Feature
    </td>
  </tr>
  <tr>
    <td>
      all-tools
    </td>
    <td>
      var-tools<br>
      sys-tools<br>
    </td>
    <td>
      STD
    </td>
    <td>
      All STD Tools
    </td>
  </tr>
  <tr>
    <td>
      var-tools
    </td>
    <td>
      intutils<br>
      memutils<br>
      stringutils<br>
      sysutils<br>
    </td>
    <td>
      STD
    </td>
    <td>
      All Variable Manipulation Tools 
    </td>
  </tr>
  <tr>
    <td>
      sys-tools
    </td>
    <td>
      consoleutils<br>
      fileutils<br>
      folderutils
    </td>
    <td>
      STD
    </td>
    <td>
      All System Tools
    </td>
  </tr>
  <tr>
    <td>
      no_std
    </td>
    <td>-</td>
    <td>
      NO_STD
    </td>
    <td>
      Standard And Required Feature For NO_STD
    </td>
  </tr>
  <tr>
    <td>
      var-tools-no_std
    </td>
    <td>
      no_std<br>
      intutils<br>
      memutils<br>
      sysutils<br>
    </td>
    <td>
      NO_STD
    </td>
    <td>
      All NO_STD Compatible Variable Manipulation Tools 
    </td>
  </tr>
  <tr>
    <td>
      memutils
    </td>
    <td>-</td>
    <td>
      STD<br>
      NO_STD
    </td>
    <td>
      Memory Manipulation Tools
    </td>
  </tr>
  <tr>
    <td>
      intutils
    </td>
    <td>-</td>
    <td>
      STD<br>
      NO_STD
    </td>
    <td>
      Common Integer Tools
    </td>
  </tr>
  <tr>
    <td>
      sysutils
    </td>
    <td>-</td>
    <td>
      STD<br>
      SEMI<br>
      NO_STD
    </td>
    <td>
      System Information Gathering Tools
    </td>
  </tr>
  <tr>
    <td>
      stringutils
    </td>
    <td>-</td>
    <td>
      STD
    </td>
    <td>
      String Manipulation Tools
    </td>
  </tr>
  <tr>
    <td>
      folderutils
    </td>
    <td>-</td>
    <td>
      STD
    </td>
    <td>
      System Directory Gathering Tools
    </td>
  </tr>
  <tr>
    <td>
      fileutils
    </td>
    <td>-</td>
    <td>
      STD
    </td>
    <td>
      File System Communication Tools
    </td>
  </tr>
  <tr>
    <td>
      consoleutils
    </td>
    <td>-</td>
    <td>
      STD
    </td>
    <td>
      Console/Terminal System Tools
    </td>
  </tr>
    <tr>
    <td>
      log-no_std
    </td>
    <td>-</td>
    <td>
      NO_STD
    </td>
    <td>
      Console/Terminal Logging Tools
    </td>
  </tr>
</table>

###### Cryptographic Parameter  Features

The following features set the parameters for the cryptographic functions

<table>
  <tr>
    <td>
      Name
    </td>
    <td>
      Description
    </td>
    <td>
      Default
    </td>
  </tr>
  <tr>
    <td>
      ECDH_S1EC25519
    </td>
    <td>
      Implement the ECDH S1EC25519 parameter set
    </td><td>x</td>
  </tr>
  <tr><td></td><td></td><td></td></tr>
    <tr>
    <td>
      KYBER_S3Q3329N256K3
    </td>
    <td>
      Implement the Kyber S3Q3329N256K3 parameter set
    </td><td></td>
  </tr>
  <tr>
    <td>
      KYBER_S5Q3329N256K4
    </td>
    <td>
      Implement the Kyber S5Q3329N256K4 parameter set
    </td><td>x</td>
  </tr>
  <tr>
    <td>
      KYBER_S6Q3329N256K5
    </td>
    <td>
      Implement the Kyber S6Q3329N256K5 parameter set. (Experimental only)
    </td><td></td>
  </tr>
  <tr><td></td><td></td><td></td></tr>
  <tr>
    <td>
      MCELIECE_S3N4608T96
    </td>
    <td>
      Implement the McEliece S3-N4608T96 parameter set
    </td><td></td>
  </tr>
  <tr>
    <td>
      MCELIECE_S5N6688T128
    </td>
    <td>
      Implement the McEliece S5-N6688T128 parameter set
    </td><td>x</td>
  </tr>
  <tr>
    <td>
      MCELIECE_S5N6960T119
    </td>
    <td>
      Implement the McEliece S5-N6960T119 parameter set
    </td><td></td>
  </tr>
  <tr>
    <td>
      MCELIECE_S5N8192T128
    </td>
    <td>
      Implement the McEliece S5-N8192T128 parameter set
    </td><td></td>
  </tr>
  <tr><td></td><td></td><td></td></tr>
  <tr>
    <td>
      DILITHIUM_S2N256Q8380417K4
    </td>
    <td>
      Implement the Dilithium S2N256Q8380417 parameter set
    </td><td></td>
  </tr>
  <tr>
    <td>
      DILITHIUM_S3N256Q8380417K6
    </td>
    <td>
      Implement the Dilithium S3N256Q83804 parameter set
    </td><td>x</td>
  </tr>
  <tr>
    <td>
      DILITHIUM_S5N256Q8380417K8
    </td>
    <td>
      Implement the Dilithium S5N256Q8380417 parameter set
    </td><td></td>
  </tr>
  <tr><td></td><td></td><td></td></tr>
  <tr>
    <td>
      ECDSA_S1EC25519
    </td>
    <td>
      Implement the ECDSA S1EC25519 parameter set
    </td><td>x</td>
  </tr>
  <tr><td></td><td></td><td></td></tr>
  <!--<tr>
    <td>
      FALCON_S3SHAKE256F512
    </td>
    <td>
      Implement the Falcon S3SHAKE256F512 parameter set
    </td><td></td>
  </tr>
  <tr>
    <td>
      FALCON_S5SHAKE256F1024
    </td>
    <td>
      Implement the Falcon S5SHAKE256F1024 parameter set
    </td><td>x</td>
  </tr>
  <tr><td></td><td></td><td></td></tr>-->
  <tr>
    <td>
      SPHINCSPLUS_S3S192SHAKERS
    </td>
    <td>
      Implement the SphincsPlus S3S192SHAKERS robust small parameter set
    </td><td></td>
  </tr>
  <tr>
    <td>
      SPHINCSPLUS_S3S192SHAKERF
    </td>
    <td>
      Implement the SphincsPlus S3S192SHAKERF robust fast parameter set
    </td><td></td>
  </tr>
  <tr>
    <td>
      SPHINCSPLUS_S5S256SHAKERS
    </td>
    <td>
      Implement the SphincsPlus S5S256SHAKERS robust small parameter set
    </td><td></td>
  </tr>
  <tr>
    <td>
      SPHINCSPLUS_S5S256SHAKERF
    </td>
    <td>
      Implement the SphincsPlus S5S256SHAKERF robust fast parameter set
    </td><td>x</td>
  </tr>
  <tr><td></td><td></td><td></td></tr>
  <tr>
    <td>
      MIN_MEMORY_CLEAR
    </td>
    <td>
      Disables secure memory clearing (Compatibility only)
    </td><td></td>
  </tr>
</table>


###### Feature Usage

```sh
[dependencies]
qrc-opensource-rs = { version = "0.3", features = ["FEATURE1", "FEATURE2"] }
```

### Examples

  View our Documentation for further information on how to impliment this crate at [Docs.rs](https://docs.rs/qrc-opensource-rs)

<ul>
    <li>
        <summary><p style="display: inline-block">Asymmetric</p></summary>
        <ul>
          <li>
              <summary><p style="display: inline-block">Cipher</p></summary>
              <ul>
                <li><a href="#ecdh">ECDH</a></li>
                <li><a href="#kyber">Kyber</a></li>
                <li><a href="#mceliece">McEliece</a></li>
              </ul>
          </li>
          <li>
              <summary><p style="display: inline-block">Signature</p></summary>
              <ul>
                <li><a href="#dilithium">Dilithium</a></li>
                <li><a href="#ecdsa">ECDSA</a></li>
                <!--<li><a href="#falcon">Falcon</a></li>-->
                <li><a href="#sphincsplus">SphincsPlus</a></li>
              </ul>
          </li>
        </ul>
    </li>
    <li>
        <summary><p style="display: inline-block">Cipher</p></summary>
        <ul>
          <li><a href="#aes">AES</a></li>
          <li><a href="#chacha">ChaCha</a></li>
          <li><a href="#csx">CSX</a></li>
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
      <summary><p style="display: inline-block">DRBG</p></summary>
      <ul>
        <li><a href="#csg">CSG</a></li>
        <li><a href="#hcg">HCG</a></li>
        <li><a href="#scb">SCB</a></li>
      </ul>
    </li>
    <li>
        <summary><p style="display: inline-block">Mac</p></summary>
        <ul>
          <li><a href="#poly1305">Poly1305</a></li>
        </ul>
    </li>
    <li>
      <summary><p style="display: inline-block">Numerics</p></summary>
      <ul>
        <li><a href="#donna128">Donna128</a></li>
      </ul>
    </li>
    <li>
      <summary><p style="display: inline-block">PRNG</p></summary>
      <ul>
        <li><a href="#nistrng">NistRng</a></li>
        <li><a href="#secrand">SecRand</a></li>
      </ul>
    </li>
    <li>
      <summary><p style="display: inline-block">Provider</p></summary>
      <ul>
      <li><a href="#rcrng">RcRng</a></li>
        <li><a href="#osrng">OsRng</a></li>
        <li><a href="#trng">Trng</a></li>
      </ul>
    </li>
  </ul>

#### Asymmetric

##### Cipher

###### ECDH

Reference implementations:<br>
[LibSodium by Frank Denis](https://github.com/jedisct1/libsodium)<br>
[curve25519-donna by Adam Langley](https://github.com/agl/curve25519-donna)<br>
[NaCI by Daniel J. Bernstein, Tanja Lange, Peter Schwabe](https://nacl.cr.yp.to)<br>

Rewritten for Misra compliance and optimization<br>
Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Date:  John G. Underhill - September 21, 2020<br>
Rust Translation: Matt Warminger - 2025<br>

The primary public api for the Elliptic Curve Diffie Hellman key exchange:

```rust
use qrc_opensource_rs::{
    asymmetric::cipher::ecdh::{
        qrc_ecdh_generate_seeded_keypair, qrc_ecdh_key_exchange, 
        QRC_ECDH_PRIVATEKEY_SIZE, QRC_ECDH_PUBLICKEY_SIZE, QRC_ECDH_SEED_SIZE, QRC_ECDH_SHAREDSECRET_SIZE
    }, 
    provider::rcrng::qrc_rcrng_generate
};

let mut seed1 = [0u8; QRC_ECDH_SEED_SIZE];
qrc_rcrng_generate(&mut seed1, QRC_ECDH_SEED_SIZE);
let mut seed2 = [0u8; QRC_ECDH_SEED_SIZE];
qrc_rcrng_generate(&mut seed2, QRC_ECDH_SEED_SIZE);

let publickey1 = &mut [0u8; QRC_ECDH_PUBLICKEY_SIZE];
let publickey2 = &mut [0u8; QRC_ECDH_PUBLICKEY_SIZE];
let privatekey1 = &mut [0u8; QRC_ECDH_PRIVATEKEY_SIZE];
let privatekey2 = &mut [0u8; QRC_ECDH_PRIVATEKEY_SIZE];

let secret1 = &mut [0u8; QRC_ECDH_SHAREDSECRET_SIZE];
let secret2 = &mut [0u8; QRC_ECDH_SHAREDSECRET_SIZE];

qrc_ecdh_generate_seeded_keypair(publickey1, privatekey1, &seed1);
qrc_ecdh_generate_seeded_keypair(publickey2, privatekey2, &seed2);

qrc_ecdh_key_exchange(secret1, privatekey1, publickey2);
qrc_ecdh_key_exchange(secret2, privatekey2, publickey1);
```

###### Kyber

Based on the C reference branch of PQ-Crystals Kyber; including base code, comments, and api.<br>
Removed the K=2 parameter, and added a K=5. The NIST '512' parameter has fallen below the threshold
required by NIST PQ S1 minimum.<br>
The new K5 parameter may have a better chance of long-term security, with only a small increase in cost.<br>

The NIST Post Quantum Competition [Round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions) Finalists.<br>
The [Kyber](https://pq-crystals.org/kyber/index.shtml) website.<br>
The Kyber [Algorithm](https://pq-crystals.org/kyber/data/kyber-specification-round3-20210131.pdf) Specification.<br>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Date: January 10, 2018<br>
C - Updated: Stiepan A. Kovac - July 2, 2021<br>
Rust Translation: Matt Warminger - 2024<br>
Updated: QRC - April 23, 2025<br>

The primary public api for the Kyber CCA-secure Key Encapsulation Mechanism implementation:

```rust
use qrc_opensource_rs::{
  asymmetric::cipher::kyber::{
    qrc_kyber_generate_keypair, qrc_kyber_encrypt, qrc_kyber_decrypt,
    QRC_KYBER_SEED_SIZE, QRC_KYBER_PUBLICKEY_SIZE, QRC_KYBER_PRIVATEKEY_SIZE, QRC_KYBER_SHAREDSECRET_SIZE, QRC_KYBER_CIPHERTEXT_SIZE
  },
  provider::rcrng::qrc_rcrng_generate,
};

let mut seed = [0u8; QRC_KYBER_SEED_SIZE];
qrc_rcrng_generate(&mut seed, QRC_KYBER_SEED_SIZE);

let publickey = &mut [0u8; QRC_KYBER_PUBLICKEY_SIZE];
let privatekey = &mut [0u8; QRC_KYBER_PRIVATEKEY_SIZE];

let secret1 = &mut [0u8; QRC_KYBER_SHAREDSECRET_SIZE];
let secret2 = &mut [0u8; QRC_KYBER_SHAREDSECRET_SIZE];

let ciphertext = &mut [0u8; QRC_KYBER_CIPHERTEXT_SIZE];

qrc_kyber_generate_keypair(publickey, privatekey, seed);
qrc_kyber_encrypt(secret1, ciphertext, publickey, seed);
qrc_kyber_decrypt(secret2, ciphertext, privatekey);
```

###### McEliece

Classic McEliece is a KEM designed for IND-CCA2 security at a very high security level, even against quantum computers.<br>
The KEM is built conservatively from a PKE designed for OW-CPA security, namely Niederreiter's dual version of McEliece's PKE using binary Goppa codes.<br>
Every level of the construction is designed so that future cryptographic auditors can be confident in the long-term security of post-quantum public-key encryption.<br>

Based entirely on the C reference branch of Dilithium taken from the NIST Post Quantum Competition Round 3 submission.<br>
The NIST Post Quantum Competition [Round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions) Finalists.<br>
The [McEliece](https://classic.mceliece.org/) website.<br>
The McEliece [Algorithm](https://classic.mceliece.org/nist/mceliece-20201010.pdf) Specification.<br>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Authors: Daniel J. Bernstein, Tung Chou, Tanja Lange, and Peter Schwabe.<br>
Updated: Stiepan A. Kovac - June 28 2021<br>
Rust Translation: Matt Warminger - 2024<br>
Updated: QRC - July 7, 2025<br>

The primary public api for the Niederreiter dual form of the McEliece asymmetric cipher implementation:

```rust
use qrc_opensource_rs::{
  asymmetric::cipher::mceliece::{
    qrc_mceliece_generate_keypair, qrc_mceliece_encrypt, qrc_mceliece_decrypt,
    QRC_MCELIECE_CIPHERTEXT_SIZE, QRC_MCELIECE_PRIVATEKEY_SIZE, QRC_MCELIECE_PUBLICKEY_SIZE, QRC_MCELIECE_SHAREDSECRET_SIZE, QRC_MCELIECE_SEED_SIZE,
  },
  provider::rcrng::qrc_rcrng_generate,
};

let mut seed = [0u8; QRC_MCELIECE_SEED_SIZE];
qrc_rcrng_generate(&mut seed, QRC_MCELIECE_SEED_SIZE);

let publickey = &mut vec![0u8; QRC_MCELIECE_PUBLICKEY_SIZE];
let privatekey = &mut vec![0u8; QRC_MCELIECE_PRIVATEKEY_SIZE];

let secret1 = &mut [0u8; QRC_MCELIECE_SHAREDSECRET_SIZE];
let secret2 = &mut [0u8; QRC_MCELIECE_SHAREDSECRET_SIZE];

let ciphertext = &mut [0u8; QRC_MCELIECE_CIPHERTEXT_SIZE];

qrc_mceliece_generate_keypair(publickey, privatekey, seed);
qrc_mceliece_encrypt(secret1, ciphertext, publickey, seed);
qrc_mceliece_decrypt(secret2, ciphertext, privatekey);
```

##### Signature

###### Dilithium

Based entirely on the C reference branch of Dilithium taken from the NIST Post Quantum Competition Round 3 submission.<br>
The NIST Post Quantum Competition [Round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions) Finalists.<br>
* The [Dilithium](https://pq-crystals.org/dilithium/index.shtml) web-site.<br>
* The Dilithium [Algorithm](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf) Specification.<br>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Date: July 2, 2021<br>
Rust Translation: Matt Warminger - 2025<br>

The primary public api for the Dilithium asymmetric signature scheme implementation:

```rust
use qrc_opensource_rs::asymmetric::signature::dilithium::{
  qrc_dilithium_generate_keypair, qrc_dilithium_sign, qrc_dilithium_verify,
  QRC_DILITHIUM_PRIVATEKEY_SIZE, QRC_DILITHIUM_PUBLICKEY_SIZE, QRC_DILITHIUM_SIGNATURE_SIZE
};

let msg = &mut [0u8; 64];
let sig = &mut [0u8; QRC_DILITHIUM_SIGNATURE_SIZE + 64];
let sk = &mut [0u8; QRC_DILITHIUM_PRIVATEKEY_SIZE];
let pk = &mut [0u8; QRC_DILITHIUM_PUBLICKEY_SIZE];

let msglen = &mut (64isize);
let siglen = &mut 0;

qrc_dilithium_generate_keypair(pk, sk);
qrc_dilithium_sign(sig, siglen, msg, 64, sk);
qrc_dilithium_verify(msg, msglen, sig, siglen.clone(), pk);
```

###### ECDSA

Reference implementations:<br>
[LibSodium by Frank Denis](https://github.com/jedisct1/libsodium)<br>
[curve25519-donna by Adam Langley](https://github.com/agl/curve25519-donna)<br>
[NaCI by Daniel J. Bernstein, Tanja Lange, Peter Schwabe](https://nacl.cr.yp.to)<br>

Rewritten for Misra compliance and optimization<br>
Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Date:  John G. Underhill - September 21, 2020<br>
Rust Translation: Matt Warminger - 2025<br>

The primary public api for the ECDSA asymmetric signature scheme implementation:

```rust
use qrc_opensource_rs::{
    asymmetric::signature::ecdsa::{
        qrc_ecdsa_generate_seeded_keypair, qrc_ecdsa_sign, qrc_ecdsa_verify, 
        QRC_ECDSA_PRIVATEKEY_SIZE, QRC_ECDSA_PUBLICKEY_SIZE, QRC_ECDSA_SEED_SIZE, QRC_ECDSA_SIGNATURE_SIZE
    }, 
    provider::rcrng::qrc_rcrng_generate
};

let msg = &mut [0u8; 64];
let mout = &mut [0u8; QRC_ECDSA_SIGNATURE_SIZE + 64];
let seed = &mut [0u8; QRC_ECDSA_SEED_SIZE];
qrc_rcrng_generate(seed, QRC_ECDSA_SEED_SIZE);
let sig = &mut [0u8; QRC_ECDSA_SIGNATURE_SIZE + 64];
let privatekey = &mut [0u8; QRC_ECDSA_PRIVATEKEY_SIZE];
let publickey = &mut [0u8; QRC_ECDSA_PUBLICKEY_SIZE];

let msglen = &mut (64usize);
let siglen = &mut (QRC_ECDSA_SIGNATURE_SIZE + 64);

qrc_ecdsa_generate_seeded_keypair(publickey, privatekey, seed);
qrc_ecdsa_sign(sig, siglen, msg, msglen.clone(), privatekey);
qrc_ecdsa_verify(mout, msglen, sig, siglen.clone(), publickey);
```
<!--
###### Falcon

Based entirely on the C reference branch of Falcon taken from the NIST Post Quantum Competition Round 3 submission.<br>
The NIST Post Quantum Competition [Round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions) Finalists.<br>
The [Falcon](https://falcon-sign.info/) website.<br>
The Falcon [Algorithm](https://falcon-sign.info/falcon.pdf) Specification.<br>


Rewritten for Misra compliance and library integration<br>
Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Author: Thomas Pornin <thomas.pornin@nccgroup.com><br>
Updated: John G. Underhill<br>
Rust Translation: Matt Warminger - 2025<br>

The primary public api for the Falcon asymmetric signature scheme implementation:

```rust

```
-->

###### SphincsPlus

Based entirely on the C reference branch of SPHINCS+ taken from the NIST Post Quantum Competition Round 3 submission.<br>
The NIST Post Quantum Competition [Round 3](https://csrc.nist.gov/Projects/post-quantum-cryptography/round-3-submissions) Finalists.<br>
The [SPHINCS+](https://sphincs.org/) website.<br>
The SPHINCS+ [Algorithm](https://sphincs.org/data/sphincs+-specification.pdf) Specification.<br>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Date: John G. Underhill - June 14, 2018<br>
Updated: February 7, 2024<br>
Rust Translation: Matt Warminger - 2024<br>
Updated: QRC - July 9, 2025<br>

The primary public api for the Sphincs+ asymmetric signature scheme implementation:

```rust
use qrc_opensource_rs::{
  asymmetric::signature::sphincsplus::{
    qrc_sphincsplus_generate_keypair, qrc_sphincsplus_sign, qrc_sphincsplus_verify,
    QRC_SPHINCSPLUS_PRIVATEKEY_SIZE, QRC_SPHINCSPLUS_PUBLICKEY_SIZE, QRC_SPHINCSPLUS_SIGNATURE_SIZE,
  },
  provider::rcrng::qrc_rcrng_generate,
};

let privatekey = &mut [0u8; QRC_SPHINCSPLUS_PRIVATEKEY_SIZE];
let publickey = &mut [0u8; QRC_SPHINCSPLUS_PUBLICKEY_SIZE];
let hash = &mut [0u8; 64];
qrc_rcrng_generate(hash, 64);
let mut hashlen = 0;
let sig = &mut [0u8; QRC_SPHINCSPLUS_SIGNATURE_SIZE + 64];
let mut siglen = 0;

qrc_sphincsplus_generate_keypair(publickey, privatekey);
qrc_sphincsplus_sign(sig, &mut siglen, hash, 64, privatekey);
qrc_sphincsplus_verify(hash, &mut hashlen, sig, siglen, publickey);
```

#### Cipher

##### AES

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Rust Translation: Matt Warminger - 2024<br>
Updated: QRC - April 23, 2025<br>

The primary public api for the AES implementation:

```rust
use qrc_opensource_rs::{
    cipher::aes::{
        qrc_aes_initialize, qrc_aes_dispose, qrc_aes_ctrbe_transform,
        QRC_AES_BLOCK_SIZE, QRC_AES256_KEY_SIZE,
        QrcAesKeyparams, QrcAesState, QrcAesCipherType, 
    },
    provider::rcrng::qrc_rcrng_generate,
};

let ctx = &mut QrcAesState::default();
let msg = &mut [0u8; QRC_AES_BLOCK_SIZE];
qrc_rcrng_generate(msg, QRC_AES_BLOCK_SIZE);
let plain = &mut [0u8; QRC_AES_BLOCK_SIZE];
let nonce = &mut [0u8; QRC_AES_BLOCK_SIZE];
qrc_rcrng_generate(nonce, QRC_AES_BLOCK_SIZE);
let cipher = &mut [0u8; QRC_AES_BLOCK_SIZE];
let key = &mut [0u8; QRC_AES256_KEY_SIZE];
qrc_rcrng_generate(key, QRC_AES256_KEY_SIZE);

let kp = QrcAesKeyparams {
  key: key.to_vec(), 
  keylen: QRC_AES256_KEY_SIZE,
  nonce: nonce.to_vec(),
  info: [].to_vec(),
  infolen: 0,
};

qrc_aes_initialize(ctx, kp.clone(), QrcAesCipherType::AES256);
qrc_aes_ctrbe_transform(ctx, cipher, msg, QRC_AES_BLOCK_SIZE);

qrc_aes_initialize(ctx, kp, QrcAesCipherType::AES256);
qrc_aes_ctrbe_transform(ctx, plain, cipher, QRC_AES_BLOCK_SIZE);
qrc_aes_dispose(ctx);
```

```rust
use qrc_opensource_rs::{
    cipher::aes::{
        qrc_aes_hba256_initialize, qrc_aes_hba256_set_associated, qrc_aes_hba256_transform,
        QRC_AES_BLOCK_SIZE, QRC_AES256_KEY_SIZE, QRC_HBA256_MAC_LENGTH,
        QrcAesKeyparams, QrcAesHba256State, 
    },
    provider::rcrng::qrc_rcrng_generate,
};

let ctx = &mut QrcAesHba256State::default();
let msg = &mut [0u8; QRC_AES_BLOCK_SIZE];
qrc_rcrng_generate(msg, QRC_AES_BLOCK_SIZE);
let plain = &mut [0u8; QRC_AES_BLOCK_SIZE];
let nonce = &mut [0u8; QRC_AES_BLOCK_SIZE];
qrc_rcrng_generate(nonce, QRC_AES_BLOCK_SIZE);
let cipher = &mut [0u8; QRC_AES_BLOCK_SIZE + QRC_HBA256_MAC_LENGTH];
let key = &mut [0u8; QRC_AES256_KEY_SIZE];
qrc_rcrng_generate(key, QRC_AES256_KEY_SIZE);
let aad = &mut [0u8; 20];
qrc_rcrng_generate(aad, 20);

let kp = QrcAesKeyparams {
  key: key.to_vec(), 
  keylen: QRC_AES256_KEY_SIZE,
  nonce: nonce.to_vec(),
  info: [].to_vec(),
  infolen: 0,
};

qrc_aes_hba256_initialize(ctx, kp.clone(), true);
qrc_aes_hba256_set_associated(ctx, aad, 20);
qrc_aes_hba256_transform(ctx, cipher, msg, QRC_AES_BLOCK_SIZE);

qrc_aes_hba256_initialize(ctx, kp, false);
qrc_aes_hba256_set_associated(ctx, aad, 20);
qrc_aes_hba256_transform(ctx, plain, cipher, QRC_AES_BLOCK_SIZE);
```

```rust
use qrc_opensource_rs::{
    cipher::aes::{
        qrc_aes_initialize, qrc_aes_dispose,
        qrc_aes_cbc_encrypt_block, qrc_aes_cbc_decrypt_block,
        qrc_aes_ecb_encrypt_block, qrc_aes_ecb_decrypt_block,
        QRC_AES_BLOCK_SIZE, QRC_AES256_KEY_SIZE,
        QrcAesKeyparams, QrcAesState, QrcAesCipherType, 
    },
    provider::rcrng::qrc_rcrng_generate,
};

let ctx = &mut QrcAesState::default();
let msg = &mut [0u8; QRC_AES_BLOCK_SIZE];
qrc_rcrng_generate(msg, QRC_AES_BLOCK_SIZE);
let plain = &mut [0u8; QRC_AES_BLOCK_SIZE];
let iv = &mut [0u8; QRC_AES_BLOCK_SIZE];
qrc_rcrng_generate(iv, QRC_AES_BLOCK_SIZE);
let cipher = &mut [0u8; QRC_AES_BLOCK_SIZE];
let key = &mut [0u8; QRC_AES256_KEY_SIZE];
qrc_rcrng_generate(key, QRC_AES256_KEY_SIZE);

let kp = QrcAesKeyparams {
    key: key.to_vec(), 
    keylen: QRC_AES256_KEY_SIZE,
    nonce: iv.to_vec(),
    info: [].to_vec(),
    infolen: 0,
};

qrc_aes_initialize(ctx, kp.clone(), QrcAesCipherType::AES256);
/* cbc api */
qrc_aes_cbc_encrypt_block(ctx, cipher, msg);
/* ecb api */
qrc_aes_ecb_encrypt_block(ctx.to_owned(), cipher, msg);

qrc_aes_initialize(ctx, kp, QrcAesCipherType::AES256);
/* cbc api */
qrc_aes_cbc_decrypt_block(ctx, plain, cipher);
/* ecb api */
qrc_aes_ecb_decrypt_block(ctx.to_owned(), plain, cipher);
qrc_aes_dispose(ctx);
```

##### ChaCha

Key sizes are 128- and 256-bit (16 and 32 byte).<br>
The nonce must be 64-bits in length (8 bytes).<br>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Author: John G. Underhill - April 7, 2018<br>
Rust Translation: Matt Warminger - 2025<br>
Updated: QRC - April 23, 2025<br>

An implementation of the ChaChaPoly20 stream cipher by Daniel J. Bernstein:

```rust
use qrc_opensource_rs::{
        cipher::chacha::{
            	qrc_chacha_dispose, qrc_chacha_initialize, qrc_chacha_transform,
            	QrcChachaKeyparams, QrcChachaState, QRC_CHACHA_KEY256_SIZE, QRC_CHACHA_NONCE_SIZE
	}, provider::rcrng::qrc_rcrng_generate
};

let out = &mut [0u8; 64];
let msg = &mut [0u8; 64];
qrc_rcrng_generate(msg, 64);
let key = &mut [0u8; QRC_CHACHA_KEY256_SIZE];
qrc_rcrng_generate(key, QRC_CHACHA_KEY256_SIZE);
let nonce = &mut [0u8; QRC_CHACHA_NONCE_SIZE];
qrc_rcrng_generate(nonce, QRC_CHACHA_NONCE_SIZE);
let ctx = &mut QrcChachaState::default();

let kp = &mut QrcChachaKeyparams::default();
kp.key = key.to_vec();
kp.keylen = QRC_CHACHA_KEY256_SIZE;
kp.nonce = nonce.to_vec();

qrc_chacha_initialize(ctx, kp.clone());
qrc_chacha_transform(ctx, out, msg, 64);
qrc_chacha_dispose(ctx);
```

##### CSX

An EXPERIMENTAL vectorized, 64-bit, 40-round stream cipher CSX512 implementation based on ChaCha.<br>
This cipher uses KMAC-512 to authenticate the cipher-text stream in an encrypt-then-mac authentication configuration.<br>
The CSX (authenticated Cipher Stream, ChaCha eXtended) cipher, is a hybrid of the ChaCha stream cipher,
using 64-bit integers, a 1024-bit block and a 512-bit key.<br>

The pseudo-random bytes generator used by this cipher is the Keccak cSHAKE extended output function (XOF).<br>
The cSHAKE XOF is implemented in the 512-bit form of that function, and used to expand the input cipher-key into the cipher and MAC keys.<br>
CSX-512 uses a 512-bit input key, an a 16 byte nonce, and an optional tweak; the info parameter, up to 48 bytes in length.<br>

This is a 'tweakable cipher', the initialization parameters; qrc_csx_keyparams, include an info parameter that can be used as a secondary user input.<br>
Internally, the info parameter is used to customize the cSHAKE output, using the cSHAKE 'custom' parameter to pre-initialize the SHAKE state.<br>
The info parameter can be tweaked, with a user defined string 'info' in an qrc_csx_keyparams structure passed to the csx_intitialize(state,keyparams,encrypt).<br>
This tweak can be used as a 'domain key', or to differentiate cipher-text output from other implementations, or as a secondary secret-key input.<br>

CSX is an authenticated encryption with associated data (AEAD) stream cipher.<br>
The cSHAKE key-expansion function generates a key for the keyed hash-based MAC function; KMAC, used to generate the authentication code,
which is appended to the cipher-text output of an encryption call.<br>
In decryption mode, before decryption is performed, an internal mac code is calculated, and compared to the code embedded in the cipher-text.<br>
If authentication fails, the cipher-text is not decrypted, and the qrc_csx_transform(state,out,in,inlen) function returns a boolean false value.<br>
The qrc_csx_set_associated(state,in,inlen) function can be used to add additional data to the MAC generators input, like packet-header data, or a custom code or counter.<br>

For authentication CSX can use either the standard form of KMAC, which uses 24 rounds, or the default authentication setting;
a reduced-rounds version of KMAC that uses half the number of permutation rounds KMAC-R12.<br>
To enable the standard from of KMAC, pass the QRC_RCS_AUTH_KMAC as a compiler definition, or unrem the definition in this header file.<br>
To run CSX without authentication, remove the QRC_RCS_AUTHENTICATED in this header file.<br>

The CSX-512, known answer vectors are taken from [The CEX++ Cryptographic Library](https://github.com/Steppenwolfe65/CEX)<br>
See the documentation and the csx_test.h tests for usage examples.<br>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Author: John G. Underhill - May 2, 2020<br>
Updated: Stiepan A Kovac - October 13, 2021<br>
Rust Translation: Matt Warminger - 2025<br>
Updated: QRC - April 23, 2025<br>

An implementation of the ChaChaPoly20 stream cipher by Daniel J. Bernstein.

```rust
use qrc_opensource_rs::{
    cipher::csx::{
        qrc_csx_dispose, qrc_csx_initialize, qrc_csx_set_associated, qrc_csx_transform,
        QrcCsxKeyparams, QrcCsxState, QRC_CSX_KEY_SIZE, QRC_CSX_MAC_SIZE, QRC_CSX_NONCE_SIZE
    },
    provider::rcrng::qrc_rcrng_generate
};


let ad = &mut [0u8; 20];
let enc = &mut [0u8; 128 + QRC_CSX_MAC_SIZE];

let dec = &mut [0u8; 128];
let key = &mut [0u8; QRC_CSX_KEY_SIZE];
let msg = &mut [0u8; 128];
qrc_rcrng_generate(msg, 128);
let nce = &mut [0u8; QRC_CSX_NONCE_SIZE];
qrc_rcrng_generate(nce, QRC_CSX_NONCE_SIZE);

let state = &mut QrcCsxState::default();

let kp = &mut QrcCsxKeyparams::default();
kp.key = key.to_vec();
kp.keylen = QRC_CSX_KEY_SIZE;
kp.nonce = nce.to_vec();

qrc_csx_initialize(state, kp.clone(), true);
qrc_csx_set_associated(state, ad, 20);
qrc_csx_transform(state, enc, msg, 128);

qrc_csx_initialize(state, kp.clone(), false);
qrc_csx_set_associated(state, ad, 20);
qrc_csx_transform(state, dec, enc, 128);
qrc_csx_dispose(state);
```

#### Digest

##### Sha2

The SHA2 and HMAC implementations use two different forms of api: short-form and long-form.<br>
The short-form api, which initializes the state, processes a message, and finalizes by producing output, all in a single function call, for example; qrc_sha512_compute(), the entire message array is processed and the hash code is written to the output array.<br>
The long-form api uses an initialization call to prepare the state, a update call to process the message, and the finalize call, which finalizes the state and generates a hash or mac-code.<br>
The HKDF key derivation functions HKDF(HMAC(SHA2-256/512)), use only the short-form api, single-call functions, to generate pseudo-random to an output array.<br>
Each of the function families (SHA2, HMAC, HKDF), have a corresponding set of reference constants associated with that member, example; QRC_HKDF_256_KEY_SIZE is the minimum expected HKDF-256 key size in bytes, QRC_HMAC_512_MAC_SIZE is the minimum size of the HMAC-512 output mac-code output array.<br>

NIST: [The SHA-2 Standard](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf)<br>
[Analysis of SIMD Applicability to SHA Algorithms](https://software.intel.com/sites/default/files/m/b/9/b/aciicmez.pdf)<br>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Author: John G. Underhill - May 23, 2019<br>
Updated: Stiepan A Kovac - Jul 11, 2024<br>
Rust Translation: Matt Warminger - 2024<br>
Updated: QRC - April 23, 2025<br>

The primary public api for SHA2 Implementation:

```rust
use qrc_opensource_rs::{
  digest::sha2::{
    qrc_hkdf512_expand,
    QRC_SHA2_512_HASH_SIZE,
  },
  provider::rcrng::qrc_rcrng_generate,
};

let hash = &mut [0u8; QRC_SHA2_512_HASH_SIZE];
let info = &mut [0u8; 20];
qrc_rcrng_generate(info, 20);
let key = &mut [0u8; 50];
qrc_rcrng_generate(key, 50);

/* compact api */
qrc_hkdf512_expand(hash, QRC_SHA2_512_HASH_SIZE, key, 50, info, 20);
```

```rust
use qrc_opensource_rs::{
  digest::sha2::{
    qrc_hmac512_compute, qrc_hmac512_initialize, qrc_hmac512_blockfinalize,
    QRC_SHA2_512_HASH_SIZE, QrcHmac512State
  },
  provider::rcrng::qrc_rcrng_generate,
};

let hash = &mut [0u8; QRC_SHA2_512_HASH_SIZE];
let msg = &mut [0u8; 20];
qrc_rcrng_generate(msg, 20);
let key = &mut [0u8; 50];
qrc_rcrng_generate(key, 50);

/* compact api */
qrc_hmac512_compute(hash, msg, 20, key, 50);

/* test long-form api */
let ctx = &mut QrcHmac512State::default();
qrc_hmac512_initialize(ctx, key, 50);
qrc_hmac512_blockfinalize(ctx, hash, msg, 20);
```

```rust
use qrc_opensource_rs::{
    digest::sha2::{
        qrc_sha512_compute, qrc_sha512_initialize, qrc_sha512_update, qrc_sha512_finalize,
        QRC_SHA2_512_HASH_SIZE,
        QrcSha512State,
    },
    provider::rcrng::qrc_rcrng_generate,
};

let hash = &mut [0u8; QRC_SHA2_512_HASH_SIZE];
let msg = &mut [0u8; 20];
qrc_rcrng_generate(msg, 20);

/* compact api */
qrc_sha512_compute(hash, msg, 20);

/* long-form api */
let ctx = &mut QrcSha512State::default();
qrc_sha512_initialize(ctx);
qrc_sha512_update(ctx, msg, 20);
qrc_sha512_finalize(ctx, hash);
```

##### Sha3

The SHA3, SHAKE, cSHAKE, and KMAC implementations all share two forms of api: short-form and long-form.<br>
The short-form api, which initializes the state, processes a message, and finalizes by producing output, all in a single function call, for example; qrc_sha3_compute512(), the entire message array is processed and the hash code is written to the output array.<br>
The long-form api uses an initialization call to prepare the state, a blockupdate call if the message is longer than a single message block, and the finalize call, which finalizes the state and generates a hash, mac-code, or an array of pseudo-random.<br>
Each of the function families (SHA3, SHAKE, KMAC), have a corresponding set of reference constants associated with that member, example; SHAKE_256_KEY is the minimum expected SHAKE-256 key size in bytes, QRC_KMAC_512_MAC_SIZE is the minimum size of the KMAC-512 output mac-code output array, and QRC_KECCAK_512_RATE is the SHA3-512 message absorption rate.<br>

NIST: [SHA3 Fips202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)<br>
NIST: [SP800-185](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf)<br>
NIST: [SHA3 Keccak Submission](http://keccak.noekeon.org/Keccak-submission-3.pdf)<br>
NIST: [SHA3 Keccak Slides](http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf)<br>
NIST: [SHA3 Third-Round Report](http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf)<br>
Team Keccak: [Specifications summary](https://keccak.team/keccak_specs_summary.html)<br>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Author: John G. Underhill - October 27, 2019<br>
Updated: Stiepan A Kovac - February 7, 2024<br>
Rust Translation: Matt Warminger - 2024<br>
Updated: QRC - April 23, 2025<br>

The primary public api for SHA3 digest, SHAKE, cSHAKE, and KMAC implementation:

```rust
use qrc_opensource_rs::{
  digest::sha3::{
    qrc_sha3_compute512, qrc_sha3_initialize, qrc_sha3_update, qrc_sha3_finalize, qrc_keccak_dispose,
    QRC_SHA3_512_HASH_SIZE,
    QrcKeccakState, QrcKeccakRate,
  },
  provider::rcrng::qrc_rcrng_generate,
};

let hash = &mut [0u8; QRC_SHA3_512_HASH_SIZE];
let msg = &mut [0u8; 200];
qrc_rcrng_generate(msg, 200);

/* compact api */
qrc_sha3_compute512(hash, msg, 200);

/* long-form api */
let ctx = &mut QrcKeccakState::default();
qrc_sha3_initialize(ctx);
qrc_sha3_update(ctx, QrcKeccakRate::QrcKeccakRate512 as usize, msg, 200);
qrc_sha3_finalize(ctx, QrcKeccakRate::QrcKeccakRate512 as usize, hash);
qrc_keccak_dispose(ctx);
```

```rust
use qrc_opensource_rs::{
  digest::sha3::{
    qrc_kmac512_compute, qrc_kmac_initialize, qrc_kmac_update, qrc_kmac_finalize,
    qrc_keccak_dispose, 
    QRC_SHA3_512_HASH_SIZE,
    QrcKeccakState, QrcKeccakRate,
  },
  provider::rcrng::qrc_rcrng_generate,
};

let hash = &mut [0u8; QRC_SHA3_512_HASH_SIZE];
let msg = &mut [0u8; 200];
qrc_rcrng_generate(msg, 200);
let key = &mut [0u8; 50];
qrc_rcrng_generate(key, 50);
let cust = &mut [0u8; 100];
qrc_rcrng_generate(cust, 100);

/* compact api */
qrc_kmac512_compute(hash, QRC_SHA3_512_HASH_SIZE, msg, 200, key, 50, cust, 100);

/* long-form api */
let ctx = &mut QrcKeccakState::default();
qrc_kmac_initialize(ctx, QrcKeccakRate::QrcKeccakRate512 as usize, key, 50, cust, 100);
qrc_kmac_update(ctx, QrcKeccakRate::QrcKeccakRate512 as usize, msg, 200);
qrc_kmac_finalize(ctx, QrcKeccakRate::QrcKeccakRate512 as usize, hash, QRC_SHA3_512_HASH_SIZE);
qrc_keccak_dispose(ctx);
```

```rust
use qrc_opensource_rs::{
  digest::sha3::{
    qrc_cshake512_compute, qrc_cshake_initialize, qrc_cshake_squeezeblocks, qrc_keccak_dispose, 
    QRC_KECCAK_512_RATE,
    QrcKeccakState, QrcKeccakRate,
  },
  provider::rcrng::qrc_rcrng_generate,
};

let hash = &mut [0u8; QRC_KECCAK_512_RATE];
let msg = &mut [0u8; 200];
qrc_rcrng_generate(msg, 200);
let cust = &mut [0u8; 15];
qrc_rcrng_generate(cust, 15);

/* compact api */
qrc_cshake512_compute(hash, QRC_KECCAK_512_RATE, msg, 200, &[], 0, cust, 15);

/* long-form api */
let ctx = &mut QrcKeccakState::default();
qrc_cshake_initialize(ctx, QrcKeccakRate::QrcKeccakRate512 as usize, msg, 200, &[], 0, cust, 15);
qrc_cshake_squeezeblocks(ctx, QrcKeccakRate::QrcKeccakRate512 as usize, hash, 1);
qrc_keccak_dispose(ctx);
```

```rust
use qrc_opensource_rs::{
  digest::sha3::{
    qrc_shake512_compute, qrc_shake_initialize, qrc_shake_squeezeblocks, qrc_keccak_dispose, 
    QrcKeccakState, QrcKeccakRate,
  },
  provider::rcrng::qrc_rcrng_generate,
};

let hash = &mut [0u8; 512];
let msg = &mut [0u8; 200];
qrc_rcrng_generate(msg, 200);

/* compact api */
qrc_shake512_compute(hash, 512, msg, 200);

/* long-form api */
let ctx = &mut QrcKeccakState::default();
qrc_shake_initialize(ctx, QrcKeccakRate::QrcKeccakRate512 as usize, msg, 200);
qrc_shake_squeezeblocks(ctx, QrcKeccakRate::QrcKeccakRate512 as usize, hash, 1);
qrc_keccak_dispose(ctx);
```

```rust
use qrc_opensource_rs::{
  digest::sha3::{
    qrc_kpa_initialize, qrc_kpa_update, qrc_kpa_finalize, 
    QrcKpaState,
  },
  provider::rcrng::qrc_rcrng_generate,
};

let hash = &mut [0u8; 64];
let msg = &mut [0u8; 200];
qrc_rcrng_generate(msg, 200);
let key = &mut [0u8; 64];
qrc_rcrng_generate(key, 64);
let cust = &mut [0u8; 15];
qrc_rcrng_generate(cust, 15);


/* long-form api */
let ctx = &mut QrcKpaState::default();
qrc_kpa_initialize(ctx, key, 64, cust, 15);
qrc_kpa_update(ctx, msg, 200);
qrc_kpa_finalize(ctx, hash, 64);
```

#### DRGB

##### CSG

CSG uses the Keccak cSHAKE XOF function to produce pseudo-random bytes from a seeded custom SHAKE generator.<br>
If a 32-byte key is used, the implementation uses the cSHAKE-256 implementation for pseudo-random generation, if a 64-byte key is used, the generator uses cSHAKE-512.<br>
An optional predictive resistance feature, enabled through the initialize function, injects random bytes into the generator at initialization and 1MB intervals,<br>
creating a non-deterministic pseudo-random output.
Pseudo random bytes are cached internally, and the generator can be initialized and then reused without requiring re-initialization in an online configuration.<br>
The generator can be updated with new seed material, which is absorbed into the Keccak state.<br>

NIST: [SHA3 Fips202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)<br>
NIST: [SP800-185](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pd)<br>
NIST: [SHA3 Keccak Submission](http://keccak.noekeon.org/Keccak-submission-3.pdf)<br>
NIST: [SHA3 Keccak Slides](http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf)<br>
NIST: [SHA3 Third-Round Report](http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf)<br>
Team Keccak: [Specifications summary](https://keccak.team/keccak_specs_summary.html)<br>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Rust Translation: Matt Warminger - 2025<br>
Updated: QRC - April 23, 2025<br>

CSG pseudo-random bytes generator:

```rust
use qrc_opensource_rs::{
    drbg::csg::{
        qrc_csg_dispose, qrc_csg_generate, qrc_csg_initialize, qrc_csg_update,
        QrcCsgState, QRC_CSG_512_SEED_SIZE
    }, 
    provider::rcrng::qrc_rcrng_generate,
};

let seed = &mut [0u8; QRC_CSG_512_SEED_SIZE];
qrc_rcrng_generate(seed, QRC_CSG_512_SEED_SIZE);
let add = &mut [0u8; 64];
qrc_rcrng_generate(add, 64);
let out = &mut [0u8; 200];
let ctx = &mut QrcCsgState::default();

qrc_csg_initialize(ctx, seed, QRC_CSG_512_SEED_SIZE, &[], 0, false);
qrc_csg_update(ctx, add, 64);
qrc_csg_generate(ctx, out, 200);
qrc_csg_dispose(ctx);
```

##### HCG

HCG has a similar configuration to the HKDF Expand pseudo-random generator, but with a 128-bit nonce, and a default info parameter.<br>

The HKDF Scheme: [Cryptographic Extraction and Key Derivation](http://eprint.iacr.org/2010/264.pdf)<br>
RFC 2104 HMAC: [Keyed-Hashing for Message Authentication](http://tools.ietf.org/html/rfc2104)<br>
Fips 198-1: [The Keyed-Hash Message Authentication Code (HMAC)](http://csrc.nist.gov/publications/fips/fips198-1/FIPS-198-1_final.pdf)<br>
Fips 180-4: [Secure Hash Standard (SHS)](http://csrc.nist.gov/publications/fips/fips180-4/fips-180-4.pdf)<br>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Author: John G. Underhill - August 31, 2020<br>
Rust Translation: Matt Warminger - 2025<br>
Updated: QRC - April 23, 2025<br>

HCG pseudo-random bytes generator:

```rust
use qrc_opensource_rs::{
    drbg::hcg::{
        qrc_hcg_dispose, qrc_hcg_generate, qrc_hcg_initialize, qrc_hcg_update,
        QrcHcgState, QRC_HCG_SEED_SIZE
    },
    provider::rcrng::qrc_rcrng_generate,
};

let seed = &mut [0u8; QRC_HCG_SEED_SIZE];
qrc_rcrng_generate(seed, QRC_HCG_SEED_SIZE);
let add = &mut [0u8; 64];
qrc_rcrng_generate(add, 64);
let out = &mut [0u8; 200];
let ctx = &mut QrcHcgState::default();


qrc_hcg_initialize(ctx, seed, QRC_HCG_SEED_SIZE, &[], 0, false);
qrc_hcg_update(ctx, add, 64);
qrc_hcg_generate(ctx, out, 200);
qrc_hcg_dispose(ctx);
```

##### SCB

CSG uses the Keccak cSHAKE XOF function to produce pseudo-random bytes from a seeded custom SHAKE generator.<br>
If a 32-byte key is used, the implementation uses the cSHAKE-256 implementation for pseudo-random generation, if a 64-byte key is used, the generator uses cSHAKE-512.<br>
The CPU cost feature is an iteration count in the cost mechanism, it determines the number of times both the state absorption and memory expansion functions execute.<br>
The Memory cost, is the maximum number of megabytes the internal cache is expanded to, during execution of the cost mechanism.<br>
The maximum values of Memory and CPU cost should be determined based on the estimated capability of an adversary,
if set too high, the application will become unsuable, if set too low, it may fall within their computational capabilities.<br>
The recommended low-threshold parameters are c:500, m:100.<br>
The generator can be updated with new seed material, which is absorbed into the Keccak state.<br>

NIST: [SHA3 Fips202](http://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf)<br>
NIST: [SP800-185](http://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pd)<br>
NIST: [SHA3 Keccak Submission](http://keccak.noekeon.org/Keccak-submission-3.pdf)<br>
NIST: [SHA3 Keccak Slides](http://csrc.nist.gov/groups/ST/hash/sha-3/documents/Keccak-slides-at-NIST.pdf)<br>
NIST: [SHA3 Third-Round Report](http://nvlpubs.nist.gov/nistpubs/ir/2012/NIST.IR.7896.pdf)<br>
Team Keccak: [Specifications summary](https://keccak.team/keccak_specs_summary.html)<br>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Rust Translation: Matt Warminger - 2025<br>
Updated: QRC - April 23, 2025<br>

An implementation of the SHAKE Cost Based SCB key derivation function:

```rust
use qrc_opensource_rs::{
    drbg::scb::{
        qrc_scb_dispose, qrc_scb_generate, qrc_scb_initialize,
        QrcScbState, QRC_SCB_512_SEED_SIZE
    },
    provider::rcrng::qrc_rcrng_generate,
};

let seed = &mut [0u8; QRC_SCB_512_SEED_SIZE];
qrc_rcrng_generate(seed, QRC_SCB_512_SEED_SIZE);
let add = &mut [0u8; 64];
qrc_rcrng_generate(add, 64);
let out = &mut [0u8; 200];
let ctx = &mut QrcScbState::default();

qrc_scb_initialize(ctx, seed, QRC_SCB_512_SEED_SIZE, &[], 0, 10, 10);
qrc_scb_generate(ctx, out, 200);
qrc_scb_dispose(ctx);
```

#### Mac

##### Poly1305

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Rust Translation: Matt Warminger - 2024<br>
Updated: QRC - April 23, 2025<br>

The primary public api for the Poly1305 implementation:

```rust
use qrc_opensource_rs::{
  mac::poly1305::{
    qrc_poly1305_compute, qrc_poly1305_initialize, qrc_poly1305_update, qrc_poly1305_finalize, 
    QrcPoly1305State,
  },
  provider::rcrng::qrc_rcrng_generate,
};

let key = &mut [0u8; 32];
qrc_rcrng_generate(key, 32);
let mac = &mut [0u8; 16];
let msg = &mut [0u8; 64];
qrc_rcrng_generate(msg, 64);

/* compact api */
qrc_poly1305_compute(mac, msg, 64, key); 

/* long-form api */
let ctx = &mut QrcPoly1305State::default();
qrc_poly1305_initialize(ctx, key);
qrc_poly1305_update(ctx, msg, 64);
qrc_poly1305_finalize(ctx, mac);
```

#### Numerics

##### Donna128

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Rust Translation: Matt Warminger - 2025<br>
Updated: QRC - April 23, 2025<br>

The primary public api for the Donna128 implementation:

```rust
use qrc_opensource_rs::{
    numerics::donna128::{
        qrc_donna128_shift_left, qrc_donna128_shift_right, Uint128
    },
    provider::rcrng::qrc_rcrng_generate
};

let mut out = [0u8; 8];    
let mut x = Uint128::default();

qrc_rcrng_generate(&mut out, 8);
x.high =  u64::from_le_bytes(out);
qrc_rcrng_generate(&mut out, 8);
x.low = u64::from_le_bytes(out);

x = qrc_donna128_shift_right(x, 32);
x = qrc_donna128_shift_left(x, 32);
```

```rust
use qrc_opensource_rs::{
    numerics::donna128::{
        qrc_donna128_andl, qrc_donna128_andh, Uint128
    },
    provider::rcrng::qrc_rcrng_generate
};

let mut out = [0u8; 8];    
let mut x = Uint128::default();

qrc_rcrng_generate(&mut out, 8);
x.high =  u64::from_le_bytes(out);
qrc_rcrng_generate(&mut out, 8);
x.low = u64::from_le_bytes(out);

qrc_rcrng_generate(&mut out, 8);
let y = qrc_donna128_andl(x, u64::from_le_bytes(out));


let mut out = [0u8; 8];    
let mut x = Uint128::default();

qrc_rcrng_generate(&mut out, 8);
x.high =  u64::from_le_bytes(out);
qrc_rcrng_generate(&mut out, 8);
x.low = u64::from_le_bytes(out);

qrc_rcrng_generate(&mut out, 8);
let y = qrc_donna128_andh(x, u64::from_le_bytes(out));
```

```rust
use qrc_opensource_rs::{
    numerics::donna128::{
        qrc_donna128_multiply, Uint128
    },
    provider::rcrng::qrc_rcrng_generate
};

let mut out = [0u8; 8];    
let mut x = Uint128::default();

qrc_rcrng_generate(&mut out, 8);
x.high =  u64::from_le_bytes(out);
qrc_rcrng_generate(&mut out, 8);
x.low = u64::from_le_bytes(out);

qrc_rcrng_generate(&mut out, 8);
x = qrc_donna128_multiply(x, 2);
```

```rust
use qrc_opensource_rs::{
    numerics::donna128::{
        qrc_donna128_add, Uint128
    },
    provider::rcrng::qrc_rcrng_generate
};

let mut out = [0u8; 8];    
let mut x = Uint128::default();
let mut y = Uint128::default();

qrc_rcrng_generate(&mut out, 8);
x.high =  u64::from_le_bytes(out);
qrc_rcrng_generate(&mut out, 8);
x.low = u64::from_le_bytes(out);

qrc_rcrng_generate(&mut out, 8);
y.high =  u64::from_le_bytes(out);
qrc_rcrng_generate(&mut out, 8);
y.low = u64::from_le_bytes(out);

qrc_rcrng_generate(&mut out, 8);
x = qrc_donna128_add(x, y);

```

```rust
use qrc_opensource_rs::{
    numerics::donna128::{
        qrc_donna128_or, Uint128
    },
    provider::rcrng::qrc_rcrng_generate
};

let mut out = [0u8; 8];    
let mut x = Uint128::default();
let mut y = Uint128::default();

qrc_rcrng_generate(&mut out, 8);
x.high =  u64::from_le_bytes(out);
qrc_rcrng_generate(&mut out, 8);
x.low = u64::from_le_bytes(out);

qrc_rcrng_generate(&mut out, 8);
y.high =  u64::from_le_bytes(out);
qrc_rcrng_generate(&mut out, 8);
y.low = u64::from_le_bytes(out);

qrc_rcrng_generate(&mut out, 8);
x = qrc_donna128_or(x, y);
```

#### PRNG

##### SecRand

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Rust Translation: Matt Warminger - 2024<br>
Updated: QRC - April 23, 2025<br>

Implementation of an secure pseudo-random generator:

```rust
use qrc_opensource_rs::{
    prng::secrand::{
        qrc_secrand_generate, qrc_secrand_destroy, qrc_secrand_initialize, QrcSecrandState
    }, 
    provider::rcrng::qrc_rcrng_generate
};

let seed= &mut [0u8; 64];
qrc_rcrng_generate(seed, 64);
let out = &mut [0u8; 64];
let secrand_state = &mut QrcSecrandState::default(); 
qrc_secrand_initialize(secrand_state, seed, 64, &[], 0);
qrc_secrand_generate(secrand_state, out, 64);
qrc_secrand_destroy(secrand_state);
```

```rust
use qrc_opensource_rs::{
    asymmetric::asymmetric::{
        qrc_asymmetric_secrand_generate, AsymmetricRandState
    }, 
    prng::secrand::{
        qrc_secrand_destroy, qrc_secrand_initialize
    }, 
    provider::rcrng::qrc_rcrng_generate
};

let seed = &mut [0u8; 64];
qrc_rcrng_generate(seed, 64);
let out = &mut [0u8; 64];
let asymmetric_state = &mut AsymmetricRandState::default(); 
qrc_secrand_initialize(&mut asymmetric_state.secrand_state, seed, 64, &[], 0);
qrc_asymmetric_secrand_generate(asymmetric_state, out, 64);
qrc_secrand_destroy(&mut asymmetric_state.secrand_state);
```

##### NistRng

<h6>This is not a secure RNG, and should be used for testing purposes only.</h6>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Rust Translation: Matt Warminger - 2025<br>
Updated: QRC - April 23, 2025<br>

```rust
use qrc_opensource_rs::{
    prng::nistrng::{
        qrc_nistrng_prng_generate, qrc_nistrng_prng_initialize, 
        QRCTEST_NIST_RNG_SEED_SIZE, QrctestNistAes256State
    }, 
    provider::rcrng::qrc_rcrng_generate
};

let seed: &mut [u8; 48] = &mut [0u8; QRCTEST_NIST_RNG_SEED_SIZE];
qrc_rcrng_generate(seed, QRCTEST_NIST_RNG_SEED_SIZE);
let out = &mut [0u8; 64];
let nistrng_state = &mut QrctestNistAes256State::default(); 
qrc_nistrng_prng_initialize(nistrng_state, seed, &[], 0);
qrc_nistrng_prng_generate(nistrng_state, out, 64);
```

```rust
use qrc_opensource_rs::{
    asymmetric::asymmetric::{
        qrc_asymmetric_nistrng_generate, AsymmetricRandState
    }, 
    prng::nistrng::{
        qrc_nistrng_prng_initialize, QRCTEST_NIST_RNG_SEED_SIZE
    }, 
    provider::rcrng::qrc_rcrng_generate
};

let seed: &mut [u8; 48] = &mut [0u8; QRCTEST_NIST_RNG_SEED_SIZE];
qrc_rcrng_generate(seed, QRCTEST_NIST_RNG_SEED_SIZE);
let out = &mut [0u8; 64];
let asymmetric_state = &mut AsymmetricRandState::default(); 
qrc_nistrng_prng_initialize(&mut asymmetric_state.nist_test_state, seed, &[], 0);
qrc_asymmetric_nistrng_generate(asymmetric_state, out, 64);
```

#### Provider

##### RcRng

<h6>Recommended Provider, combination of latter two.</h6>

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Rust Translation: Matt Warminger - 2024<br>
Updated: QRC - April 23, 2025<br>

Resource RNG:

```rust
use qrc_opensource_rs::provider::rcrng::qrc_rcrng_generate;
let out = &mut [0u8; 64];
qrc_rcrng_generate(out, 64);
```

##### OsRng

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Rust Translation: Matt Warminger - 2024<br>
Updated: QRC - April 23, 2025<br>

OSRing RNG:

```rust
use qrc_opensource_rs::provider::osrng::qrc_osrng_generate;
let out = &mut [0u8; 64];
qrc_osrng_generate(out, 64);
```

##### TrRng

Derived from John G. Underhill's AGPLv3 QSC library in C<br>
Rust Translation: Matt Warminger - 2024<br>
Updated: QRC - April 23, 2025<br>

Thread RNG:

```rust
use qrc_opensource_rs::provider::trrng::qrc_trrng_generate;
let out = &mut [0u8; 64];
qrc_trrng_generate(out, 64);
```

## Roadmap

NOTE The package is under active development. As such, it is likely to remain volatile until a 1.0.0 release.<br>

Todo:

<ul>
  <li>Asymmetric/Signature/Falcon</li>
</ul>

## License

The contents of this repository are licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3.<br>
See [LICENSE](LICENSE) for more information on the license.
