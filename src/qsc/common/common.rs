/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2024 DFD & QRC Eurosmart SA
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General public License as pub(crate)lished by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General public License for more details.
*
* You should have received a copy of the GNU Affero General public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

/* Quantum Secure Cryptographic library in Rust (QSC) */


/*
\def QSC_SYSTEM_IS_LITTLE_ENDIAN
* \brief The system is little endian
*/
pub(crate) const QSC_SYSTEM_IS_LITTLE_ENDIAN: bool = cfg!(target_endian = "little");

/*
* AVX512 Capabilities Check
* https://software.intel.com/en-us/intel-cplusplus-compiler-16.0-user-and-reference-guide
* https://software.intel.com/en-us/articles/compiling-for-the-intel-xeon-phi-processor-and-the-intel-avx-512-isa
* https://colfaxresearch.com/knl-avx512/
*
* #include <immintrin.h>
* supported is 1: ex. __AVX512CD__ 1
* F		__AVX512F__					Foundation
* CD	__AVX512CD__				Conflict Detection Instructions(CDI)
* ER	__AVX512ER__				Exponential and Reciprocal Instructions(ERI)
* PF	__AVX512PF__				Pre-fetch Instructions(PFI)
* DQ	__AVX512DQ__				Double-word and Quadword Instructions(DQ)
* BW	__AVX512BW__				Byte and Word Instructions(BW)
* VL	__AVX512VL__				Vector Length Extensions(VL)
* IFMA	__AVX512IFMA__				Integer Fused Multiply Add(IFMA)
* VBMI	__AVX512VBMI__				Vector Byte Manipulation Instructions(VBMI)
* VNNIW	__AVX5124VNNIW__			Vector instructions for deep learning enhanced word variable precision
* FMAPS	__AVX5124FMAPS__			Vector instructions for deep learning floating - point single precision
* VPOPCNT	__AVX512VPOPCNTDQ__		?
*
* Note: AVX512 is currently untested, this flag enables support on a compliant system
*/
/* Enable this define to support AVX512 on a compatible system */

/*
\def QSC_SYSTEM_HAS_AVX
* \brief The system supports AVX instructions
*/
const QSC_SYSTEM_HAS_AVX: bool = cfg!(target_feature = "avx");

/*
\def QSC_SYSTEM_HAS_AVX2
* \brief The system supports AVX2 instructions
*/
pub(crate) const QSC_SYSTEM_HAS_AVX2: bool = cfg!(target_feature = "avx2");

/*
\def QSC_SYSTEM_HAS_AVX512
* \brief The system supports AVX512 instructions
*/
const QSC_SYSTEM_HAS_AVX512: bool = cfg!(target_feature = "avx512f");

//const QSC_SYSTEM_HAS_XOP: bool = cfg!(target_feature = "xop");

/*
\def QSC_SYSTEM_AVX_INTRINSICS
* \brief The system supports AVX instructions
*/
const QSC_SYSTEM_AVX_INTRINSICS: bool = QSC_SYSTEM_HAS_AVX || QSC_SYSTEM_HAS_AVX2 || QSC_SYSTEM_HAS_AVX512;


/* User Modifiable Values
* Modifiable values that determine which parameter sets and options get compiled.
* These values can be tuned by the user to enable/disable features for a specific environment, or hardware configuration.
* This list also includes the asymmetric cipher and signature scheme parameter set options.
*/

/*
\def QSC_SYSTEM_AESNI_ENABLED
* Enable the use of intrinsics and the AES-NI implementation.
* Just for testing, add the QSC_SYSTEM_AESNI_ENABLED preprocessor definition and enable SIMD and AES-NI.
*/

pub(crate) const QSC_SYSTEM_AESNI_ENABLED: bool = QSC_SYSTEM_AVX_INTRINSICS;

/*** Kyber ***/

/*
\def QSC_KYBER_S3Q3329N256K3
* Implement the Kyber S3Q3329N256K3 parameter set
*/
pub(crate) const QSC_KYBER_S3Q3329N256K3: bool = false;

/*
\def QSC_KYBER_S5Q3329N256K4
* Implement the Kyber S5Q3329N256K4 parameter set
*/
pub(crate) const QSC_KYBER_S5Q3329N256K4: bool = true;

/*
\def QSC_KYBER_S6Q3329N256K5
* Implement the Kyber S6Q3329N256K5 parameter set.
* /warning Experimental, not an official parameter.
*/
pub(crate) const QSC_KYBER_S6Q3329N256K5: bool = false;

/*** McEliece ***/

/*
\def QSC_MCELIECE_S3N4608T96
* Implement the McEliece S3-N4608T96 parameter set
*/
pub(crate) const QSC_MCELIECE_S3N4608T96: bool = false;

/*
\def QSC_MCELIECE_S5N6688T128
* Implement the McEliece S5-N6688T128 parameter set
*/
pub(crate) const QSC_MCELIECE_S5N6688T128: bool = true;

/*
\def QSC_MCELIECE_S5N6960T119
* Implement the McEliece S5-N6960T119 parameter set
*/
pub(crate) const QSC_MCELIECE_S5N6960T119: bool = false;

/*
\def QSC_MCELIECE_S5N8192T128
* Implement the McEliece S5-N8192T128 parameter set
*/
pub(crate) const QSC_MCELIECE_S5N8192T128: bool = false;

/*** SphincsPlus ***/

/*
\def QSC_SPHINCSPLUS_S3S192SHAKERS
* Implement the SphincsPlus S3S192SHAKERS robust small parameter set
*/
pub(crate) const QSC_SPHINCSPLUS_S3S192SHAKERS: bool = false;

/*
\def QSC_SPHINCSPLUS_S3S192SHAKERF
* Implement the SphincsPlus S3S192SHAKERF robust fast parameter set
*/
pub(crate) const QSC_SPHINCSPLUS_S3S192SHAKERF: bool = false;

/*
\def QSC_SPHINCSPLUS_S5S256SHAKERS
* Implement the SphincsPlus S5S256SHAKERS robust small parameter set
*/
pub(crate) const QSC_SPHINCSPLUS_S5S256SHAKERS: bool = false;

/*
\def QSC_SPHINCSPLUS_S5S256SHAKERF
* Implement the SphincsPlus S5S256SHAKERF robust fast parameter set
*/
pub(crate) const QSC_SPHINCSPLUS_S5S256SHAKERF: bool = true;