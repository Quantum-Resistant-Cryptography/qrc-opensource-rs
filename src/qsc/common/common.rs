/* The AGPL version 3 License (AGPLv3)
*
* Copyright (c) 2024 DFD & QRC Eurosmart SA
* This file is part of the QSC Cryptographic library
*
* This program is free software : you can redistribute it and / or modify
* it under the terms of the GNU Affero General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
* See the GNU Affero General Public License for more details.
*
* You should have received a copy of the GNU Affero General Public License
* along with this program. If not, see <http://www.gnu.org/licenses/>.
*/

/* Quantum Secure Cryptographic library in Rust (QSC) */

/*
\def QSC_SYSTEM_OS_XXX
* \brief The identified operating system
*/
pub const QSC_SYSTEM_OS_WINDOWS: bool = cfg!(target_os = "windows");
    pub const QSC_SYSTEM_ISWIN64: bool = cfg!(target_pointer_width = "64") && QSC_SYSTEM_OS_WINDOWS;
    pub const QSC_SYSTEM_ISWIN32: bool = cfg!(target_pointer_width = "32") && QSC_SYSTEM_OS_WINDOWS;

pub const QSC_SYSTEM_OS_ANDROID: bool = cfg!(target_os = "android");

pub const QSC_SYSTEM_OS_APPLE: bool = cfg!(target_vendor = "apple");
    pub const TARGET_OS_IPHONE: bool = cfg!(target_os = "ios") && QSC_SYSTEM_OS_APPLE;
    pub const TARGET_IPHONE_SIMULATOR: bool = !TARGET_OS_IPHONE; //Treat simulator as real

    pub const QSC_SYSTEM_ISIPHONE: bool = TARGET_OS_IPHONE && !TARGET_IPHONE_SIMULATOR;
    pub const QSC_SYSTEM_ISIPHONESIM: bool = TARGET_OS_IPHONE && TARGET_IPHONE_SIMULATOR;

    pub const QSC_SYSTEM_ISOSX: bool = cfg!(target_os = "macos") && QSC_SYSTEM_OS_APPLE;

pub const QSC_SYSTEM_OS_BSD: bool = cfg!(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd", target_os = "dragonfly")) || QSC_SYSTEM_OS_APPLE;

pub const QSC_SYSTEM_OS_LINUX: bool = cfg!(target_os = "linux") && !QSC_SYSTEM_OS_ANDROID && !QSC_SYSTEM_OS_BSD;

pub const QSC_SYSTEM_OS_UNIX: bool = cfg!(target_family = "unix") && !QSC_SYSTEM_OS_ANDROID && !QSC_SYSTEM_OS_BSD && !QSC_SYSTEM_OS_LINUX;
    //pub const QSC_SYSTEM_OS_HPUX: bool = cfg!(target_os = "hpux") && QSC_SYSTEM_OS_UNIX;
    pub const QSC_SYSTEM_OS_SUNUX: bool = cfg!(target_os = "solaris") && QSC_SYSTEM_OS_UNIX;

pub const QSC_SYSTEM_OS_POSIX: bool = QSC_SYSTEM_OS_ANDROID || QSC_SYSTEM_OS_APPLE || QSC_SYSTEM_OS_BSD || QSC_SYSTEM_OS_LINUX || QSC_SYSTEM_OS_UNIX;

pub const QSC_DEBUG_MODE: bool = cfg!(debug_assertions);


/*
\def QSC_SYSTEM_ARCH_XXX
* \brief The CPU architecture
*/
pub const QSC_SYSTEM_ARCH_IX86: bool = cfg!(any(target_arch = "x86", target_arch = "x86_64"));
    pub const QSC_SYSTEM_ARCH_IX86_64: bool = cfg!(target_arch = "x86_64") && QSC_SYSTEM_ARCH_IX86;
    pub const QSC_SYSTEM_ARCH_AMD64: bool = cfg!(target_arch = "x86_64") && QSC_SYSTEM_ARCH_IX86;
    pub const QSC_SYSTEM_ARCH_IX86_32: bool = cfg!(target_arch = "x86") && QSC_SYSTEM_ARCH_IX86;

pub const QSC_SYSTEM_ARCH_ARM: bool = cfg!(any(target_arch = "arm", target_arch = "aarch64"));
    pub const QSC_SYSTEM_ARCH_ARMV7VE: bool = cfg!(target_feature = "v7") && QSC_SYSTEM_ARCH_ARM;
    //pub const QSC_SYSTEM_ARCH_ARMFP: bool = cfg!(target_feature = "fp") && QSC_SYSTEM_ARCH_ARM;
    pub const QSC_SYSTEM_ARCH_ARM64: bool = cfg!(target_arch = "aarch64") && QSC_SYSTEM_ARCH_ARM;

//pub const QSC_SYSTEM_ARCH_IA64: bool = cfg!(target_arch = "ia64");

pub const QSC_SYSTEM_ARCH_PPC: bool = cfg!(any(target_arch = "powerpc", target_arch = "powerpc64"));

pub const QSC_SYSTEM_ARCH_SPARC: bool = cfg!(target_arch = "sparc");
    pub const QSC_SYSTEM_ARCH_SPARC64: bool = cfg!(target_arch = "sparc64") && QSC_SYSTEM_ARCH_SPARC;


/*
\def QSC_SYSTEM_IS_LITTLE_ENDIAN
* \brief The system is little endian
*/
pub const QSC_SYSTEM_IS_LITTLE_ENDIAN: bool = cfg!(target_endian = "little");
pub const QSC_SYSTEM_IS_BIG_ENDIAN: bool = cfg!(target_endian = "big");


/*
\def QSC_SYSTEM_MAX_PATH
* \brief The maximum path length
*/
pub const QSC_SYSTEM_MAX_PATH: usize = 260;

/*
\def QSC_SYSTEM_SECMEMALLOC_DEFAULT
* \brief The secure memory default buffer allocation
*/
pub const QSC_SYSTEM_SECMEMALLOC_DEFAULT: usize = 4096;

/*
\def QSC_SYSTEM_SECMEMALLOC_MIN
* \brief The minimum secure memory allocation
*/
pub const QSC_SYSTEM_SECMEMALLOC_MIN: usize = 16;

/*
\def QSC_SYSTEM_SECMEMALLOC_MAX
* \brief The maximum secure memory allocation
*/
pub const QSC_SYSTEM_SECMEMALLOC_MAX: usize = 128;

/*
\def QSC_SYSTEM_SECMEMALLOC_MAXKB
* \brief The secure memory maximum allocation in kilobytes
*/
pub const QSC_SYSTEM_SECMEMALLOC_MAXKB: usize = 512;

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
\def QSC_SYSTEM_HAS_SSE2
* \brief The system supports SSE2 instructions
*/
pub const QSC_SYSTEM_HAS_SSE2: bool = cfg!(target_feature = "sse2");

/*
\def QSC_SYSTEM_HAS_SSE3
* \brief The system supports SSE3 instructions
*/
pub const QSC_SYSTEM_HAS_SSE3: bool = cfg!(target_feature = "sse3");

/*
\def QSC_SYSTEM_HAS_SSSE3
* \brief The system supports SSSE3 instructions
*/
pub const QSC_SYSTEM_HAS_SSSE3: bool = cfg!(target_feature = "ssse3");

/*
\def QSC_SYSTEM_HAS_SSE41
* \brief The system supports SSE41 instructions
*/
pub const QSC_SYSTEM_HAS_SSE41: bool = cfg!(target_feature = "sse4.1");

/*
\def QSC_SYSTEM_HAS_SSE42
* \brief The system supports SSE42 instructions
*/
pub const QSC_SYSTEM_HAS_SSE42: bool = cfg!(target_feature = "sse4.2");

/*
\def QSC_SYSTEM_HAS_AVX
* \brief The system supports AVX instructions
*/
pub const QSC_SYSTEM_HAS_AVX: bool = cfg!(target_feature = "avx");

/*
\def QSC_SYSTEM_HAS_AVX2
* \brief The system supports AVX2 instructions
*/
pub const QSC_SYSTEM_HAS_AVX2: bool = cfg!(target_feature = "avx2");

/*
\def QSC_SYSTEM_HAS_AVX512
* \brief The system supports AVX512 instructions
*/
pub const QSC_SYSTEM_HAS_AVX512: bool = cfg!(target_feature = "avx512f");

//pub const QSC_SYSTEM_HAS_XOP: bool = cfg!(target_feature = "xop");

/*
\def QSC_SYSTEM_AVX_INTRINSICS
* \brief The system supports AVX instructions
*/
pub const QSC_SYSTEM_AVX_INTRINSICS: bool = QSC_SYSTEM_HAS_AVX || QSC_SYSTEM_HAS_AVX2 || QSC_SYSTEM_HAS_AVX512;

/*
\def QSC_SIMD_ALIGN
* \brief Align an array by SIMD instruction width
*/
pub const QSC_SIMD_ALIGNMENT: usize = if QSC_SYSTEM_HAS_AVX512 {
    64
} else if QSC_SYSTEM_HAS_AVX2 {
    32
} else if QSC_SYSTEM_HAS_AVX {
    16
} else {
    8
};

/*
* \def QSC_RDRAND_COMPATIBLE
* \brief The system has an RDRAND compatible CPU
*/
pub const QSC_RDRAND_COMPATIBLE: bool = QSC_SYSTEM_AVX_INTRINSICS;

/*
\def QSC_STATUS_SUCCESS
* Function return value indicates successful operation
*/
pub const QSC_STATUS_SUCCESS: i32 = 0;

/*
\def QSC_STATUS_FAILURE
* Function return value indicates failed operation
*/
pub const QSC_STATUS_FAILURE: i32 = -1;


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

pub const QSC_SYSTEM_AESNI_ENABLED: bool = QSC_SYSTEM_AVX_INTRINSICS;

/*
* \def QSC_KECCAK_UNROLLED_PERMUTATION
* \brief Define to use the UNROLLED form of the Keccak permutation function
* if undefined, functions use the compact form of the Keccak permutation
*/
pub const QSC_KECCAK_UNROLLED_PERMUTATION: bool = false;

/*** Asymmetric Ciphers ***/

/*** ECDH ***/

/*
\def QSC_ECDH_S1EC25519
* Implement the ECDH S1EC25519 parameter set
*/
pub const QSC_ECDH_S1EC25519: bool = true;

/*** Kyber ***/

/*
\def QSC_KYBER_S3Q3329N256K3
* Implement the Kyber S3Q3329N256K3 parameter set
*/
pub const QSC_KYBER_S3Q3329N256K3: bool = false;

/*
\def QSC_KYBER_S5Q3329N256K4
* Implement the Kyber S5Q3329N256K4 parameter set
*/
pub const QSC_KYBER_S5Q3329N256K4: bool = true;

/*
\def QSC_KYBER_S6Q3329N256K5
* Implement the Kyber S6Q3329N256K5 parameter set.
* /warning Experimental, not an official parameter.
*/
pub const QSC_KYBER_S6Q3329N256K5: bool = false;

/*** McEliece ***/

/*
\def QSC_MCELIECE_S3N4608T96
* Implement the McEliece S3-N4608T96 parameter set
*/
pub const QSC_MCELIECE_S3N4608T96: bool = false;

/*
\def QSC_MCELIECE_S5N6688T128
* Implement the McEliece S5-N6688T128 parameter set
*/
pub const QSC_MCELIECE_S5N6688T128: bool = true;

/*
\def QSC_MCELIECE_S5N6960T119
* Implement the McEliece S5-N6960T119 parameter set
*/
pub const QSC_MCELIECE_S5N6960T119: bool = false;

/*
\def QSC_MCELIECE_S5N8192T128
* Implement the McEliece S5-N8192T128 parameter set
*/
pub const QSC_MCELIECE_S5N8192T128: bool = false;

/*** NTRU ***/

/*
\def QSC_NTRU_S1HPS2048509
* Implement the NTRU S1HPS2048509 parameter set
*/
pub const QSC_NTRU_S1HPS2048509: bool = false;
/*
\def QSC_NTRU_HPSS32048677
* Implement the NTRU HPSS32048677 parameter set
*/
pub const QSC_NTRU_HPSS32048677: bool = false;

/*
\def QSC_NTRU_S5HPS4096821
* Implement the NTRU S5HPS4096821 parameter set
*/
pub const QSC_NTRU_S5HPS4096821: bool = true;

/*
\def QSC_NTRU_S5HRSS701
* Implement the NTRU S5HRSS701 parameter set
*/
pub const QSC_NTRU_S5HRSS701: bool = false;

/*** Signature Schemes ***/

/*** Dilithium ***/

/*
\def QSC_DILITHIUM_S2N256Q8380417K4
* Implement the Dilithium S1N256Q8380417 parameter set
*/
pub const QSC_DILITHIUM_S2N256Q8380417K4: bool = false;

/*
\def QSC_DILITHIUM_S2N256Q8380417K4
* Implement the Dilithium S2N256Q8380417 parameter set
*/
pub const QSC_DILITHIUM_S3N256Q8380417K6: bool = true;

/*
\def QSC_DILITHIUM_S3N256Q8380417K6
* Implement the Dilithium S3N256Q8380417 parameter set
*/
pub const QSC_DILITHIUM_S5N256Q8380417K8: bool = false;

/*** ECDSA ***/

/*
\def QSC_ECDSA_S1EC25519
* Implement the ECDSA S1EC25519 parameter set
*/
pub const QSC_ECDSA_S1EC25519: bool = true;

/*** Falcon ***/

/*
\def QSC_FALCON_S3SHAKE256F512
* Implement the Falcon S3SHAKE256F512 parameter set
*/
pub const QSC_FALCON_S3SHAKE256F512: bool = false;

/*
\def QSC_FALCON_S5SHAKE256F1024
* Implement the Falcon S5SHAKE256F1024 parameter set
*/
pub const QSC_FALCON_S5SHAKE256F1024: bool = true;

/*** SphincsPlus ***/

/*
\def QSC_SPHINCSPLUS_S3S192SHAKERS
* Implement the SphincsPlus S3S192SHAKERS robust small parameter set
*/
pub const QSC_SPHINCSPLUS_S3S192SHAKERS: bool = false;

/*
\def QSC_SPHINCSPLUS_S3S192SHAKERF
* Implement the SphincsPlus S3S192SHAKERF robust fast parameter set
*/
pub const QSC_SPHINCSPLUS_S3S192SHAKERF: bool = false;

/*
\def QSC_SPHINCSPLUS_S5S256SHAKERS
* Implement the SphincsPlus S5S256SHAKERS robust small parameter set
*/
pub const QSC_SPHINCSPLUS_S5S256SHAKERS: bool = false;

/*
\def QSC_SPHINCSPLUS_S5S256SHAKERF
* Implement the SphincsPlus S5S256SHAKERF robust fast parameter set
*/
pub const QSC_SPHINCSPLUS_S5S256SHAKERF: bool = true;