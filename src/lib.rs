#![cfg_attr(feature = "no_std", no_std)]

pub mod asymmetric {
    pub mod cipher {
        /*pub mod ecdhbody {
            pub(crate) mod ec25519base;
            pub(crate) mod ecdhbase;
                        pub(crate) mod ecdhface;
        }*/
        pub mod kyberbody {
            pub(crate) mod kyberbase;
            pub(crate) mod kyberface;
        }
        pub mod mceliecebody {
            pub(crate) mod mceliecebase;
            pub(crate) mod mcelieceface;
        }
        //pub mod ecdh;
        pub mod kyber;
        pub mod mceliece;
    }
    pub mod signature {
        /*pub mod dilithiumbody {
            pub(crate) mod dilithiumbase;
            pub(crate) mod dilithiumface;
        }*/
        /*pub mod ecdsabody {
            pub(crate) mod ecdsabase;
            pub(crate) mod ecdsaface;
        }*/
        /*pub mod falconbody {
            pub(crate) mod falconbase;
            pub(crate) mod falconface;
        }*/
        pub mod sphincsplusbody {
            pub(crate) mod sphincsplusbase;
            pub(crate) mod sphincsplusface;
        }
        //pub mod dilithium;
        //pub mod ecdsa;
        //pub mod falcon;
        pub mod sphincsplus;
    }
    pub mod asymmetric;
}
pub mod cipher {
    pub mod aes;
    pub mod chacha;
    pub mod csx;
}
pub mod digest {
    pub mod sha2;
    pub mod sha3;
}
pub mod common {
    pub mod common;
    pub mod timestamp;
}
pub mod drbg {
    pub mod csg;
    pub mod hcg;
    pub mod scb;
}
pub mod mac {
    pub mod poly1305;
}
pub mod numerics {
    pub mod donna128;
}
pub mod prng {
    pub mod nistrng;
    pub mod secrand;
}
pub mod provider {
    pub mod osrng;
    pub mod rcrng;
    pub mod trng;
}

pub mod tools {
    #[cfg(not(feature = "intutils"))]
    pub(crate) mod intutils;
    #[cfg(not(feature = "memutils"))]
    pub(crate) mod memutils;
    #[cfg(not(feature = "stringutils"))]
    pub(crate) mod stringutils;
    #[cfg(not(feature = "sysutils"))]
    pub(crate) mod sysutils;

    #[cfg(feature = "consoleutils")]
    pub mod consoleutils;
    #[cfg(feature = "fileutils")]
    pub mod fileutils;
    #[cfg(feature = "folderutils")]
    pub mod folderutils;
    #[cfg(feature = "intutils")]
    pub mod intutils;
    #[cfg(feature = "memutils")]
    pub mod memutils;
    #[cfg(feature = "stringutils")]
    pub mod stringutils;
    #[cfg(feature = "sysutils")]
    pub mod sysutils;
}

#[cfg(feature = "no_std")]
extern crate alloc;