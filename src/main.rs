pub mod qsc {
    pub mod asymmetric {
        pub mod cipher {
            pub mod ecdh {
                pub mod ec25519;
                pub mod ecdh;
                pub mod ecdhbase;
            }
            pub mod kyber {
                pub mod kyber;
                pub mod kyberbase;  
            }
            pub mod mceliece {
                pub mod mceliece;
                pub mod mceliecebase;
            }
            pub mod ntru {
                pub mod ntru;
                pub mod ntrubase;
            }
        }
        pub mod signature {
            pub mod dilithium {
                pub mod dilithium;
                pub mod dilithiumbase;
            }
            pub mod ecdsa {
                pub mod ecdsa;
                pub mod ecdsabase;
            }
            pub mod falcon {
                pub mod falcon;
                pub mod falconbase;
            }
            pub mod sphincsplus {
                pub mod sphincplus;
                pub mod sphincsplusbase;
            }
        }
    }
    pub mod cipher {
        pub mod aes;
        pub mod chacha;
    }
    pub mod common {
        pub mod common;
        pub mod timestamp;
    }
    pub mod digest {
        pub mod sha2;
        pub mod sha3;
    }
    pub mod drbg {
        pub mod csg;
        pub mod scb;
    }
    pub mod mac {
        pub mod poly1305;
    }
    pub mod numerics {
        pub mod donna128;
    }
    pub mod prng {
        pub mod secrand;
    }
    pub mod provider {
            pub mod rcrng;
            pub mod trng;
            pub mod osrng;
    }
    pub mod tools {
        pub mod intutils;
        pub mod memutils;
        pub mod stringutils;
        pub mod sysutils;
    }
}

fn main() {}