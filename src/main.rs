mod qsc {
    mod asymmetric {
        mod cipher {
            mod ecdh {
                mod ec25519;
                mod ecdh;
                mod ecdhbase;
            }
            mod kyber {
                mod kyber;
                mod kyberbase;  
            }
            mod mceliece {
                mod mceliece;
                mod mceliecebase;
            }
            mod ntru {
                mod ntru;
                mod ntrubase;
            }
        }
        mod signature {
            mod dilithium {
                mod dilithium;
                mod dilithiumbase;
            }
            mod ecdsa {
                mod ecdsa;
                mod ecdsabase;
            }
            mod falcon {
                mod falcon;
                mod falconbase;
            }
            mod sphincsplus {
                mod sphincplus;
                mod sphincsplusbase;
            }
        }
    }
    mod cipher {
        mod aes;
        mod chacha;
    }
    pub mod common {
        pub mod common;
    }
    pub mod digest {
        pub mod sha2;
        pub mod sha3;
    }
    pub mod drbg {
        pub mod csg;
    }
    mod mac {
        mod poly1305;
    }
    mod numerics {
        mod donna128;
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

fn main() {

}