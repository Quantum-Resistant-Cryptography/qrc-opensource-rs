use crate::qsc::{
    tools::{
        memutils::{
            qsc_memutils_copy,
            qsc_memutils_clear,
        },
        intutils::{
            qsc_intutils_be64to8,
            qsc_intutils_verify,
        },
    },
    common::common::{
        QSC_SPHINCSPLUS_S3S192SHAKERF,
        QSC_SPHINCSPLUS_S3S192SHAKERS,
        QSC_SPHINCSPLUS_S5S256SHAKERF,
        QSC_SPHINCSPLUS_S5S256SHAKERS,
    },
    digest::sha3::{
        QscKeccakState,
        QSC_KECCAK_256_RATE,
        QSC_KECCAK_SHAKE_DOMAIN_ID,
        qsc_shake256_compute, 
        qsc_keccak_incremental_absorb, 
        qsc_keccak_incremental_finalize, 
        qsc_keccak_incremental_squeeze,
    },
};

use std::mem::size_of;
use bytemuck::{cast_slice_mut, cast_slice};

/* Hash output length in bytes. */
const SPX_N: usize = if QSC_SPHINCSPLUS_S3S192SHAKERF {
    24
} else if QSC_SPHINCSPLUS_S3S192SHAKERS {
    24
} else if QSC_SPHINCSPLUS_S5S256SHAKERF {
    32
} else if QSC_SPHINCSPLUS_S5S256SHAKERS {
    32
} else {
    0
};

/* Height of the hypertree. */
const SPX_FULL_HEIGHT: usize = if QSC_SPHINCSPLUS_S3S192SHAKERF {
    66
} else if QSC_SPHINCSPLUS_S3S192SHAKERS {
    63
} else if QSC_SPHINCSPLUS_S5S256SHAKERF {
    68
} else if QSC_SPHINCSPLUS_S5S256SHAKERS {
    64
} else {
    0
};

/* Number of subtree layer. */
const SPX_D: usize = if QSC_SPHINCSPLUS_S3S192SHAKERF {
    22
} else if QSC_SPHINCSPLUS_S3S192SHAKERS {
    7
} else if QSC_SPHINCSPLUS_S5S256SHAKERF {
    17
} else if QSC_SPHINCSPLUS_S5S256SHAKERS {
    8
} else {
    0
};

/* FORS tree dimensions. */
const SPX_FORS_HEIGHT: usize = if QSC_SPHINCSPLUS_S3S192SHAKERF {
    8
} else if QSC_SPHINCSPLUS_S3S192SHAKERS {
    14
} else if QSC_SPHINCSPLUS_S5S256SHAKERF {
    9
} else if QSC_SPHINCSPLUS_S5S256SHAKERS {
    14
} else {
    0
};
const SPX_FORS_TREES: usize = if QSC_SPHINCSPLUS_S3S192SHAKERF {
    33
} else if QSC_SPHINCSPLUS_S3S192SHAKERS {
    17
} else if QSC_SPHINCSPLUS_S5S256SHAKERF {
    35
} else if QSC_SPHINCSPLUS_S5S256SHAKERS {
    22
} else {
    0
};

/* Winternitz parameter, */
const SPX_WOTS_W: usize = if QSC_SPHINCSPLUS_S3S192SHAKERF {
    16
} else if QSC_SPHINCSPLUS_S3S192SHAKERS {
    16
} else if QSC_SPHINCSPLUS_S5S256SHAKERF {
    16
} else if QSC_SPHINCSPLUS_S5S256SHAKERS {
    16
} else {
    0
};

/* For clarity */
const SPX_ADDR_BYTES: usize = 32;

/* WOTS parameters. */
const SPX_WOTS_LOGW: usize = if SPX_WOTS_W == 256 {
    8
} else if SPX_WOTS_W == 16 {
    4
} else {
    0
};


const SPX_WOTS_LEN1: usize = 8 * SPX_N / SPX_WOTS_LOGW;

/* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
const SPX_WOTS_LEN2: usize = if SPX_WOTS_W == 256 {
    if SPX_N <= 1 {
        1
    } else if SPX_N <= 256 {
        2
    } else {
        0
    }
} else if SPX_WOTS_W == 16 {
    if SPX_N <= 8 {
        2
    } else if SPX_N <= 136 {
        3
    } else if SPX_N <= 256 {
        4
    } else {
        0
    }
} else {
    0
};

const SPX_WOTS_LEN: usize = SPX_WOTS_LEN1 + SPX_WOTS_LEN2;
const SPX_WOTS_BYTES: usize = SPX_WOTS_LEN * SPX_N;

/* Subtree size. */
const SPX_TREE_HEIGHT: usize = SPX_FULL_HEIGHT / SPX_D;

/* FORS parameters. */
const SPX_FORS_MSG_BYTES: usize = (SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8;
const SPX_FORS_BYTES: usize = (SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N;

/* Resulting SPX sizes. */
const SPX_BYTES: usize = SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES + SPX_FULL_HEIGHT * SPX_N;
const SPX_PK_BYTES: usize = 2 * SPX_N;


/* Offsets of various fields in the address structure when we use SHAKE as the Sphincs+ hash function */
/* The byte used to specify the Merkle tree layer */
const SPX_OFFSET_LAYER: usize = 3;
/* The start of the 8 byte field used to specify the tree */
const SPX_OFFSET_TREE: usize = 8;
/* The byte used to specify the hash type (reason) */
const SPX_OFFSET_TYPE: usize = 19;
/* The high byte used to specify the key pair (which one-time signature) */
const SPX_OFFSET_KP_ADDR2: usize = 22;
/* The low byte used to specify the key pair */
const SPX_OFFSET_KP_ADDR1: usize = 23;
/* The byte used to specify the chain address (which Winternitz chain) */
const SPX_OFFSET_CHAIN_ADDR: usize = 27;
/* The byte used to specify the hash address (where in the Winternitz chain) */
const SPX_OFFSET_HASH_ADDR: usize = 31;
/* The byte used to specify the height of this node in the FORS or Merkle tree */
const SPX_OFFSET_TREE_HGT: usize =  27;
/* The start of the 4 byte field used to specify the node in the FORS or Merkle tree */
const SPX_OFFSET_TREE_INDEX: usize = 28;

/* The hash types that are passed to set_type */
const SPX_ADDR_TYPE_WOTS: usize = 0;
const SPX_ADDR_TYPE_WOTSPK: usize = 1;
const SPX_ADDR_TYPE_HASHTREE: usize = 2;
const SPX_ADDR_TYPE_FORSTREE: usize = 3;
const SPX_ADDR_TYPE_FORSPK: usize = 4;

const SPX_TREE_BITS: usize = SPX_TREE_HEIGHT * (SPX_D - 1);
const SPX_TREE_BYTES: usize = (SPX_TREE_BITS + 7) / 8;
const SPX_LEAF_BITS: usize = SPX_TREE_HEIGHT;
const SPX_LEAF_BYTES: usize = (SPX_LEAF_BITS + 7) / 8;
const SPX_DGST_BYTES: usize = SPX_FORS_MSG_BYTES + SPX_TREE_BYTES + SPX_LEAF_BYTES;

const SPHINCSPLUS_CRYPTO_SEEDBYTES: usize = 3 * SPX_N;

/* utils.c */

fn sphincsplus_ull_to_bytes(out: &mut [u8], outlen: u32, mut int: u64) {
    let mut pos = outlen;

    loop {
        pos -= 1;
        out[pos as usize] = int as u8 & 0xFF;
        int >>= 8;
        
        if pos <= 0 {
            break;
        }
    } 
}

fn sphincsplus_u32_to_bytes(out: &mut [u8], int: u32) {
    out[0] = (int >> 24) as u8;
    out[1] = (int >> 16) as u8;
    out[2] = (int >> 8) as u8;
    out[3] = int as u8;
}

fn sphincsplus_bytes_to_ull(int: &[u8], inlen: u32) -> u64 {
    let mut ret: u64 = 0;

    for i in 0..inlen {
        ret |= (int[i as usize] as u64) << (8 * (inlen - 1 - i));
    }

    return ret;
}

/* address.c */

/* These functions are used for all hash tree addresses (including FORS). */

fn sphincsplus_set_layer_addr(addr: &mut [u32; 8], layer: u32) {
    /* Specify which level of Merkle tree (the "layer") we're working on */

    let bytes = addr.as_mut_slice();
    let byte_slice = cast_slice_mut::<u32, u8>(bytes);

    byte_slice[SPX_OFFSET_LAYER] = layer as u8;
}

fn sphincsplus_set_tree_addr(addr: &mut [u32; 8], tree: u64) {
    /* Specify which Merkle tree within the level (the "tree address") we're working on */

    if SPX_TREE_HEIGHT * (SPX_D - 1) <= 64 {
        let bytes = addr.as_mut_slice();
        let byte_slice = cast_slice_mut::<u32, u8>(bytes);

        qsc_intutils_be64to8(&mut byte_slice[SPX_OFFSET_TREE..], tree);
    }
}

fn sphincsplus_set_type(addr: &mut [u32; 8], type_var: u32) {
    /* Specify the reason we'll use this address structure for, that is, what
    hash will we compute with it.  This is used so that unrelated types of
    hashes don't accidentally get the same address structure.  The type will be
    one of the SPX_ADDR_TYPE constants */

    let bytes = addr.as_mut_slice();
    let byte_slice = cast_slice_mut::<u32, u8>(bytes);

    byte_slice[SPX_OFFSET_TYPE] = type_var as u8;
}

fn sphincsplus_copy_subtree_addr(out: &mut [u32; 8], int: &mut [u32; 8]) {
    /* Copy the layer and tree fields of the address structure.  This is used
    when we're doing multiple types of hashes within the same Merkle tree */

    let bytes_one = out.as_mut_slice();
    let byte_slice_one = cast_slice_mut::<u32, u8>(bytes_one);

    let bytes_two = int.as_slice();
    let byte_slice_two = cast_slice::<u32, u8>(bytes_two);

    qsc_memutils_copy(byte_slice_one, byte_slice_two, SPX_OFFSET_TREE + 8);
}

fn sphincsplus_set_keypair_addr(addr: &mut [u32; 8], keypair: u32) {
    /* Specify which Merkle leaf we're working on; that is, 
    which OTS keypair we're talking about. */

    let bytes = addr.as_mut_slice();
    let byte_slice = cast_slice_mut::<u32, u8>(bytes);

    if SPX_FULL_HEIGHT/SPX_D > 8 {
        /* We have > 256 OTS at the bottom of the Merkle tree; to specify
        which one, we'd need to express it in two bytes */
        byte_slice[SPX_OFFSET_KP_ADDR2] = keypair as u8 >> 8;
    } else {
        byte_slice[SPX_OFFSET_KP_ADDR1] = keypair as u8;
    }
}

fn sphincsplus_copy_keypair_addr(out: &mut [u32; 8], int: [u32; 8]) {
    /* Copy the layer, tree and keypair fields of the address structure.
    This is used when we're doing multiple things within the same OTS keypair */

    let bytes_one = out.as_mut_slice();
    let byte_slice_one = cast_slice_mut::<u32, u8>(bytes_one);

    let bytes_two = int.as_slice();
    let byte_slice_two = cast_slice::<u32, u8>(bytes_two);

    qsc_memutils_copy(byte_slice_one, byte_slice_two, SPX_OFFSET_TREE + 8);

    if SPX_FULL_HEIGHT/SPX_D > 8 {
        byte_slice_one[SPX_OFFSET_KP_ADDR2] = byte_slice_two[SPX_OFFSET_KP_ADDR2];
    } else {
        byte_slice_one[SPX_OFFSET_KP_ADDR1] = byte_slice_two[SPX_OFFSET_KP_ADDR1];
    }
}

fn sphincsplus_set_chain_addr(addr: &mut [u32; 8], chain: u32) {
    /* Specify which Merkle chain within the OTS we're working with (the chain address) */

    let bytes = addr.as_mut_slice();
    let byte_slice = cast_slice_mut::<u32, u8>(bytes);

    byte_slice[SPX_OFFSET_CHAIN_ADDR] = chain as u8;
}

fn sphincsplus_set_hash_addr(addr: &mut [u32; 8], hash: u32) {
    /* Specify where in the Merkle chain we are (the hash address) */

    let bytes = addr.as_mut_slice();
    let byte_slice = cast_slice_mut::<u32, u8>(bytes);

    byte_slice[SPX_OFFSET_HASH_ADDR] = hash as u8;
}

fn sphincsplus_set_tree_height(addr: &mut [u32; 8], tree_height: u32) {
    /* Specify the height of the node in the Merkle/FORS tree we are in (the tree height) */

    let bytes = addr.as_mut_slice();
    let byte_slice = cast_slice_mut::<u32, u8>(bytes);

    byte_slice[SPX_OFFSET_TREE_HGT] = tree_height as u8;
}

fn sphincsplus_set_tree_index(addr: &mut [u32; 8], tree_index: u32) {
    /* Specify the distance from the left edge of the node in the Merkle/FORS tree (the tree index) */

    let bytes = addr.as_mut_slice();
    let byte_slice = cast_slice_mut::<u32, u8>(bytes);

    sphincsplus_u32_to_bytes(&mut byte_slice[SPX_OFFSET_TREE_INDEX..], tree_index);
}
/*
/* hash_shake256.c */
*/
fn sphincsplus_prf_addr(out: &mut [u8], key: &[u8], addr: &mut [u32; 8]) {
    /* Computes PRF(key, addr), given a secret key of SPX_N bytes and an address */

    let buf = &mut [0u8; SPX_N + SPX_ADDR_BYTES];

    qsc_memutils_copy(buf, key, SPX_N);

    let bytes = addr.as_slice();
    let byte_slice = cast_slice::<u32, u8>(bytes);

    qsc_memutils_copy(&mut buf[SPX_N..], byte_slice, SPX_ADDR_BYTES);

    qsc_shake256_compute(out, SPX_N, buf, SPX_N + SPX_ADDR_BYTES);
}

fn sphincsplus_gen_message_random(r: &mut [u8], sk_prf: &[u8], optrand: &[u8], m: &[u8], mlen: u64) {
    /* Computes the message-dependent randomness R, using a secret seed and an
       optional randomization value as well as the message. */
    let kctx = &mut QscKeccakState::default();

    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_256_RATE, sk_prf, SPX_N);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_256_RATE, optrand, SPX_N);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_256_RATE, m, mlen as usize);
    qsc_keccak_incremental_finalize(kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(kctx, QSC_KECCAK_256_RATE, r, SPX_N);
}

fn sphincsplus_hash_message(digest: &mut [u8], tree: &mut u64, leaf_idx: &mut u32, r: &[u8], pk: &[u8], m: &[u8], mlen: u64) {
    /* Computes the message hash using R, the public key, and the message.
       Outputs the message digest and the index of the leaf. The index is split in
       the tree index and the leaf index, for convenient copying to an address. */

    let buf = &mut [0u8; SPX_DGST_BYTES];
    let kctx = &mut QscKeccakState::default();

    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_256_RATE, r, SPX_N);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_256_RATE, pk, SPX_PK_BYTES);
    qsc_keccak_incremental_absorb(kctx, QSC_KECCAK_256_RATE, m, mlen as usize);
    qsc_keccak_incremental_finalize(kctx, QSC_KECCAK_256_RATE, QSC_KECCAK_SHAKE_DOMAIN_ID);
    qsc_keccak_incremental_squeeze(kctx, QSC_KECCAK_256_RATE, buf, SPX_DGST_BYTES);

    let mut bufp: &[u8] = &buf.to_owned();

    qsc_memutils_copy(digest, &bufp, SPX_FORS_MSG_BYTES);
    bufp = &bufp[SPX_FORS_MSG_BYTES..];

    *tree = sphincsplus_bytes_to_ull(bufp, SPX_TREE_BYTES as u32);
    *tree &= (!0 as u64) >> (64 - SPX_TREE_BITS);

    bufp = &bufp[SPX_TREE_BYTES..];

    *leaf_idx = sphincsplus_bytes_to_ull(bufp, SPX_LEAF_BYTES as u32) as u32;
    *leaf_idx &= (!0 as u32) >> (32 - SPX_LEAF_BITS);
}

fn sphincsplus_thash(out: &mut [u8], int: &[u8], inblocks: u32, pubseed: &[u8], addr: &mut [u32; 8]) {
    /* Takes an array of inblocks concatenated arrays of SPX_N bytes */
    let blklen = inblocks as usize * SPX_N;
    let keylen = SPX_N + SPX_ADDR_BYTES;

    let buf = &mut vec![0u8; blklen+keylen];
    let bitmask = &mut vec![0u8; blklen];

    qsc_memutils_copy(buf, pubseed, SPX_N);

    let bytes = addr.as_slice();
    let byte_slice = cast_slice::<u32, u8>(bytes);

    qsc_memutils_copy(&mut buf[SPX_N..], byte_slice, SPX_ADDR_BYTES);

    qsc_shake256_compute(bitmask, blklen, &buf, keylen);

    for i in 0..blklen {
        buf[keylen + i] = int[i] ^ bitmask[i];
    }

    qsc_shake256_compute(out, SPX_N, &buf, keylen + blklen);
    bitmask.fill(0);
    buf.fill(0);

}

fn sphincsplus_compute_root(root: &mut [u8], leaf: &[u8], mut leaf_idx: u32, mut idx_offset: u32, mut auth_path: &[u8], tree_height: u32, pubseed: &[u8], addr: &mut [u32; 8]) {
    /* Computes a root node given a leaf and an auth path.
       Expects address to be complete other than the tree_height and tree_index */

    let buffer = &mut [0u8; 2 * SPX_N];

    /* If leaf_idx is odd (last bit = 1), current path element is a right child
       and auth_path has to go left. Otherwise it is the other way around. */
    if (leaf_idx & 1) != 0 {
        qsc_memutils_copy(&mut buffer[SPX_N..], leaf, SPX_N);
        qsc_memutils_copy(buffer, auth_path, SPX_N);
    } else {
        qsc_memutils_copy(buffer, leaf, SPX_N);
        qsc_memutils_copy(&mut buffer[SPX_N..], auth_path, SPX_N);
    }

    auth_path = &auth_path[SPX_N..];

    for i in 0..tree_height - 1 {
        leaf_idx >>= 1;
        idx_offset >>= 1;

        /* Set the address of the node we're creating. */
        sphincsplus_set_tree_height(addr, i as u32 + 1);
        sphincsplus_set_tree_index(addr, leaf_idx + idx_offset);

        /* Pick the right or left neighbor, depending on parity of the node. */
        let buffers = &buffer.to_owned();
        if (leaf_idx & 1) != 0 {
            sphincsplus_thash(&mut buffer[SPX_N..], buffers, 2, pubseed, addr);
            qsc_memutils_copy(buffer, auth_path, SPX_N);
        } else {
            sphincsplus_thash(buffer, buffers, 2, pubseed, addr);
            qsc_memutils_copy(&mut buffer[SPX_N..], auth_path, SPX_N);
        }

        auth_path = &auth_path[SPX_N..];
    }

    /* The last iteration is exceptional; we do not copy an auth_path node. */
    leaf_idx >>= 1;
    idx_offset >>= 1;
    sphincsplus_set_tree_height(addr, tree_height);
    sphincsplus_set_tree_index(addr, leaf_idx + idx_offset);
    sphincsplus_thash(root, buffer, 2, pubseed, addr);
}

fn sphincsplus_treehash(root: &mut [u8], auth_path: &mut [u8], sk_seed: &[u8], pubseed: &[u8], leaf_idx: u32, idx_offset: u32, tree_height: u32,
    gen_leaf: fn(&mut [u8] /* leaf */, &[u8] /* sk_seed */, &[u8] /* pubseed */, u32 /* addr_idx */, &mut [u32; 8] /* tree_addr */), tree_addr: &mut [u32; 8]) {
    /* For a given leaf index, computes the authentication path and the resulting
    root node using Merkle's TreeHash algorithm.
    Expects the layer and tree parts of the tree_addr to be set, as well as the
    tree type (i.e. SPX_ADDR_TYPE_HASHTREE or SPX_ADDR_TYPE_FORSTREE).
    Applies the offset idx_offset to indices before building addresses, so that
    it is possible to continue counting indices across trees. */


    let mut offset = 0;
    let stack = &mut vec![0u8; (tree_height as usize + 1) * SPX_N as usize];
    let heights = &mut vec![0u8; (tree_height as usize + 1) * size_of::<u32>()];

    for idx in 0..(1 << tree_height) as u32 {
        /* Add the next leaf node to the stack. */
        gen_leaf(&mut stack[offset * SPX_N..], sk_seed, pubseed, idx + idx_offset, tree_addr);
        offset += 1;
        heights[offset - 1] = 0;

        /* If this is a node we need for the auth path.. */
        if (leaf_idx ^ 0x1) == idx {
            qsc_memutils_copy(auth_path, &stack[(offset - 1) * SPX_N..], SPX_N);
        }

        /* While the top-most nodes are of equal height.. */

        loop {
            if offset < 2 || heights[offset - 1] != heights[offset - 2] {
                break;
            }

            /* Compute index of the new node, in the next layer. */
            let tree_idx = idx >> (heights[offset - 1] + 1);

            /* Set the address of the node we're creating. */
            sphincsplus_set_tree_height(tree_addr, (heights[offset - 1] + 1) as u32);
            sphincsplus_set_tree_index(tree_addr, tree_idx + (idx_offset >> (heights[offset - 1] + 1)));
            /* Hash the top-most nodes from the stack together. */
            let stackoffest = &stack[(offset - 2) * SPX_N..].to_owned();
            sphincsplus_thash(&mut stack[(offset - 2) * SPX_N..], stackoffest, 2, pubseed, tree_addr);
            offset -= 1;
            /* Note that the top-most node is now one layer higher. */
            heights[offset - 1] += 1;

            /* If this is a node we need for the auth path.. */
            if ((leaf_idx >> heights[offset - 1]) ^ 0x1) == tree_idx {
                qsc_memutils_copy(&mut auth_path[heights[offset - 1] as usize * SPX_N..], &stack[(offset - 1) * SPX_N..], SPX_N);
            }
        }
    }

    qsc_memutils_copy(root, &stack, SPX_N);
    heights.fill(0);
    stack.fill(0);
}

/* fors.c */

fn sphincsplus_fors_gen_sk(sk: &mut [u8], sk_seed: &[u8], fors_leaf_addr: &mut [u32; 8]) {
    sphincsplus_prf_addr(sk, sk_seed, fors_leaf_addr);
}

fn sphincsplus_fors_sk_to_leaf(leaf: &mut [u8], sk: &[u8], pubseed: &[u8], fors_leaf_addr: &mut [u32; 8]) {
    sphincsplus_thash(leaf, sk, 1, pubseed, fors_leaf_addr);
}

fn sphincsplus_fors_gen_leaf(leaf: &mut [u8], sk_seed: &[u8], pubseed: &[u8], addr_idx: u32, fors_tree_addr: &mut [u32; 8]) {
    let fors_leaf_addr = &mut [0u32; 8];

    /* Only copy the parts that must be kept in fors_leaf_addr. */
    sphincsplus_copy_keypair_addr(fors_leaf_addr, fors_tree_addr.clone());
    sphincsplus_set_type(fors_leaf_addr, SPX_ADDR_TYPE_FORSTREE as u32);
    sphincsplus_set_tree_index(fors_leaf_addr, addr_idx);

    sphincsplus_fors_gen_sk(leaf, sk_seed, fors_leaf_addr);
    let leafs = &leaf.to_owned();
    sphincsplus_fors_sk_to_leaf(leaf, leafs, pubseed, fors_leaf_addr);
}

fn sphincsplus_message_to_indices(indices: &mut [u32], m: &[u8]) {
    /* Interprets m as SPX_FORS_HEIGHT-bit unsigned integers.
       Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits.
       Assumes indices has space for SPX_FORS_TREES integers. */

    let mut oft: u32 = 0;

    for i in 0..SPX_FORS_TREES {
        indices[i] = 0;

        for j in 0..SPX_FORS_HEIGHT {
            let byte = (oft / 8) as usize;
            let bit = oft % 8;
            indices[i] ^= ((m[byte] as u32 >> (bit & 7)) & 1) << j;
            oft += 1;
        }
    }
}

fn sphincsplus_fors_sign(mut sig: &mut [u8], pk: &mut [u8], m: &[u8], sk_seed: &[u8], pubseed: &[u8], fors_addr: [u32; 8]) {
    /* Signs a message m, deriving the secret key from sk_seed and the FTS address.
       Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits. */
    let indices = &mut [0u32; SPX_FORS_TREES];
    let roots = &mut [0u8; SPX_FORS_TREES * SPX_N];
    let fors_tree_addr = &mut [0u32; 8];
    let fors_pk_addr = &mut [0u32; 8];

    sphincsplus_copy_keypair_addr(fors_tree_addr, fors_addr);
    sphincsplus_copy_keypair_addr(fors_pk_addr, fors_addr);

    sphincsplus_set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE as u32);
    sphincsplus_set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK as u32);

    sphincsplus_message_to_indices(indices, m);

    for i in 0..SPX_FORS_TREES {
        let idx_offset = (i * (1 << SPX_FORS_HEIGHT)) as u32;

        sphincsplus_set_tree_height(fors_tree_addr, 0);
        sphincsplus_set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Include the secret key part that produces the selected leaf node. */
        sphincsplus_fors_gen_sk(sig, sk_seed, fors_tree_addr);
        sig = &mut sig[SPX_N..];

        /* Compute the authentication path for this leaf node. */
        sphincsplus_treehash(&mut roots[i * SPX_N..], sig, sk_seed, pubseed, indices[i], idx_offset, SPX_FORS_HEIGHT as u32, sphincsplus_fors_gen_leaf, fors_tree_addr);

        sig = &mut sig[SPX_N * SPX_FORS_HEIGHT..];
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    sphincsplus_thash(pk, roots, SPX_FORS_TREES as u32, pubseed, fors_pk_addr);
}

fn sphincsplus_fors_pk_from_sig(pk: &mut [u8], mut sig: &[u8], m: &[u8], pubseed: &[u8], fors_addr: [u32; 8]) {
    /* Derives the FORS public key from a signature.
       This can be used for verification by comparing to a known public key, or to
       subsequently verify a signature on the derived public key. The latter is the
       typical use-case when used as an FTS below an OTS in a hypertree.
       Assumes m contains at least SPX_FORS_HEIGHT * SPX_FORS_TREES bits. */

    let indices = &mut [0u32; SPX_FORS_TREES];
    let roots = &mut [0u8; SPX_FORS_TREES * SPX_N];
    let leaf = &mut [0u8; SPX_N];
    let fors_tree_addr = &mut [0u32; 8];
    let fors_pk_addr = &mut [0u32; 8];

    sphincsplus_copy_keypair_addr(fors_tree_addr, fors_addr);
    sphincsplus_copy_keypair_addr(fors_pk_addr, fors_addr);

    sphincsplus_set_type(fors_tree_addr, SPX_ADDR_TYPE_FORSTREE as u32);
    sphincsplus_set_type(fors_pk_addr, SPX_ADDR_TYPE_FORSPK as u32);

    sphincsplus_message_to_indices(indices, m);

    for i in 0..SPX_FORS_TREES {
        let idx_offset = (i * (1 << SPX_FORS_HEIGHT)) as u32;

        sphincsplus_set_tree_height(fors_tree_addr, 0);
        sphincsplus_set_tree_index(fors_tree_addr, indices[i] + idx_offset);

        /* Derive the leaf from the included secret key part. */
        sphincsplus_fors_sk_to_leaf(leaf, sig, pubseed, fors_tree_addr);
        sig = &sig[SPX_N..];

        /* Derive the corresponding root node of this tree. */
        sphincsplus_compute_root(&mut roots[i * SPX_N..], leaf, indices[i], idx_offset, sig, SPX_FORS_HEIGHT as u32, pubseed, fors_tree_addr);
        sig = &sig[SPX_N * SPX_FORS_HEIGHT..];
    }

    /* Hash horizontally across all tree roots to derive the public key. */
    sphincsplus_thash(pk, roots, SPX_FORS_TREES as u32, pubseed, fors_pk_addr);
}

/* wots.c */

fn sphincsplus_wots_gen_sk(sk: &mut [u8], sk_seed: &[u8], wots_addr: &mut [u32; 8]) {
    /* Computes the starting value for a chain, i.e. the secret key.
       Expects the address to be complete up to the chain address. */

    /* Make sure that the hash address is actually zeroed. */
    sphincsplus_set_hash_addr(wots_addr, 0);

    /* Generate sk element. */
    sphincsplus_prf_addr(sk, sk_seed, wots_addr);
}

fn sphincsplus_gen_chain(out: &mut [u8], int: &[u8], start: u32, steps: u32, pubseed: &[u8], addr: &mut [u32; 8]) {
    /* Computes the chaining function.
       out and in have to be n-byte arrays.
       Interprets in as start-th value of the chain.
       addr has to contain the address of the chain. */

    /* Initialize out with the value at position 'start'. */
    qsc_memutils_copy(out, int, SPX_N);

    /* Iterate 'steps' calls to the hash function. */
    for i in start..(start + steps).min(SPX_WOTS_W as u32) {
        sphincsplus_set_hash_addr(addr, i as u32);
        let outint = &out.to_owned();
        sphincsplus_thash(out, outint, 1 as u32, pubseed, addr);
    }
}

fn sphincsplus_base_w(output: &mut [u32], out_len: usize, input: &[u8]) {
    /* sphincsplus_base_w algorithm as described in draft.
       Interprets an array of bytes as integers in base w.
       This only works when log_w is a divisor of 8. */


    let mut bits: i32 = 0;
    let mut total: u8 = 0;
    let mut ictr = 0;
    let mut octr = 0;

    for _ in 0..out_len {
        if bits == 0 {
            total = input[ictr];
            ictr += 1;
            bits += 8;
        }

        bits -= SPX_WOTS_LOGW as i32;
        output[octr] = (total >> bits) as u32 & (SPX_WOTS_W - 1) as u32;
        octr += 1;
    }
}

fn sphincsplus_wots_checksum(csum_base_w: &mut [u32], msg_base_w : &[u32]) {
    /* Computes the WOTS+ checksum over a message (in sphincsplus_base_w). */

    let csum_bytes = &mut [0u8; (SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8];

    let mut csum: u32 = 0;

    /* Compute checksum. */
    for i in 0..SPX_WOTS_LEN1 {
        csum += (SPX_WOTS_W - 1) as u32 - msg_base_w[i];
    }

    /* Convert checksum to sphincsplus_base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW) % 8)) % 8);
    sphincsplus_ull_to_bytes(csum_bytes, ((SPX_WOTS_LEN2 * SPX_WOTS_LOGW + 7) / 8) as u32, csum as u64);
    sphincsplus_base_w(csum_base_w, SPX_WOTS_LEN2, csum_bytes);
}

fn sphincsplus_chain_lengths(lengths: &mut [u32], msg: &[u8]) {
    /* Takes a message and derives the matching chain lengths */

    sphincsplus_base_w(lengths, SPX_WOTS_LEN1, msg);
    let lengthss = &lengths.to_owned();
    sphincsplus_wots_checksum(&mut lengths[SPX_WOTS_LEN1..], lengthss);
}

fn sphincsplus_wots_gen_pk(pk: &mut [u8], sk_seed: &[u8], pubseed: &[u8], addr: &mut [u32; 8]) {
    /* WOTS key generation. Takes a 32 byte sk_seed, expands it to WOTS private key
       elements and computes the corresponding public key.
       It requires the seed pubseed (used to generate bitmasks and hash keys)
       and the address of this WOTS key pair.
       Writes the computed public key to 'pk'. */

    for i in 0..SPX_WOTS_LEN {
        sphincsplus_set_chain_addr(addr, i as u32);
        sphincsplus_wots_gen_sk(&mut pk[i * SPX_N..], sk_seed, addr);
        let pkbrw = &pk[i * SPX_N..].to_owned();
        sphincsplus_gen_chain(&mut pk[i * SPX_N..], pkbrw, 0, (SPX_WOTS_W - 1) as u32, pubseed, addr);
    }
}

fn sphincsplus_wots_sign(sig: &mut [u8], msg: &[u8], sk_seed: &[u8], pubseed: &[u8], addr: &mut [u32; 8]) {
    /* Takes a n-byte message and the 32-byte sk_see to compute a signature 'sig'. */

    let lengths = &mut [0u32; SPX_WOTS_LEN];

    sphincsplus_chain_lengths(lengths, msg);

    for i in 0..SPX_WOTS_LEN {
        sphincsplus_set_chain_addr(addr, i as u32);
        sphincsplus_wots_gen_sk(&mut sig[i * SPX_N..], sk_seed, addr);
        let sigspx = &sig[i * SPX_N..].to_owned();
        sphincsplus_gen_chain(&mut sig[i * SPX_N..], sigspx, 0, lengths[i], pubseed, addr);
    }
}

fn sphincsplus_wots_pk_from_sig(pk: &mut [u8], sig: &[u8], msg: &[u8], pubseed: &[u8], addr: &mut [u32; 8]) {
    /* Takes a WOTS signature and an n-byte message, computes a WOTS public key.
       Writes the computed public key to 'pk'. */

    let lengths = &mut [0u32; SPX_WOTS_LEN];

    sphincsplus_chain_lengths(lengths, msg);

    for i in 0..SPX_WOTS_LEN {
        sphincsplus_set_chain_addr(addr, i as u32);
        sphincsplus_gen_chain(&mut pk[i * SPX_N..], &sig[i * SPX_N..], lengths[i], (SPX_WOTS_W - 1) as u32 - lengths[i], pubseed, addr);
    }
}

fn sphincsplus_wots_gen_leaf(leaf: &mut [u8], sk_seed: &[u8], pubseed: &[u8], addr_idx: u32, tree_addr: &mut [u32; 8]) {
    /* Computes the leaf at a given address. First generates the WOTS key pair,
    then computes leaf by hashing horizontally. */

    let pk = &mut [0u8; SPX_WOTS_BYTES];
    let wots_addr = &mut [0u32; 8];
    let wots_pk_addr = &mut [0u32; 8];

    sphincsplus_set_type(wots_addr, SPX_ADDR_TYPE_WOTS as u32);
    sphincsplus_set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK as u32);

    sphincsplus_copy_subtree_addr(wots_addr,  tree_addr);
    sphincsplus_set_keypair_addr(wots_addr, addr_idx);
    sphincsplus_wots_gen_pk(pk, sk_seed, pubseed, wots_addr);

    sphincsplus_copy_keypair_addr(wots_pk_addr, wots_addr.clone());
    sphincsplus_thash(leaf, pk, SPX_WOTS_LEN as u32, pubseed, wots_pk_addr);
}

/**
* \brief Generates a SphincsPlus public/private key-pair from a seed
*
* \param pk: The public verification key
* \param sk: The private signature key
* \param seed: A pointer to the seed array
*/
fn sphincsplus_ref_generate_seed_keypair(pk: &mut [u8], sk: &mut [u8], seed: &[u8]) -> i32 {
    /* Generates an SPX key pair given a seed of length
       Format sk [SK_SEED || SK_PRF || PUB_SEED || root]
       Format pk [PUB_SEED || root] */
    /* We do not need the auth path in key generation, but it simplifies the
        code to have just one sphincsplus_treehash routine that computes both root and path
        in one function. */

    let auth_path = &mut [0u8; SPX_TREE_HEIGHT * SPX_N];
    let top_tree_addr = &mut [0u32; 8];

    sphincsplus_set_layer_addr(top_tree_addr, (SPX_D - 1) as u32);
    sphincsplus_set_type(top_tree_addr, SPX_ADDR_TYPE_HASHTREE as u32);

    /* Initialize SK_SEED, SK_PRF and PUB_SEED from seed. */
    qsc_memutils_copy(sk, seed, SPHINCSPLUS_CRYPTO_SEEDBYTES);
    qsc_memutils_copy(pk, &sk[2 * SPX_N..], SPX_N);

    /* Compute root node of the top-most subtree. */
    let skowned = &sk.to_owned();
    let skspx = &skowned[2 * SPX_N..].to_owned();
    sphincsplus_treehash(&mut sk[3 * SPX_N..], auth_path, skowned, skspx, 0, 0, SPX_TREE_HEIGHT as u32, sphincsplus_wots_gen_leaf, top_tree_addr);
    qsc_memutils_copy(&mut pk[SPX_N..], &sk[3 * SPX_N..], SPX_N);

    return 0;
}

/**
* \brief Generates a SphincsPlus public/private key-pair
*
* \param pk: The public verification key
* \param sk: The private signature key
* \param rng_generate: A pointer to the random generator function
*/
pub fn sphincsplus_ref_generate_keypair(pk: &mut [u8], sk: &mut [u8], rng_generate: fn(&mut [u8], usize) -> bool) {
    /* Generates an SPX key pair.
       Format sk [SK_SEED || SK_PRF || PUB_SEED || root]
       Format pk [PUB_SEED || root] */

    let seed = &mut [0u8; SPHINCSPLUS_CRYPTO_SEEDBYTES];

    rng_generate(seed, SPHINCSPLUS_CRYPTO_SEEDBYTES);
    sphincsplus_ref_generate_seed_keypair(pk, sk, seed);
}

/**
* \brief Takes the message as input and returns an array containing the signature
*
* \param sig: The signature
* \param siglen: The signature length
* \param m: The message to be signed
* \param mlen: The message length
* \param sk: The private signature key
* \param rng_generate: A pointer to the random generator function
*/
fn sphincsplus_ref_sign_signature(mut sig: &mut [u8], siglen: &mut usize, m: &[u8], mlen: usize, sk: &[u8], rng_generate: fn(&mut [u8], usize) -> bool) {
    /* Returns an array containing a detached signature */

    let sk_seed = sk;
    let sk_prf = &sk[SPX_N..];
    let pk = &sk[2 * SPX_N..];
    let pubseed = pk;

    let optrand = &mut [0u8; SPX_N];
    let mhash = &mut [0u8; SPX_FORS_MSG_BYTES];
    let root = &mut [0u8; SPX_N];
    let mut tree: u64 = 0;
    let mut idx_leaf: u32 = 0;
    let wots_addr = &mut [0u32; 8];
    let tree_addr = &mut [0u32; 8];

    sphincsplus_set_type(wots_addr, SPX_ADDR_TYPE_WOTS as u32);
    sphincsplus_set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE as u32);

    /* Optionally, signing can be made non-deterministic using optrand.
       This can help counter side-channel attacks that would benefit from
       getting a large number of traces when the signer uses the same nodes. */
    rng_generate(optrand, SPX_N);

    /* Compute the digest randomization value. */
    sphincsplus_gen_message_random(sig, sk_prf, optrand, m, mlen as u64);

    /* Derive the message digest and leaf index from R, PK and M. */
    sphincsplus_hash_message(mhash, &mut tree, &mut idx_leaf, sig, pk, m, mlen as u64);
    sig = &mut sig[SPX_N..];

    sphincsplus_set_tree_addr(wots_addr, tree);
    sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

    /* Sign the message hash using FORS. */
    sphincsplus_fors_sign(sig, root, mhash, sk_seed, pubseed, wots_addr.clone());
    sig = &mut sig[SPX_FORS_BYTES..];

    for i in 0..SPX_D {
        sphincsplus_set_layer_addr(tree_addr, i as u32);
        sphincsplus_set_tree_addr(tree_addr, tree);

        sphincsplus_copy_subtree_addr(wots_addr, tree_addr);
        sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

        /* Compute a WOTS signature. */
        sphincsplus_wots_sign(sig, root, sk_seed, pubseed, wots_addr);
        sig = &mut sig[SPX_WOTS_BYTES..];

        /* Compute the authentication path for the used WOTS leaf. */
        sphincsplus_treehash(root, sig, sk_seed, pubseed, idx_leaf, 0, SPX_TREE_HEIGHT as u32, sphincsplus_wots_gen_leaf, tree_addr);
        sig = &mut sig[SPX_TREE_HEIGHT * SPX_N..];

        /* Update the indices for the next layer. */
        idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1)) as u32;
        tree = tree >> SPX_TREE_HEIGHT;
    }

    *siglen = SPX_BYTES;
}

/**
* \brief Verifies a signature-message pair with the public key
*
* \param sig: The signature array
* \param siglen: The length of the signature array
* \param m: The message array
* \param mlen: The length of the message array
* \param pk: The public verification key
* \return Returns true for success
*/
fn sphincsplus_ref_sign_verify(mut sig: &[u8], siglen: usize, m: &[u8], mlen: usize, pk: &[u8]) -> bool {
    /* Verifies a detached signature and message under a given public key */

    let pubseed = pk;
    let pub_root = &pk[SPX_N..];
    let mhash = &mut [0u8; SPX_FORS_MSG_BYTES];
    let wots_pk = &mut [0u8; SPX_WOTS_BYTES];
    let root = &mut [0u8; SPX_N];
    let leaf = &mut [0u8; SPX_N];
    let mut tree: u64 = 0;
    let mut idx_leaf: u32 = 0;
    let wots_addr = &mut [0u32; 8];
    let tree_addr = &mut [0u32; 8];
    let wots_pk_addr = &mut [0u32; 8];

    let mut res = false;

    if siglen == SPX_BYTES {
        sphincsplus_set_type(wots_addr, SPX_ADDR_TYPE_WOTS as u32);
        sphincsplus_set_type(tree_addr, SPX_ADDR_TYPE_HASHTREE as u32);
        sphincsplus_set_type(wots_pk_addr, SPX_ADDR_TYPE_WOTSPK as u32);

        /* Derive the message digest and leaf index from R || PK || M */
        /* The additional SPX_N is a result of the hash domain separator. */
        sphincsplus_hash_message(mhash, &mut tree, &mut idx_leaf, sig, pk, m, mlen as u64);

        sig = &sig[SPX_N..];

        /* Layer correctly defaults to 0, so no need to sphincsplus_set_layer_addr */
        sphincsplus_set_tree_addr(wots_addr, tree);
        sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

        sphincsplus_fors_pk_from_sig(root, sig, mhash, pubseed, wots_addr.clone());

        sig = &sig[SPX_FORS_BYTES..];

        /* For each subtree.. */
        for i in 0..SPX_D {
            sphincsplus_set_layer_addr(tree_addr, i as u32);
            sphincsplus_set_tree_addr(tree_addr, tree);

            sphincsplus_copy_subtree_addr(wots_addr, tree_addr);
            sphincsplus_set_keypair_addr(wots_addr, idx_leaf);

            sphincsplus_copy_keypair_addr(wots_pk_addr, wots_addr.clone());

            /* The WOTS public key is only correct if the signature was correct. */
            /* Initially, root is the FORS pk, but on subsequent iterations it is
               the root of the subtree below the currently processed subtree. */
            sphincsplus_wots_pk_from_sig(wots_pk, sig, root, pubseed, wots_addr);
            sig = &sig[SPX_WOTS_BYTES..];

            /* Compute the leaf node using the WOTS public key. */
            sphincsplus_thash(leaf, wots_pk, SPX_WOTS_LEN as u32, pubseed, wots_pk_addr);

            /* Compute the root node of this subtree. */
            sphincsplus_compute_root(root, leaf, idx_leaf, 0, sig, SPX_TREE_HEIGHT as u32, pubseed, tree_addr);
            sig = &sig[SPX_TREE_HEIGHT * SPX_N..];

            /* Update the indices for the next layer. */
            idx_leaf = (tree & ((1 << SPX_TREE_HEIGHT) - 1)) as u32;
            tree = tree >> SPX_TREE_HEIGHT;
        }

        /* Check if the root node equals the root node in the public key. */
        res = qsc_intutils_verify(root, pub_root, SPX_N) == 0;
    }

    return res;
}

/**
* \brief Takes the message as input and returns an array containing the signature followed by the message.
*
* \param sm: The signed message
* \param smlen: The signed message length
* \param m: The message to be signed
* \param mlen: The message length
* \param sk: The private signature key
* \param rng_generate: A pointer to the random generator function
*/
pub fn sphincsplus_ref_sign(sm: &mut [u8], smlen: &mut usize, m: &[u8], mlen: usize, sk: &[u8], rng_generate: fn(&mut [u8], usize) -> bool) {
    /* Returns an array containing the signature followed by the message */

    let mut siglen = 0;

    sphincsplus_ref_sign_signature(sm, &mut siglen, m, mlen, sk, rng_generate);
    qsc_memutils_copy(&mut sm[SPX_BYTES..], m, mlen);
    *smlen = siglen + mlen;
}

/**
* \brief Verifies a signature with the public key
*
* \param m: The message to be signed
* \param mlen: The message length
* \param sm: The signed message
* \param smlen: The signed message length
* \param pk: The public verification key
* \return Returns true for success
*/
pub fn sphincsplus_ref_sign_open(m: &mut [u8], mlen: &mut usize, sm: &[u8], smlen: usize, pk: &[u8]) -> bool {
    /* Verifies a given signature-message pair under a given public key */

    let mut res = false;

    /* The API caller does not necessarily know what size a signature should be
       but SPHINCS+ signatures are always exactly SPX_BYTES. */
    if smlen >= SPX_BYTES {
        *mlen = smlen - SPX_BYTES;
        res = sphincsplus_ref_sign_verify(sm, SPX_BYTES, &sm[SPX_BYTES..], mlen.clone(), pk);

        if res == true {
            /* If verification was successful, move the message to the right place. */
            qsc_memutils_copy(m, &sm[SPX_BYTES..], mlen.clone());
        } else {
            qsc_memutils_clear(m);
            *mlen = 0;
            res = false;
        }
    } else {
        qsc_memutils_clear(m);
        *mlen = 0;
    }

    return res;
}