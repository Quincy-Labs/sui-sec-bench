#[test_only]
module case::consortium_tests;

use std::hash;
use std::vector;
use sui::tx_context;
use case::consortium::{new_consortium, configure_validator_set, epoch_set, pub_keys, threshold, delete_consortium};

#[test_only]
public fun key65(b: u8): vector<u8> {
    let mut v: vector<u8> = vector[];
    let mut i: u64 = 0;
    while (i < 65) {
        v.push_back(b);
        i = i + 1;
    };
    v
}

#[test]
public fun valid_set_configures() {
    let h = hash::sha2_256(vector[1u8]);
    let mut ctx = tx_context::new(@0x1111, h, 1, 0, 0);
    let mut c = new_consortium(1, &mut ctx);
    let keys = vector[key65(1), key65(2)];
    let weights = vector[60u64, 60u64];
    configure_validator_set(&mut c, 1, keys, weights, 100, 7);
    let s = epoch_set(&c, 7);
    assert!(vector::length(pub_keys(&s)) == 2, 0);
    assert!(threshold(&s) == 100, 0);
    delete_consortium(c);
}
