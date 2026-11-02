module case::consortium;

use sui::object;
use sui::tx_context;
use std::vector;

const EInvalidAction: u64 = 0;
const EInvalidSetSize: u64 = 1;
const EInvalidThreshold: u64 = 2;
const EInvalidLengths: u64 = 3;
const EInvalidKeyLength: u64 = 4;
const EDuplicateValidator: u64 = 5;
const EThresholdExceedsTotal: u64 = 6;

const MIN_SET_SIZE: u64 = 1;
const MAX_SET_SIZE: u64 = 100;

/// A validator set registered for an epoch.
public struct ValidatorSet has store, drop, copy {
    epoch: u64,
    pub_keys: vector<vector<u8>>,
    weights: vector<u64>,
    weight_threshold: u64,
}

/// The consortium registry. Holds one validator set per configured epoch.
public struct Consortium has key {
    id: UID,
    valset_action: u32,
    sets: vector<ValidatorSet>,
}

/// Create a consortium registry.
public fun new_consortium(valset_action: u32, ctx: &mut TxContext): Consortium {
    let id = object::new(ctx);
    Consortium {
        id: id,
        valset_action: valset_action,
        sets: vector[],
    }
}

/// Retrieve the validator set registered for an epoch. Aborts if absent.
public fun epoch_set(c: &Consortium, epoch: u64): ValidatorSet {
    let mut i: u64 = 0;
    while (i < vector::length(&c.sets)) {
        let s = *c.sets.borrow(i);
        if (s.epoch == epoch) {
            return s
        };
        i = i + 1;
    };
    abort 99
}

public fun pub_keys(s: &ValidatorSet): &vector<vector<u8>> {
    &s.pub_keys
}

public fun threshold(s: &ValidatorSet): u64 {
    s.weight_threshold
}

/// Validate and register a validator set for an epoch.
public fun configure_validator_set(
    c: &mut Consortium,
    action: u32,
    pub_keys: vector<vector<u8>>,
    weights: vector<u64>,
    weight_threshold: u64,
    epoch: u64,
) {
    assert!(action == c.valset_action, EInvalidAction);
    assert!(vector::length(&pub_keys) >= MIN_SET_SIZE, EInvalidSetSize);
    assert!(vector::length(&pub_keys) <= MAX_SET_SIZE, EInvalidSetSize);
    assert!(weight_threshold > 0, EInvalidThreshold);
    assert!(vector::length(&pub_keys) == vector::length(&weights), EInvalidLengths);
    let mut i: u64 = 0;
    while (i < vector::length(&pub_keys)) {
        assert!((*pub_keys.borrow(i)).length() == 65, EInvalidKeyLength);
        i = i + 1;
    };
    let mut a: u64 = 0;
    while (a < vector::length(&pub_keys)) {
        let mut b: u64 = a + 1;
        while (b < vector::length(&pub_keys)) {
            assert!(*pub_keys.borrow(a) != *pub_keys.borrow(b), EDuplicateValidator);
            b = b + 1;
        };
        a = a + 1;
    };
    let mut total: u64 = 0;
    let mut j: u64 = 0;
    while (j < vector::length(&weights)) {
        total = total + *weights.borrow(j);
        j = j + 1;
    };
    assert!(weight_threshold <= total, EThresholdExceedsTotal);
    let set = ValidatorSet {
        epoch: epoch,
        pub_keys: pub_keys,
        weights: weights,
        weight_threshold: weight_threshold,
    };
    c.sets.push_back(set);
}

/// Delete the consortium and its registered sets.
public fun delete_consortium(c: Consortium) {
    let Consortium { id, valset_action, sets } = c;
    object::delete(id);
    valset_action;
    sets;
}
