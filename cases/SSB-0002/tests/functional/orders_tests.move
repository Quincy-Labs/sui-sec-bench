#[test_only]
module case::orders_tests;

use std::hash;
use std::vector;
use sui::tx_context;
use sui::clock;
use case::orders::{new_order, delete_order};
use case::fulfill;

#[test]
public fun driver_can_fulfill_inside_penalty_window() {
    let h = hash::sha2_256(vector[1u8]);
    let mut dctx = tx_context::new(@0x1111, h, 1, 0, 0);
    let mut clk = clock::create_for_testing(&mut dctx);
    clock::set_for_testing(&mut clk, 1700000000000);
    let now_s = clock::timestamp_ms(&clk) / 1000;
    // The penalty window is [deadline - penalty, deadline] and contains `now_s`.
    let mut o = new_order(@0x1111, now_s + 300, 200, 5000, &mut dctx);
    let out = fulfill::prepare_fulfill_winner(&mut o, &clk, &mut dctx);
    assert!(out == 5000, 0);
    clock::destroy_for_testing(clk);
    delete_order(o);
}
