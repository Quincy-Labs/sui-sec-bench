module case::fulfill;

use sui::tx_context;
use sui::clock;
use sui::clock::Clock;
use case::orders::{Self, OrderItem};

const EDeadlinePassed: u64 = 0;
const EInvalidDriver: u64 = 1;

/// Begin settlement of an order after its auction has closed.
/// Releases the order's amount to the auction winner.
public fun prepare_fulfill_winner(order: &mut OrderItem, clock: &Clock, ctx: &mut TxContext): u64 {
    assert!(orders::driver(order) == ctx.sender(), EInvalidDriver);
    let now_s = clock::timestamp_ms(clock) / 1000;
    assert!(orders::deadline(order) > now_s, EDeadlinePassed);
    orders::amount(order)
}
