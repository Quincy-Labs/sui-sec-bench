module case::orders;

use sui::object;
use sui::tx_context;

/// A cross-chain order in a sealed auction. The winning driver of the auction
/// settles the order on the destination chain before the deadline.
public struct OrderItem has key {
    id: UID,
    driver: address,
    deadline: u64,
    penalty_period: u64,
    amount: u64,
}

/// Create an order item.
public fun new_order(
    driver: address,
    deadline: u64,
    penalty_period: u64,
    amount: u64,
    ctx: &mut TxContext,
): OrderItem {
    let id = object::new(ctx);
    OrderItem {
        id: id,
        driver: driver,
        deadline: deadline,
        penalty_period: penalty_period,
        amount: amount,
    }
}

public fun driver(o: &OrderItem): address {
    o.driver
}

public fun deadline(o: &OrderItem): u64 {
    o.deadline
}

public fun penalty_period(o: &OrderItem): u64 {
    o.penalty_period
}

public fun amount(o: &OrderItem): u64 {
    o.amount
}

/// Delete a settled order.
public fun delete_order(o: OrderItem) {
    let OrderItem { id, driver, deadline, penalty_period, amount } = o;
    object::delete(id);
    driver;
    deadline;
    penalty_period;
    amount;
}
