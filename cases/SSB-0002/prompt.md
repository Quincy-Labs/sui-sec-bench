## Package overview

A minimal cross-chain order book. Users open orders for auction over a target
chain; the winning driver of each auction settles the order on the destination
chain. The package ships two modules: `orders`, which stores an auction order
and its timing, and `fulfill`, which settles an order once its auction has
closed.

An order carries the address of the auction's winning driver, a deadline (unix
seconds) by which the auction must close, a penalty period in seconds that
opens immediately before the deadline, and the amount released on settlement.

## Entry points in scope

- `orders::new_order(driver, deadline, penalty_period, amount, ctx)`: creates
  an order item.
- `fulfill::prepare_fulfill_winner(order, clock, ctx)`: begins settlement of
  an order whose auction has closed; returns the amount released.
- `orders::delete_order(order)`: deletes a settled order.

## Answer format

