module case::pool;

use case::math;

const ERange: u64 = 0;

/// Token A required for a position of the given liquidity spanning
/// the given square-root price interval.
public fun get_delta_a(liquidity: u256, delta_sqrt: u256, den: u256): u256 {
    let (num, bad) = math::scale(liquidity * delta_sqrt);
    if (bad) {
        abort ERange;
    };
    num / den
}
