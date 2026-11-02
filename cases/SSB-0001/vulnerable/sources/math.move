module case::math;

/// Scales a value up by 64 bits of fixed-point precision.
/// Reports whether the result does not fit the register.
public fun scale(n: u256): (u256, bool) {
    let mask = 0xffffffffffffffff << 192;
    if (n > mask) {
        (0, true)
    } else {
        (n << 64, false)
    }
}
