#[test_only]
module case::math_tests;

use case::math;
use case::pool;

#[test]
public fun scale_small() {
    let (v, bad) = math::scale(123);
    assert!(!bad, 0);
    assert!(v == 123 * (1 << 64), 0);
}

#[test]
public fun scale_normal() {
    let (v, bad) = math::scale(1 << 80);
    assert!(!bad, 0);
    assert!(v == 1 << 144, 0);
}

#[test_only]
public fun pool_normal() {
    let a = pool::get_delta_a(1 << 40, 1 << 40, 1 << 60);
    assert!(a == 1 << 20, 0);
}
