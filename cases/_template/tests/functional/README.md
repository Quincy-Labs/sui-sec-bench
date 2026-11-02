Put normal-behavior Move tests here (`*_tests.move`). They must pass on both
`vulnerable/` and `fixed/`. Use the 2024 edition test module form:

    #[test_only]
    module case::<name>_tests;

    #[test]
    fun test_x() { ... }

The harness copies them into a temp copy of each package's `tests/` folder
before running `sui move test`. The case folder is never modified.
