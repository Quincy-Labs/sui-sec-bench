## Package overview

A minimal automated market maker (AMM). Users open and size positions over
square-root price intervals. The package ships two modules: `math`, a
fixed-point helper, and `pool`, which computes the token amounts required
for a position.

`math::scale(n)` shifts a value up by 64 bits of fixed-point precision and
reports whether the result does not fit the register.

## Entry points in scope

- `pool::get_delta_a(liquidity, delta_sqrt, den)`: amount of token A required
  for a position with the given liquidity over the given square-root price
  interval.
- `math::scale(n)`: fixed-point upscaling of one value.

## Answer format

Audit the package and report the most severe vulnerability, if any.

Answer in JSON:

```json
{"found": true, "bug_class": "arithmetic|access-control|input-validation|object-validation|business-logic|oracle-price|shared-object|upgrade-versioning|none", "location": "module::function", "explanation": "one or two sentences"}
```
