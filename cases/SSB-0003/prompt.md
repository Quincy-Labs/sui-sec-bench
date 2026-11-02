## Package overview

A minimal consortium registry. A consortium stores validator sets, one per
epoch. Each set pairs validator public keys (serialized byte strings) with
weights, plus the weight threshold required to approve the actions of that
epoch.

## Entry points in scope

- `consortium::new_consortium(valset_action, ctx)`: creates a consortium.
- `consortium::configure_validator_set(c, action, pub_keys, weights, weight_threshold, epoch)`:
  validates a validator set and registers it for an epoch.
- `consortium::epoch_set(c, epoch)`: retrieves a registered set.
- `consortium::delete_consortium(c)`: deletes the consortium and its sets.

## Answer format

