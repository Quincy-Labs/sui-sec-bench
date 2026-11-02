# Contributing a case

The public repo holds cases without exploit tests. Exploit tests live in a restricted bundle that isn't published. Never put an exploit test in a public pull request or issue.

See also [docs/REPRODUCE.md](docs/REPRODUCE.md) and [docs/RESPONSIBLE_USE.md](docs/RESPONSIBLE_USE.md).

## Two ways to contribute

### Propose a case (public)

Open a GitHub issue with the **Case proposal** template. Our team writes the case.

### Submit a full case (private)

1. Create the case:

   ```bash
   uv run python scripts/new_case.py
   ```

2. Fill it in, then check it, using your new case id:

   ```bash
   uv run python harness/check_case.py cases/SSB-0004
   uv run python scripts/leak_check.py cases/SSB-0004
   ```

3. Send it privately to cases@quincylabs.org, as a zip or by asking for a private repo invite.

Don't open a public pull request that contains exploit tests.

## What makes a good case

- It's based on a public finding or incident that is already fixed.
- It's a minimal rewrite, not copied production code.
- It has one clear bug.
- It builds on the Sui CLI version in [docs/REPRODUCE.md](docs/REPRODUCE.md).
- Functional tests pass on both `vulnerable/` and `fixed/`.
- The exploit test passes on `vulnerable/` and fails on `fixed/`.

## What we don't accept

- Unreported bugs in live protocols. Report those to the protocol's bug bounty first.
- Real mainnet addresses or package IDs.
- Large copied chunks of audit reports or code.

## Credit

Contributors are credited in the case's `meta.yaml` (the `contributors` field) and in the release notes.

## License

Contributions are under Apache-2.0, the same as the repo.
