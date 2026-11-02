# Sui Sec Bench

A preliminary pilot that tests local LLMs on Sui Move security tasks: finding a bug, patching it, and writing a test that demonstrates it. It covers three cases and six models, so the results are not a ranking.

- Report: [docs/PILOT-REPORT-clean.md](docs/PILOT-REPORT-clean.md)
- Tables: [leaderboard/README.md](leaderboard/README.md)
- Corrections to earlier drafts: [docs/review/CORRECTIONS.md](docs/review/CORRECTIONS.md)
- Running it and adding a case: [docs/REPRODUCE.md](docs/REPRODUCE.md)
- Responsible use: [docs/RESPONSIBLE_USE.md](docs/RESPONSIBLE_USE.md)
- Contributing a case: [CONTRIBUTING.md](CONTRIBUTING.md)

This repo holds grades without model outputs, and cases without exploit tests. You can rebuild the tables with `python3 leaderboard/build.py`. Regrading needs the restricted bundle, which isn't published here.
