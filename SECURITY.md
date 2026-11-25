# Security policy

## Reporting

Please report security problems privately through GitHub's
"Report a vulnerability" button on this repository rather than in a public issue.

## Scope

cargo-cbom reads `cargo metadata` output and prints a report. It does not build or run
your code, and it does not execute build scripts. Running it without `--metadata` calls
`cargo metadata`, which may download crate sources unless you pass `--offline` or
`--frozen`.

A wrong or outdated rule (for example, a crate reported as post-quantum when it is
not) is a bug, not a vulnerability: please open a normal issue or pull request with a
link to the source that shows the correct behavior.

## Disclaimer

The report is an aid for planning a post-quantum migration. It describes what is
compiled into a project, not how the code uses it, and it is not a substitute for a
security review.
