# 1. Apache 2.0, with ClamAV as a separate process

Date: 2026-11-27. Status: accepted.

## Context

OpenScout is fully open source. ClamAV gives free signatures but is GPLv2. Linking libclamav would make the whole app GPL.

## Decision

OpenScout is Apache 2.0. ClamAV runs as a separate process through `clamscan` and `freshclam`, called with an argument array, never a shell. The same applies to YARA, which keeps the engines swappable.

## Consequences

Apache 2.0 keeps contribution and reuse simple and includes a patent grant. The cost is process overhead per scan batch, which batching 200 files at a time keeps small. Bundling the engines later needs a GPL-compliant way to ship ClamAV's binaries next to the app.
