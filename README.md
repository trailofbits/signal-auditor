# Signal Key Transparency Auditor

This repo implements the Third-Party Auditor role for the
[Signal Key Transparency Log](https://github.com/signalapp/key-transparency-server).

Signal's key transparency uses a [Mekle^2](https://eprint.iacr.org/2021/453) style log, combining a prefix tree for version lookups with a left-balanced append-only log tree which tracks the history of the prefix tree and public key registrations.

# Usage

For interactive usage, run:

```
cargo run --config config.yaml
```

For Google Cloud storage, KMS and logging backends, use feature `gcp`

```
cargo run -F gcp
```