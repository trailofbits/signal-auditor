# Signal Key Transparency Auditor

This repo implements the Third-Party Auditor role for the
[Signal Key Transparency Log](https://github.com/signalapp/key-transparency-server).

Signal's key transparency uses a [Mekle^2](https://eprint.iacr.org/2021/453) style log, combining a prefix tree for version lookups with a left-balanced append-only log tree which tracks the history of the prefix tree and public key registrations.

# Usage

For interactive usage, run:

```
cargo run main
```

To reduce clutter, you can run:

```
cargo run main > log.out & watch tail -n 2 log.out
```

For Google Cloud Logging compatible JSON, use feature `stackdriver`

```
cargo run main -F stackdriver
```