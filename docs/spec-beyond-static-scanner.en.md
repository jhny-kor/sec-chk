# KODA Beyond-Static-Scanner Specification

This is the English entry point for the implementation specification behind AI
triage, reachability, deterministic auto-fix, and changed-file CI. The design
keeps discovery separate from deterministic validation, makes writes dry-run by
default, and keeps cloud transfer explicitly opt-in.

The source specification contains module boundaries, CLI/config contracts, and
the historical implementation record. Current behavior is defined by the
[English CLI guide](usage.md), while planning detail remains in the [Korean
specification](spec-beyond-static-scanner.md).

- [English documentation index](README.en.md)
- [Korean implementation specification](spec-beyond-static-scanner.md)
