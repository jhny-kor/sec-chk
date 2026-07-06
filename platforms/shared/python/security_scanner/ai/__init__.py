"""Optional, opt-in AI layer for KODA.

Everything here stays disabled by default. The local (Ollama) backend uses only the
standard library and sends nothing off the machine; cloud backends are lazy-imported
optional extras. See docs/spec-beyond-static-scanner.md for the design.
"""
