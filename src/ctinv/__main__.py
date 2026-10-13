"""Allow running the CLI as ``python -m ctinv``."""

from ctinv.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
