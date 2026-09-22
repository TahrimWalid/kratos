"""Makes `python -m kratos` work the same as the `kratos` console script."""
from kratos.cli.app import main

if __name__ == "__main__":
    raise SystemExit(main())

