from pathlib import Path

from prevent_visit.cli import main


if __name__ == "__main__":
    config_path = Path(__file__).resolve().parent / "config" / "settings.json"
    import sys

    sys.argv = [
        "prevent-visit",
        "run-service",
        "--config",
        str(config_path),
    ]
    main()
