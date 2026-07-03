from pathlib import Path
import sys

from prevent_visit.cli import main


if __name__ == "__main__":
    repo_root = Path(__file__).resolve().parent
    config_path = repo_root / "config" / "settings.json"

    # If no arguments provided, show help
    if len(sys.argv) == 1:
        sys.argv = ["prevent-visit"]

    # Add config path to relevant commands
    if len(sys.argv) >= 2:
        command = sys.argv[1]
        if command in ("install", "uninstall", "start", "stop", "status", "run-service"):
            if "--config" not in sys.argv:
                sys.argv.extend(["--config", str(config_path)])
        if command in ("install", "uninstall"):
            if "--repo-root" not in sys.argv:
                sys.argv.extend(["--repo-root", str(repo_root)])

    main()
