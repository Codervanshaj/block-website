import shutil
import uuid
from pathlib import Path

from prevent_visit.certs import CertificateManager
from prevent_visit.config import AppConfig


def test_generates_root_ca_files() -> None:
    temp_root = Path("build") / f"test-certs-{uuid.uuid4().hex}"
    config = AppConfig(certs_dir=str(temp_root / "certs"))
    manager = CertificateManager(config)

    try:
        key_path, cert_path = manager.ensure_root_ca()

        assert key_path.exists()
        assert cert_path.exists()
        assert (temp_root / "certs" / "root_ca_cert.cer").exists()
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)
