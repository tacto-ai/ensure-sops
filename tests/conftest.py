import pathlib
import subprocess

import pytest


@pytest.fixture(scope="session")
def tests_dir():
    return pathlib.Path(__file__).parent


@pytest.fixture
def source_file(tests_dir, tmp_path):
    def _f(extension):
        return tests_dir / f"files/test.{extension}"

    return _f


@pytest.fixture
def encrypt_file(tests_dir, tmp_path, source_file):
    def _encrypt(extension):
        if extension == "bin":
            in_type = "bin"
            out_type = "json"
        elif extension == "env":
            in_type = out_type = "dotenv"
        else:
            in_type = out_type = extension

        output_path = tmp_path / f"enc.test.{extension}"
        tmp_path.mkdir(parents=True, exist_ok=True)
        with output_path.open("w") as out:
            subprocess.Popen(
                [
                    "sops",
                    "--config",
                    tests_dir / ".sops.yaml",
                    "--input-type",
                    in_type,
                    "--output-type",
                    out_type,
                    "--encrypt",
                    source_file(extension),
                ],
                stdout=out,
                stderr=subprocess.DEVNULL,
            ).wait()
        return output_path

    return _encrypt
