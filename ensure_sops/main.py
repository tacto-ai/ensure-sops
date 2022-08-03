import sys
from argparse import ArgumentParser, FileType
from io import TextIOWrapper
from typing import Dict, List, Optional

from .validator import Methods, SopsValidator


def _get_parser() -> ArgumentParser:
    argparser = ArgumentParser()
    argparser.add_argument("files", type=FileType("r"), nargs="+")
    argparser.add_argument(
        "--method", type=Methods, choices=list(Methods), default=Methods.strict
    )
    return argparser


def _validate_files(
    files: List[TextIOWrapper], method: Methods
) -> Dict[str, List[str]]:
    failed_files = {}
    for file in files:
        validator = SopsValidator(file, file.name, method=method)
        is_encrypted, failed_keys = validator.is_encrypted
        if not is_encrypted:
            failed_files[file.name] = failed_keys
    return failed_files


def main(args: Optional[List[str]] = None) -> int:
    parser = _get_parser()
    parsed_args = parser.parse_args(args)

    failed_files = _validate_files(parsed_args.files, parsed_args.method)

    if failed_files:
        for filename, keys in failed_files.items():
            print(f"Unencrypted keys found in {filename}, keys={keys}", file=sys.stdout)
        return 1
    return 0
