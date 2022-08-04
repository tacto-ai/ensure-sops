import pathlib
import sys
from argparse import ArgumentParser
from typing import Dict, List, Optional

from .exceptions import ValidationError
from .validator import Methods, SopsValidator


def _get_parser() -> ArgumentParser:
    argparser = ArgumentParser()
    argparser.add_argument("files", type=pathlib.Path, nargs="+")
    argparser.add_argument(
        "--method", type=Methods, choices=list(Methods), default=Methods.strict
    )
    return argparser


def _validate_files(
    paths: List[pathlib.Path], method: Methods
) -> Dict[pathlib.Path, str]:
    failed_files = {}
    for path in paths:
        with path.open() as stream:
            validator = SopsValidator(stream, path.name, method=method)
            fmt, values = validator.parse()
            try:
                validator.check_encryption(fmt, values)
            except ValidationError as e:
                failed_files[path] = str(e)
    return failed_files


def main(args: Optional[List[str]] = None) -> int:
    parser = _get_parser()
    parsed_args = parser.parse_args(args)

    errors = _validate_files(parsed_args.files, parsed_args.method)

    if errors:
        for path, error in errors.items():
            print(f"{path} - {error}", file=sys.stderr)
        return 1
    return 0
