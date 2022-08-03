import enum
import itertools
from functools import cached_property
from typing import Any, Dict, Iterable, List, Optional, TextIO, Tuple, Union

from ensure_sops.formats import Formats


class Methods(enum.Enum):
    """
    strict: Try either the one matching with file extension or json
    bruteforce: Try all, starting from the one which matches with file extensions
    """

    strict = "strict"
    bruteforce = "bruteforce"

    def __str__(self):
        return self.name


def _check_encryption(
    container: Union[List, Dict], prefix: str = ""
) -> Tuple[List[str], List[str]]:
    successful_keys = []
    failed_keys = []

    iterable: Iterable[Tuple[Any, Any]]
    if isinstance(container, dict):
        iterable = container.items()
    else:
        iterable = enumerate(container)

    for key, value in iterable:
        if (
            isinstance(value, str) and value.startswith("ENC[") and value.endswith("]")
        ) or value is None:
            successful_keys.append(f"{prefix}{key}")
        elif isinstance(value, (dict, list)):
            successful_subkeys, failed_subkeys = _check_encryption(
                value, prefix=f"{prefix}{key}."
            )
            successful_keys.extend(successful_subkeys)
            failed_keys.extend(failed_subkeys)
        else:
            failed_keys.append(f"{prefix}{key}")
    return successful_keys, failed_keys


class SopsValidator:
    _file_cache: Optional[str]
    fmt: str

    def __init__(self, stream: TextIO, filename: str, method: Methods = Methods.strict):
        self.stream = stream
        self.values: Dict[str, Any] = {}
        self.filename = filename
        self.method = method
        self._parsers = self._determine_parsers(self.filename)

    def _determine_parsers(self, filename: str) -> List[Formats]:
        suffixes = filename.split(".")[1:]

        hinted_fmt = None
        for fmt, suffix in itertools.product(Formats, suffixes):
            if suffix in fmt.value.extensions:
                hinted_fmt = fmt
                break

        if self.method == Methods.strict:
            if hinted_fmt is not None:
                return [hinted_fmt]
            else:
                return [Formats.json, Formats.yaml]  # Binary files use json by default

        reordered_formats = list(Formats)
        if hinted_fmt:
            reordered_formats.insert(
                0, reordered_formats.pop(reordered_formats.index(hinted_fmt))
            )
        return reordered_formats

    def _cache_file(self) -> None:
        position = self.stream.tell()
        file_content = self.stream.read()
        self._file_cache = file_content
        self.stream.seek(position)

    @cached_property
    def is_encrypted(self) -> Tuple[bool, List[str]]:
        if self.format == Formats.bin:
            return False, []
        else:
            has_sops_keys, user_defined_values = self.format.value.filter_values(
                self.values
            )
            successful_keys, failed_keys = _check_encryption(user_defined_values)
            if failed_keys or not has_sops_keys:
                return False, failed_keys
            else:
                return True, failed_keys

    @cached_property
    def format(self) -> Formats:
        self._cache_file()
        for fmt in self._parsers:
            is_success, values = fmt.value.parse(self._file_cache)
            if is_success:
                self.values = values
                return fmt

        self._file_cache = None  # Cleanup Memory
        return Formats.bin
