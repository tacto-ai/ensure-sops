import itertools
from typing import Any, Dict, Iterable, List, Optional, Set, TextIO, Tuple, Union

from ordered_set import OrderedSet

from ensure_sops import MissingSOPSMeta, UnencryptedItemsError, UnknownFormatError
from ensure_sops.enums import Formats, Methods


def _check_encryption(
    container: Union[List, Dict], prefix: str = ""
) -> Tuple[Set[str], Set[str]]:
    successful_keys = OrderedSet([])
    failed_keys = OrderedSet([])

    iterable: Iterable[Tuple[Any, Any]]
    if isinstance(container, dict):
        iterable = container.items()
    else:
        iterable = enumerate(container)

    for key, value in iterable:
        if (
            isinstance(value, str) and value.startswith("ENC[") and value.endswith("]")
        ) or value in ("", None):
            successful_keys.add(f"{prefix}{key}")
        elif isinstance(value, (dict, list)):
            successful_subkeys, failed_subkeys = _check_encryption(
                value, prefix=f"{prefix}{key}."
            )
            successful_keys.update(successful_subkeys)
            failed_keys.update(failed_subkeys)
        else:
            failed_keys.add(f"{prefix}{key}")
    return successful_keys, failed_keys


class SopsValidator:
    _file_cache: Optional[str]
    fmt: str

    def __init__(self, stream: TextIO, filename: str, method: Methods = Methods.strict):
        self.stream = stream
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

    def check_encryption(self, fmt: Formats, values: Dict[str, Any]) -> None:
        if fmt == Formats.bin:
            raise UnknownFormatError([fmt_class for fmt_class in self._parsers])
        else:
            has_sops_keys, user_defined_values = fmt.value.filter_values(values)
            successful_keys, failed_keys = _check_encryption(user_defined_values)
            if failed_keys:
                raise UnencryptedItemsError(failed_keys)
            elif not has_sops_keys:
                raise MissingSOPSMeta(list(values.keys()))

    def parse(self) -> Tuple[Formats, Dict[str, Any]]:
        self._cache_file()
        for fmt in self._parsers:
            is_success, values = fmt.value.parse(self._file_cache)
            if is_success:
                return fmt, values

        self._file_cache = None  # Cleanup Memory
        return Formats.bin, {}
