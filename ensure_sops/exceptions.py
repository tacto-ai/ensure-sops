from typing import Any, Dict, List, Set

from ensure_sops import Formats


class ValidationError(Exception):
    message: str
    data: Dict[str, Any]

    def __str__(self):
        return self.message.format(**self.data)


class UnknownFormatError(ValidationError):
    message = (
        "File format cannot be determined, here's the list of formats tried: "
        "{tried_formats}"
    )

    def __init__(self, tried_formats: List[Formats]):
        self.data = {"tried_formats": [fmt.name for fmt in tried_formats]}


class UnencryptedItemsError(ValidationError):
    message = "Some items in this file are not encrypted, here's the list: " "{items}"

    def __init__(self, items: Set[str]):
        self.data = {"items": items}


class MissingSOPSMeta(ValidationError):
    message = (
        "SOPS metadata is missing, here's all the top level keys in the file: "
        "{found_keys}"
    )

    def __init__(self, found_keys: List[str]):
        self.data = {"found_keys": found_keys}
