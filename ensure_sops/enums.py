import enum

from .formats import BinFormat, EnvFormat, IniFormat, JsonFormat, YamlFormat


class Formats(enum.Enum):
    json = JsonFormat()
    ini = IniFormat()
    yaml = YamlFormat()
    env = EnvFormat()
    bin = BinFormat()


class Methods(enum.Enum):
    """
    strict: Try either the one matching with file extension or json
    bruteforce: Try all, starting from the one which matches with file extensions
    """

    strict = "strict"
    bruteforce = "bruteforce"

    def __str__(self):
        return self.name
