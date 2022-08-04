import configparser
import io
import json
import logging
import re
from typing import Any, Dict, List, Optional, Tuple

import dotenv
from ruamel.yaml import YAML
from ruamel.yaml.parser import ParserError

yaml = YAML(typ="safe")

logger = logging.getLogger("dotenv.main")
logger.setLevel(logging.ERROR)


class Format:
    name: str
    extensions: List[str]
    ignore_pattern: re.Pattern

    def parse(
        self, raw_string: str
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:  # pragma: no cover
        return NotImplemented

    def filter_values(self, values: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        has_sops_keys = False
        user_defined_values = {}
        ignore_pattern: re.Pattern = self.ignore_pattern
        for key, value in values.items():
            if not ignore_pattern.match(key):
                user_defined_values[key] = value
            else:
                has_sops_keys = True
        return has_sops_keys, user_defined_values


class JsonFormat(Format):
    name: str = "json"
    extensions: List[str] = ["json"]
    ignore_pattern: re.Pattern = re.compile("^sops$")

    def parse(self, raw_string: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        try:
            values = json.loads(raw_string)
            if not isinstance(values, dict):
                return False, None
        except json.JSONDecodeError:
            return False, None
        else:
            return True, values


class YamlFormat(Format):
    name: str = "yaml"
    extensions: List[str] = ["yaml", "yml"]
    ignore_pattern: re.Pattern = re.compile("^sops$")

    def parse(self, raw_string: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        try:
            values = yaml.load(raw_string)
            if not isinstance(values, dict):
                return False, None
        except ParserError:
            return False, None
        else:
            return True, values


class IniFormat(Format):
    name: str = "ini"
    extensions: List[str] = ["ini", "cfg", "conf", "config"]
    ignore_pattern: re.Pattern = re.compile("^sops$")

    def ini_to_dict(self, parser):
        results = {}
        for section in parser.sections():
            results[section] = {}
            for key, value in parser.items(section):
                results[section][key] = None if value == "" else value
        return results

    def parse(self, raw_string: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        parser = configparser.ConfigParser()
        try:
            parser.read_string(raw_string)
            values = self.ini_to_dict(parser)
            if not values:
                return False, None
        except configparser.ParsingError:
            return False, None
        else:
            return True, values


class EnvFormat(Format):
    name: str = "env"
    extensions: List[str] = ["env"]
    ignore_pattern: re.Pattern = re.compile("^sops_.+")

    def parse(self, raw_string: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        values = dotenv.dotenv_values(stream=io.StringIO(raw_string))
        cleaned_values = {
            key: value for key, value in values.items() if value not in ("", None)
        }
        if not bool(cleaned_values):
            return False, None
        else:
            return True, cleaned_values


class BinFormat(Format):
    name: str = "bin"
    extensions: List[str] = []
    ignore_pattern: re.Pattern = re.compile("^$")

    def parse(self, raw_string: str) -> Tuple[bool, Optional[Dict[str, Any]]]:
        return False, None
