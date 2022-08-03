import io

import pytest

from ensure_sops.formats import (
    BinFormat,
    EnvFormat,
    Format,
    Formats,
    IniFormat,
    JsonFormat,
    YamlFormat,
)


@pytest.mark.parametrize(
    "extension,formatter_class",
    [
        ("json", JsonFormat),
        ("yaml", YamlFormat),
        ("ini", IniFormat),
        ("env", EnvFormat),
    ],
)
def test_formatter_encrypted(extension, formatter_class, encrypt_file):
    """
    Check format's behavior for encrypted files. All should succeed to parse and
    validate their encryption status.
    """
    path = encrypt_file(extension)
    formatter = formatter_class()
    with path.open() as stream:
        is_success, values = formatter.parse(stream.read())
    assert is_success
    assert values.keys()
    assert any((key for key in values if formatter.ignore_pattern.match(key)))
    is_encrypted, cleaned_values = formatter.filter_values(values)
    assert is_encrypted
    assert not any(
        (key for key in cleaned_values if formatter.ignore_pattern.match(key))
    )


@pytest.mark.parametrize(
    "extension,formatter_class",
    [
        ("json", JsonFormat),
        ("yaml", YamlFormat),
        ("ini", IniFormat),
        ("env", EnvFormat),
    ],
)
def test_formatter_unencrypted(extension, formatter_class, source_file):
    """
    Check format's behavior for unencrypted files. All should succeed to parse and
    validate encryption.
    """
    path = source_file(extension)
    formatter = formatter_class()
    with path.open() as stream:
        is_success, values = formatter.parse(stream.read())
    assert is_success
    assert values.keys()
    assert not any((key for key in values if formatter.ignore_pattern.match(key)))
    is_encrypted, cleaned_values = formatter.filter_values(values)
    assert not is_encrypted


@pytest.mark.parametrize(
    "formatter_class", [JsonFormat, YamlFormat, IniFormat, EnvFormat]
)
def test_formatter_empty(formatter_class):
    """
    Check format's behavior for unencrypted files. All should succeed to parse and
    validate encryption.
    """
    stream = io.StringIO()
    formatter = formatter_class()
    is_success, values = formatter.parse(stream.read())
    assert not is_success
    assert values is None
    is_encrypted, cleaned_values = formatter.filter_values({})
    assert not is_encrypted
    assert not cleaned_values


def test_formatter_broken_json():
    """
    Test the json parser's JSONDecodeError
    """
    stream = io.StringIO("[]")
    formatter = JsonFormat()
    is_success, values = formatter.parse(stream.read())
    assert not is_success
    assert values is None


def test_formatter_broken_yaml():
    """
    Test the yaml parser's ParserError
    """
    stream = io.StringIO("{:]")
    formatter = YamlFormat()
    is_success, values = formatter.parse(stream.read())
    assert not is_success
    assert values is None


def test_formatter_broken_ini():
    """
    Test the ini parser's ParsingError
    """
    stream = io.StringIO("[]")
    formatter = IniFormat()
    is_success, values = formatter.parse(stream.read())
    assert not is_success
    assert values is None


def test_bin_formatter(encrypt_file):
    """
    Bin is a special case that always fails. It's used in place of unsupported files.
    """
    path = encrypt_file("bin")
    formatter = BinFormat()
    with path.open() as stream:
        is_success, values = formatter.parse(stream.read())
    assert not is_success
    assert values is None
    is_encrypted, cleaned_values = formatter.filter_values({})
    assert not is_encrypted
    assert not cleaned_values


def test_formats():
    """
    All entries in Formats must be instances of Format or it's subclasses.
    """
    for fmt in Formats:
        assert isinstance(fmt.value, Format)
