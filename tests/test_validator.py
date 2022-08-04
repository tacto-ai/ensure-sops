import pytest

from ensure_sops import (
    Formats,
    Methods,
    MissingSOPSMeta,
    SopsValidator,
    UnencryptedItemsError,
    UnknownFormatError,
)


def test_methods():
    """
    Methods' string representation must be same as their name and value.
    """
    for method in Methods:
        assert str(method) == method.name == method.value


@pytest.mark.parametrize(
    "extension",
    [
        "json",
        "yaml",
        "ini",
        "env",
    ],
)
def test_sops_validator_format_strict_with_correct_extension(extension, source_file):
    """
    If the method is strict, then SopsValidator should use the correct Format based on
    the file extension.
    """
    unencrypted_file = source_file(extension)
    with unencrypted_file.open() as stream:
        validator = SopsValidator(stream, unencrypted_file.name, method=Methods.strict)
        fmt, _ = validator.parse()

    assert fmt == Formats[extension]


@pytest.mark.parametrize(
    "extension",
    [
        "json",
        "yaml",
    ],
)
def test_sops_validator_format_strict_without_correct_extension_json_and_yaml(
    extension, source_file
):
    """
    If the method is strict, but the file extensions are not known, then SopsValidator
    should try json and yaml and parse them correctly.
    """

    unencrypted_file = source_file(extension)
    with unencrypted_file.open() as stream:
        validator = SopsValidator(
            stream,
            unencrypted_file.name.replace(extension, "foo"),
            method=Methods.strict,
        )
        fmt, _ = validator.parse()

    assert fmt == Formats[extension]


@pytest.mark.parametrize(
    "extension",
    [
        "env",
        "ini",
    ],
)
def test_sops_validator_format_strict_without_correct_extension_env_and_ini(
    extension, source_file
):
    """
    If the method is strict, but the file extensions are not known, then SopsValidator
    should try json and yaml. Thus env and ini should be marked as bin.
    """

    unencrypted_file = source_file(extension)
    with unencrypted_file.open() as stream:
        validator = SopsValidator(
            stream,
            unencrypted_file.name.replace(extension, "foo"),
            method=Methods.strict,
        )
        fmt, _ = validator.parse()

    assert fmt == Formats.bin


@pytest.mark.parametrize(
    "extension",
    [
        "json",
        "yaml",
        "ini",
        "env",
    ],
)
def test_sops_validator_format_bruteforce_with_correct_extension(
    extension, source_file
):
    """
    If the method is bruteforce, then SopsValidator should determine the correct format
    by trying all the possibilities, starting with the one that matches the file
    extension.
    """
    unencrypted_file = source_file(extension)
    with unencrypted_file.open() as stream:
        validator = SopsValidator(
            stream, unencrypted_file.name, method=Methods.bruteforce
        )
        fmt, _ = validator.parse()

    assert fmt == Formats[extension]


@pytest.mark.parametrize(
    "extension",
    [
        "json",
        "yaml",
        "ini",
        "env",
    ],
)
def test_sops_validator_format_bruteforce_without_correct_extension(
    extension, source_file
):
    """
    If the method is bruteforce, then SopsValidator should determine the correct format
    by trying all the possibilities in default order.
    """
    unencrypted_file = source_file(extension)
    with unencrypted_file.open() as stream:
        validator = SopsValidator(
            stream,
            unencrypted_file.name.replace(extension, "foo"),
            method=Methods.bruteforce,
        )
        fmt, _ = validator.parse()

    assert fmt == Formats[extension]


@pytest.mark.parametrize(
    "extension",
    [
        "json",
        "yaml",
        "ini",
        "env",
    ],
)
def test_sops_validator_check_encryption_correctly(extension, encrypt_file):
    """
    If the sops values are there and all the other keys are encrypted, then it should
    be a success.
    """
    encrypted_file = encrypt_file(extension)
    with encrypted_file.open() as stream:
        validator = SopsValidator(stream, encrypted_file.name, method=Methods.strict)
        fmt, values = validator.parse()
    validator.check_encryption(fmt, values)


@pytest.mark.parametrize(
    "extension",
    [
        "json",
        "yaml",
        "ini",
        "env",
    ],
)
def test_sops_validator_check_encryption_unencrypted(extension, source_file):
    """
    If the sops values are there but the other keys are unencrypted, then it should
    return False and the failed items.
    """
    unencrypted_file = source_file(extension)
    with unencrypted_file.open() as stream:
        validator = SopsValidator(stream, unencrypted_file.name, method=Methods.strict)
        fmt, values = validator.parse()
    with pytest.raises(UnencryptedItemsError):
        validator.check_encryption(fmt, values)


@pytest.mark.parametrize(
    "extension",
    [
        "json",
        "yaml",
        "ini",
        "env",
    ],
)
def test_sops_validator_check_encryption_missing_sops(extension, encrypt_file):
    """
    If the sops values are not there and all the other keys are encrypted, then it
    should return False but no failed items.
    """
    encrypted_file = encrypt_file(extension)
    with encrypted_file.open() as stream:
        validator = SopsValidator(stream, encrypted_file.name, method=Methods.strict)
        fmt, values = validator.parse()
        _, broken_values = fmt.value.filter_values(values)
    with pytest.raises(MissingSOPSMeta) as excinfo:
        validator.check_encryption(fmt, broken_values)
    assert not [
        key
        for key in excinfo.value.data["found_keys"]
        if fmt.value.ignore_pattern.match(key)
    ]


def test_sops_validator_check_encryption_encrypted_bin(encrypt_file):
    """
    Bin format is a special case. When we're running on strict mode, the validator
    still tries to parse unknown file extensions with json and yaml. If it can parse
    the file, then it's format will be json or yaml, not bin, thus work as expected.
    If it can't determine the file format, the format will be set as bin and bin
    files are by default cannot be parsed or checked for encryption.

    In this example the bin file is encrypted with output format as json, thus will
    be validated as it's a json.
    """
    extension = "bin"
    encrypted_file = encrypt_file(extension)
    with encrypted_file.open() as stream:
        validator = SopsValidator(stream, encrypted_file.name, method=Methods.strict)
        fmt, values = validator.parse()
    validator.check_encryption(fmt, values)


def test_sops_validator_check_encryption_unencrypted_bin(source_file):
    """
    Bin format is a special case. When we're running on strict mode, the validator
    still tries to parse unknown file extensions with json and yaml. If it can parse
    the file, then it's format will be json or yaml, not bin, thus work as expected.
    If it can't determine the file format, the format will be set as bin and bin
    files are by default cannot be parsed or checked for encryption.

    In this example the bin file is unencrypted, thus cannot be parsed, or checked.
    """
    extension = "bin"
    unencrypted_file = source_file(extension)
    with unencrypted_file.open() as stream:
        validator = SopsValidator(stream, unencrypted_file.name, method=Methods.strict)
        fmt, values = validator.parse()
    with pytest.raises(UnknownFormatError):
        validator.check_encryption(fmt, values)


@pytest.mark.parametrize(
    "extension",
    [
        "json",
        "yaml",
        "ini",
    ],
)
def test_sops_validator_check_encryption_broken_nested(extension, encrypt_file):
    """
    If the sops values are there but not all the other keys (including nested ones) are
    encrypted, then it should return False and the failed items.
    """
    encrypted_file = encrypt_file(extension)
    with encrypted_file.open() as stream:
        validator = SopsValidator(stream, encrypted_file.name, method=Methods.strict)
        fmt, values = validator.parse()
        values.update(
            {
                "parent": {
                    "children": [{"working_one": "ENC[]"}, {"broken_one": "ha-ha!"}]
                }
            }
        )
    with pytest.raises(UnencryptedItemsError) as excinfo:
        validator.check_encryption(fmt, values)
    assert excinfo.value.data["items"] == {"parent.children.1.broken_one"}
