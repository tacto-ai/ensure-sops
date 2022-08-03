import io

import pytest

from ensure_sops import Formats, Methods, SopsValidator

generic_sops_values = {
    "sops": {
        "kms": "",
        "gcp_kms": "",
        "azure_kv": "",
        "hc_vault": "",
        "age": "",
        "lastmodified": "",
        "mac": "",
        "pgp": [],
        "unencrypted_suffix": "",
        "version": "",
    }
}
env_sops_values = {
    "sops_pgp__list_0__map_enc": "None",
    "sops_pgp__list_0__map_created_at": "None",
    "sops_mac": "None",
    "sops_unencrypted_suffix": "None",
    "sops_lastmodified": "None",
    "sops_pgp__list_0__map_fp": "None",
    "sops_version": "None",
}


def test_methods():
    """
    Methods' string representation must be same as their name and value.
    """
    for method in Methods:
        assert str(method) == method.name == method.value


def test_sops_validator_format_strict_with_correct_extension():
    """
    If the method is strict, then SopsValidator should use the correct Format based on
    the file extension.
    """
    validator = SopsValidator(
        io.StringIO('{"a":10}'), "test.json", method=Methods.strict
    )
    assert validator.format == Formats.json
    validator = SopsValidator(io.StringIO("a: 10"), "test.yaml", method=Methods.strict)
    assert validator.format == Formats.yaml
    validator = SopsValidator(
        io.StringIO("[global]\na=10"), "test.ini", method=Methods.strict
    )
    assert validator.format == Formats.ini
    validator = SopsValidator(io.StringIO("A=10"), "test.env", method=Methods.strict)
    assert validator.format == Formats.env
    validator = SopsValidator(
        io.StringIO("Lorem ipsum dolor"), "test.env", method=Methods.strict
    )
    assert validator.format == Formats.bin


def test_sops_validator_format_strict_without_correct_extension_supported_formats():
    """
    If the method is strict, but the file extensions are not known, then SopsValidator
    should try json and yaml. Because Sops only supports those two formats for
    unsupported file types.
    """
    validator = SopsValidator(
        io.StringIO('{"a":10}'), "test.foo", method=Methods.strict
    )
    assert validator.format == Formats.json
    validator = SopsValidator(io.StringIO("a: 10"), "test.foo", method=Methods.strict)
    assert validator.format == Formats.yaml
    validator = SopsValidator(
        io.StringIO("[global]\na=10"), "test.foo", method=Methods.strict
    )
    assert validator.format == Formats.bin
    validator = SopsValidator(io.StringIO("A=10"), "test.foo", method=Methods.strict)
    assert validator.format == Formats.bin


def test_sops_validator_format_bruteforce_with_correct_extension():
    """
    If the method is bruteforce, then SopsValidator should determine the correct format
    by trying all the possibilities, starting with the one that matches the file
    extension.
    """
    validator = SopsValidator(
        io.StringIO('{"a":10}'), "test.json", method=Methods.bruteforce
    )
    assert validator.format == Formats.json
    validator = SopsValidator(
        io.StringIO("a: 10"), "test.yaml", method=Methods.bruteforce
    )
    assert validator.format == Formats.yaml
    validator = SopsValidator(
        io.StringIO("[global]\na=10"), "test.ini", method=Methods.bruteforce
    )
    assert validator.format == Formats.ini
    validator = SopsValidator(
        io.StringIO("A=10"), "test.env", method=Methods.bruteforce
    )
    assert validator.format == Formats.env
    validator = SopsValidator(
        io.StringIO("Lorem ipsum dolor"), "test.bin", method=Methods.bruteforce
    )
    assert validator.format == Formats.bin


def test_sops_validator_format_bruteforce_without_correct_extension():
    """
    If the method is bruteforce, then SopsValidator should determine the correct format
    by trying all the possibilities in default order.
    """
    validator = SopsValidator(
        io.StringIO('{"a":10}'), "test.foo", method=Methods.bruteforce
    )
    assert validator.format == Formats.json
    validator = SopsValidator(
        io.StringIO("a: 10"), "test.foo", method=Methods.bruteforce
    )
    assert validator.format == Formats.yaml
    validator = SopsValidator(
        io.StringIO("[global]\na=10"), "test.foo", method=Methods.bruteforce
    )
    assert validator.format == Formats.ini
    validator = SopsValidator(
        io.StringIO("A=10"), "test.foo", method=Methods.bruteforce
    )
    assert validator.format == Formats.env
    validator = SopsValidator(
        io.StringIO("Lorem ipsum dolor"), "test.foo", method=Methods.bruteforce
    )
    assert validator.format == Formats.bin


@pytest.mark.parametrize(
    "extension,sops_values",
    [
        ("json", generic_sops_values),
        ("yaml", generic_sops_values),
        ("ini", generic_sops_values),
        ("env", env_sops_values),
    ],
)
def test_sops_validator_is_encrypted_correctly(extension, sops_values, mocker):
    """
    If the sops values are there and all the other keys are encrypted, then it should
    be a success.
    """
    validator = SopsValidator(io.StringIO(), f"test.{extension}", method=Methods.strict)
    mocker.patch.object(validator, "format", Formats[extension])

    validator.values = {**sops_values, "data": "ENC[]"}
    is_encrypted, failed_values = validator.is_encrypted
    assert is_encrypted
    assert failed_values == []


def test_sops_validator_is_encrypted_unencrypted(mocker):
    """
    If the sops values are there but the other keys are unencrypted, then it should
    return False and the failed items.
    """
    validator = SopsValidator(io.StringIO(), "test.json", method=Methods.strict)
    mocker.patch.object(validator, "format", Formats.json)
    validator.values = {**generic_sops_values, "data": ""}
    is_encrypted, failed_values = validator.is_encrypted
    assert not is_encrypted
    assert ["data"]


def test_sops_validator_is_encrypted_missing_sops(mocker):
    """
    If the sops values are not there and all the other keys are encrypted, then it
    should return False but no failed items.
    """
    validator = SopsValidator(io.StringIO(), "test.json", method=Methods.strict)
    mocker.patch.object(validator, "format", Formats.json)
    validator.values = {"data": "ENC[]"}
    is_encrypted, failed_values = validator.is_encrypted
    assert not is_encrypted
    assert failed_values == []


def test_sops_validator_is_encrypted_bin(mocker):
    """
    Bin format is a special case, We know that it can't be encrypted because it's
    unsupported by SOPS. We don't parse the file in this case, therefore no items to
    fail. Thus, is_encrypted should return False, and no failed items.

    This statement is true, even if the file has sops values and only encrypted items.
    """
    validator = SopsValidator(io.StringIO(), "test.bin", method=Methods.strict)
    mocker.patch.object(validator, "format", Formats.bin)
    validator.values = {**generic_sops_values, "data": "ENC[]"}
    is_encrypted, failed_values = validator.is_encrypted
    assert not is_encrypted
    assert failed_values == []


def test_sops_validator_is_encrypted_correctly_nested(mocker):
    """
    If the sops values are there and all the other keys (including nested ones) are
    encrypted, then it should return True and no failed items.
    """
    validator = SopsValidator(io.StringIO(), "test.json", method=Methods.strict)
    mocker.patch.object(validator, "format", Formats.json)

    validator.values = {
        **generic_sops_values,
        "data": {"subdata": [{"even_more_subdata": "ENC[]"}]},
    }
    is_encrypted, failed_values = validator.is_encrypted
    assert is_encrypted
    assert failed_values == []


def test_sops_validator_is_encrypted_broken_nested(mocker):
    """
    If the sops values are there but not all the other keys (including nested ones) are
    encrypted, then it should return False and the failed items.
    """
    validator = SopsValidator(io.StringIO(), "test.json", method=Methods.strict)
    mocker.patch.object(validator, "format", Formats.json)

    validator.values = {
        **generic_sops_values,
        "data": {"subdata": [{"even_more_subdata": "ENC[]"}, {"fail_me": ""}]},
    }
    is_encrypted, failed_values = validator.is_encrypted
    assert not is_encrypted
    assert failed_values == ["data.subdata.1.fail_me"]
