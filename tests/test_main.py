import shutil

from ensure_sops import Methods, main


def test_main_unencrypted(tests_dir, capsys):
    """
    Unencrypted files should exit with return_code == 1
    """
    return_code = main([str(tests_dir / "files" / "test.json")])
    captured = capsys.readouterr()
    path, message = captured.err.split(" - ")
    assert return_code == 1
    assert path.endswith("test.json")
    expected_message = (
        "Some items in this file are not encrypted, here's the list:"
        " OrderedSet(['a', 'b', 'c.0', 'c.1', 'e', 'f', 'sub.a', "
        "'sub.b', 'sub.c.0', 'sub.c.1', 'sub.e', 'sub.f'])\n"
    )
    assert message == expected_message


def test_main_encrypted(encrypt_file):
    """
    Encrypted files should exit with return_code == 0
    """
    return_code = main([str(encrypt_file("json"))])
    assert return_code == 0


def test_main_methods_strict(encrypt_file, capsys):
    """
    If method is strict, we shouldn't be able to determine the file type by content.
    Thus, causing the format to be set as bin, and always failing the encryption check.
    """
    encrypted_file = encrypt_file("env")
    renamed_file = encrypted_file.parent / encrypted_file.name.replace(".env", ".foo")
    shutil.copy(encrypted_file, renamed_file)
    return_code = main([str(renamed_file), "--method", str(Methods.strict)])
    captured = capsys.readouterr()
    path, message = captured.err.split(" - ")
    assert return_code == 1
    assert path.endswith("enc.test.foo")
    expected_message = (
        "File format cannot be determined, here's the list of formats tried: "
        "['json', 'yaml']\n"
    )
    assert message == expected_message


def test_main_methods_bruteforce(encrypt_file):
    """
    If method is bruteforce, we should be able to determine the file type by content.
    Format should be determined correctly and the file should be processed accordingly.
    """
    encrypted_file = encrypt_file("env")
    renamed_file = encrypted_file.parent / encrypted_file.name.replace(".env", ".foo")
    shutil.copy(encrypted_file, renamed_file)
    return_code = main([str(renamed_file), "--method", str(Methods.bruteforce)])
    assert return_code == 0
