import shutil

from ensure_sops import Methods, main


def test_main_unencrypted(tests_dir):
    """
    Unencrypted files should exit with return_code == 1
    """
    return_code = main([str(tests_dir / "files" / "test.json")])
    assert return_code == 1


def test_main_encrypted(encrypt_file):
    """
    Encrypted files should exit with return_code == 0
    """
    return_code = main([str(encrypt_file("json"))])
    assert return_code == 0


def test_main_methods_strict(encrypt_file):
    """
    If method is strict, we shouldn't be able to determine the file type by content.
    Thus, causing the format to be set as bin, and always failing the encryption check.
    """
    encrypted_file = encrypt_file("env")
    renamed_file = encrypted_file.parent / encrypted_file.name.replace(".env", ".foo")
    shutil.copy(encrypted_file, renamed_file)
    return_code = main([str(renamed_file), "--method", str(Methods.strict)])
    assert return_code == 1


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
