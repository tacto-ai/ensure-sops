# `ensure_sops`

## Summary
This is a pre-commit compatible application that validates your SOPS encrypted files are indeed encrypted. It works with json, yaml, ini and dotenv formatted files that are products of SOPS' encryption. Main use case is preventing mistakes like committing files that should've been encrypted, unencrypted.

## History
`ensure_sops` is influenced by [pre-commit-hook-ensure-sops](https://github.com/yuvipanda/pre-commit-hook-ensure-sops). We tried to extend that package but the way it was written didn't provided all the features we needed, thus we created a new package with extensibility in mind.

## Features
- Compatibility with all SOPS' output formats
- Compatibility with null/empty values
- Can determine file format by extension, or content.
- Automatically find all json, yaml, ini and dotenv files that start or end with `enc` or `secret` (or `secrets`)

## Installation
Pre-commit can handle installation automatically, you can skip this part if you're going to use pre-commit. Otherwise, you can any use any python package manager to install.

Here's some examples:
```shell
$ pip install ensure_sops
$ pipx install ensure_sops
$ poetry add --dev ensure_sops
$ pipenv install --dev ensure_sops
$ pdm add --dev test ensure_sops
```

## Use with pre-commit
You can add this to your pre-commit configuration for the most basic use. The commented lines can be used to improve file selection.

```yaml
  - repo: https://github.com/Tacto-Technology/ensure-sops
    rev: 0.1.0
    hooks:
      - id: ensure-sops
        # files: 'enc\..+'
        # type: 'json'
        # exclude: 'decrypted/.+'
```

## Use with other tools
After installing the package, you can call the `ensure_sops` script with a list of files.

```shell
$ ensure_sops .example.env
$ ensure_sops */secrets/*
$ ensure_sops --method=bruteforce output_file
```

## License
[BSD 3-Clause](LICENSE)
