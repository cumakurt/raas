# Contributing

Thank you for your interest in RAAS.

## Development setup

```bash
git clone https://github.com/cumakurt/raas.git
cd raas
python3 -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements-dev.txt
```

Copy `config/config.yaml.example` to `config/config.yaml` and adjust paths or disable outbound features while testing.

## Tests

```bash
python -m pytest
```

(`requirements-dev.txt` includes `requirements.txt` plus `pytest`.)

Pull requests should pass CI (see `.github/workflows/ci.yml`).

## Style

- Keep user-facing documentation changes consistent between `README.md` and `README.tr.md` when both apply.
- Application code and comments: English.

## Pull requests

- Describe the change and why it is needed.
- Reference related issues when applicable.

## License

By contributing, you agree that your contributions are licensed under the same license as the project (GPL-3.0-or-later, see `LICENSE`).
