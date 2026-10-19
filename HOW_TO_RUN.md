# How to run

## Requirements

- Python 3.10 or newer
- No third-party packages (standard library only)

## Install

From the repo root:

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e .
```

## Get the headers

- **Outlook (desktop):** open the message, File > Properties, copy "Internet headers," or drag the message to a folder to save it as `.msg` and export as `.eml`.
- **Gmail:** open the message, three-dot menu > "Show original," then "Download original" to get a `.eml`.
- **Thunderbird:** File > Save As > File to save as `.eml`.

A plain text file containing only the pasted headers also works.

## Usage

```bash
# JSON report to stdout
phishing-header-analyzer message.eml

# Markdown report to stdout
phishing-header-analyzer message.eml --format md

# Write the report to a file
phishing-header-analyzer message.eml --format md --out report.md
```

## Run the tests

```bash
python -m unittest discover -s tests -v
```
