![Last Commit](https://img.shields.io/github/last-commit/Mahamud-Dev/TLS-Parser)

# TLS-Parser

Parses `.pcapng` files and extracts metadata from TLS handshake packets using PyShark.

---

## 🔍 Overview

This project helps security analysts quickly extract useful TLS handshake metadata such as:

- TLS version
- Handshake type
- Cipher suite used
- Server Name Indication (SNI)

Useful for detecting anomalies in encrypted traffic or preparing for MITM detection workflows.

---

## 🧪 Features

- Works with `.pcapng` captures
- Filters only `tls` packets
- Outputs key handshake metadata to CSV
- Designed for Kali or Raspberry Pi 5 environments

---

## ⚙️ Setup

```bash
git clone git@github.com:Mahamud-Dev/TLS-Parser.git
cd TLS-Parser
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
