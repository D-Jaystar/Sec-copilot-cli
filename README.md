# 🛡 sec-copilot-cli

**Defensive AI Sparring Partner & Static Code/Log Auditor**

An interactive CLI tool that leverages Google Gemini to perform OWASP-aligned code audits, security log analysis, and guided defensive sparring sessions for cybersecurity learners and professionals.

Built for educational labs (TryHackMe, HackTheBox, PicoCTF) and real-world code review workflows.

---

## ✨ Features

| Feature | Description |
|---|---|
| **`audit`** | Static security review of source files mapped to OWASP Top-10 2021 |
| **`log`**   | Security event log analysis for IOCs, anomalies, and attack timelines |
| **`chat`**  | Interactive defensive sparring partner with Socratic mentoring |
| **Tuned SafetySettings** | Custom Gemini safety thresholds prevent false-positive blocks on legitimate defensive content |
| **Rich Terminal UI** | Syntax-highlighted code, colour-coded severity panels, and structured report cards |

---

## 🏗 Architecture

```
sec-copilot-cli/
├── src/
│   ├── __init__.py       # Package root & version
│   ├── cli.py            # argparse entry point — subcommand routing
│   ├── client.py         # Gemini API wrapper with SafetySettings
│   ├── prompts.py        # Modular system instructions (OWASP, sparring, log)
│   └── formatter.py      # Rich output: panels, tables, syntax blocks
├── .env.example          # API key template
├── .gitignore
├── requirements.txt
└── README.md
```

**Design Principles:**
- **Separation of Concerns** — API transport, prompt engineering, rendering, and CLI routing live in isolated modules.
- **Guard Clauses / Early Returns** — Every function validates inputs at the top; no deep nesting.
- **Registry Pattern** — Prompts are registered by mode key, making new personas a one-liner addition.

---

## 🚀 Quickstart

### 1. Clone & Install

```bash
git clone https://github.com/<your-username>/sec-copilot-cli.git
cd sec-copilot-cli
python -m venv venv
# Windows
venv\Scripts\activate
# macOS / Linux
source venv/bin/activate
pip install -r requirements.txt
```

### 2. Configure API Key

```bash
cp .env.example .env
# Edit .env and paste your Gemini API key
```

Get a key at [Google AI Studio](https://aistudio.google.com/apikey).

### 3. Run

```bash
# Static code audit
python -m src.cli audit path/to/vulnerable_app.py

# Log analysis
python -m src.cli log path/to/auth.log

# Interactive sparring session
python -m src.cli chat
```

---

## 🔐 SafetySettings Rationale

The Gemini API applies content safety filters by default. For legitimate defensive security analysis, discussions of vulnerabilities, attack patterns, and exploit techniques can trigger false-positive blocks.

This tool configures `HARM_CATEGORY_DANGEROUS_CONTENT` to `BLOCK_NONE` while keeping other categories at `BLOCK_ONLY_HIGH`, ensuring:
- ✅ Vulnerability descriptions and remediation advice flow freely
- ✅ Attack-pattern explanations for educational purposes are not blocked
- ✅ Harassment, hate speech, and explicit content remain filtered

---

## 🛠 Development

```bash
# Verify imports resolve cleanly
python -c "from src.cli import main; print('✅ All imports OK')"
```

---

## 📄 License

MIT — see [LICENSE](LICENSE) for details.

---

> Built with 🐍 Python, 🤖 Google Gemini, and 🎨 Rich.
