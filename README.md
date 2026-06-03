# Shell GPT / CSecAI Kali Setup

Shell GPT is a Kali Linux terminal assistant powered by Groq. It can run shell commands, analyze command output, help with reconnaissance, scan targets you are authorized to test, and suggest a focused next action.

Use this tool only on systems you own or have explicit permission to assess.

## Requirements

- Kali Linux
- Python 3
- Internet access
- A Groq API key from `https://console.groq.com`

## Install On Kali

From the directory where you downloaded or cloned this project:

```bash
cd shell-gpt
```

Install system packages:

```bash
sudo apt update
```

```bash
sudo apt install -y python3 python3-venv python3-pip
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
```

```bash
source .venv/bin/activate
```

Install Python dependencies:

```bash
pip install requests rich
```

Make the script executable:

```bash
chmod +x shell-gpt.py
```

Run it:

```bash
./shell-gpt.py
```

## Set Up Groq API Keys

On first run, the tool opens a setup wizard. Paste your Groq API key when prompted.

Get a key here:

```text
https://console.groq.com
```

The tool stores keys locally in:

```text
~/.config/csec/config.json
```

You can add more keys later from inside the tool:

```text
config
```

Multiple keys are supported. The tool rotates between them when one is rate limited.

## Optional: Install As A Global Command

If you want to run the tool as `csec` from anywhere:

```bash
sudo cp shell-gpt.py /usr/local/bin/csec
```

```bash
sudo chmod +x /usr/local/bin/csec
```

Then start it with:

```bash
csec
```

If you installed dependencies inside a virtual environment, run it from the project directory with the venv activated, or install the dependencies system-wide/user-wide:

```bash
python3 -m pip install --user requests rich
```

## Basic Usage

Start interactive mode:

```bash
./shell-gpt.py
```

Run a command and ask the AI to analyze the output:

```text
run nmap -sV -sC 192.168.1.10
```

Run a shell command without AI analysis:

```text
shell whoami
```

Ask a direct question:

```text
ask explain this nmap result
```

Run a quick scan wizard:

```text
scan 192.168.1.10
```

Run domain reconnaissance:

```text
recon example.com
```

Analyze a local file:

```text
file /path/to/output.txt
```

Show help:

```text
help
```

Exit:

```text
exit
```

## Non-Interactive Examples

Run one command and analyze it:

```bash
./shell-gpt.py run "nmap -sV -sC 192.168.1.10"
```

Ask a one-off question:

```bash
./shell-gpt.py ask "What does port 445 usually indicate?"
```

Run a shell command directly:

```bash
./shell-gpt.py shell "ip addr"
```

## Configuration

Open the config menu:

```bash
./shell-gpt.py config
```

Configurable values include:

- Groq API keys
- Model name
- Temperature
- Max tokens
- Command timeout
- Auto-install missing tools

Default config path:

```text
~/.config/csec/config.json
```

Session files are stored in:

```text
~/.config/csec/sessions
```

## Troubleshooting

If dependencies are missing:

```bash
pip install requests rich
```

If the command is not executable:

```bash
chmod +x shell-gpt.py
```

If no API keys are configured:

```bash
./shell-gpt.py config
```

If Kali tools are missing, the assistant can suggest or run install commands when auto-install is enabled.

If Groq rate limits a key, add more keys in the config menu.
