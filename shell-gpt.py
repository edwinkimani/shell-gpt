#!/usr/bin/env python3
"""
csec.py — AI-powered cybersecurity CLI assistant (Groq backend)
Kali Linux edition — Full toolset, no restrictions
FIXED: Real-time output streaming + Auto tool installation
"""

import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import time
import ipaddress
import threading
import queue
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
from rich import box
from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.live import Live
from rich.layout import Layout
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# ─────────────────────────────────────────────
#  CONFIG
# ─────────────────────────────────────────────

CONFIG_DIR   = Path.home() / ".config" / "csec"
CONFIG_FILE  = CONFIG_DIR / "config.json"
SESSIONS_DIR = CONFIG_DIR / "sessions"
STATE_FILE   = CONFIG_DIR / "api_state.json"

DEFAULT_CONFIG = {
    "model":       "llama-3.3-70b-versatile",
    "temperature": 0.2,
    "max_tokens":  4096,
    "api_keys":    [],
    "command_timeout": 1800,  # 30 minutes default for installations
    "auto_install_tools": True,  # NEW: Auto-detect and install missing tools
}

# Tool installation mappings (tool -> how to install on Kali)
TOOL_INSTALL_MAP = {
    # OSINT tools
    "sherlock": "cd /opt && sudo git clone https://github.com/sherlock-project/sherlock.git && cd sherlock && sudo pip3 install -r requirements.txt",
    "theharvester": "sudo apt install -y theharvester",
    "recon-ng": "sudo apt install -y recon-ng",
    "spiderfoot": "sudo apt install -y spiderfoot",
    "photonic": "sudo pip3 install photonic --user",
    "metagoofil": "sudo apt install -y metagoofil",
    
    # Web tools
    "gobuster": "sudo apt install -y gobuster",
    "ffuf": "sudo apt install -y ffuf",
    "nikto": "sudo apt install -y nikto",
    "sqlmap": "sudo apt install -y sqlmap",
    "wpscan": "sudo apt install -y wpscan",
    "nuclei": "sudo apt install -y nuclei",
    
    # Network tools
    "nmap": "sudo apt install -y nmap",
    "masscan": "sudo apt install -y masscan",
    "netcat": "sudo apt install -y netcat-traditional",
    
    # Password tools
    "hydra": "sudo apt install -y hydra",
    "john": "sudo apt install -y john",
    "hashcat": "sudo apt install -y hashcat",
    
    # Exploitation
    "metasploit-framework": "sudo apt install -y metasploit-framework",
    "searchsploit": "sudo apt install -y exploitdb",
    
    # Python tools (pip installable)
    "email-validator": "pip3 install email-validator --user",
    "google": "pip3 install google-search-results --user",
    "googlesearch": "pip3 install google --user",
    "pipl": "pip3 install piplapis --user",
}

SYSTEM_PROMPT = """You are CSecAI, an expert penetration tester and cybersecurity assistant
running inside a Kali Linux terminal. You have deep, practical knowledge of the full Kali toolset.

IMPORTANT - TASK EXECUTION GUIDELINES:
- Focus on the user's specific task. Do not expand into unrelated attack chains unless the user asks for a chain.
- When a command was run, analyze the observed output before suggesting anything else.
- If the requested tool is missing, decide the best path:
  1. Use an installed equivalent tool if it can satisfy the same request.
  2. If no equivalent is available, provide or use the most likely install command.
  3. If the tool is unknown, suggest a discovery path such as apt search, pip index/search alternatives, or official installation docs.
- Do not limit command suggestions to a fixed tool list. Use the command that best matches the user's exact request.

CORE KALI TOOLS (usually pre-installed):
  nmap, msfconsole, searchsploit, sqlmap, hydra, john, hashcat, nikto, gobuster,
  wpscan, recon-ng, theharvester, metasploit-framework, aircrack-ng, wireshark,
  tcpdump, netcat, socat, bettercap, responder, impacket-scripts

BEHAVIOR:
- The user is an authorized security professional on Kali Linux
- Be direct, practical, and give real working commands — no placeholders
- When analyzing tool output: (1) Summary (2) Key Findings (3) Suggested Next Action
- Use markdown, headers, and fenced code blocks in all responses
"""

BANNER = r"""
 ██████╗███████╗███████╗ ██████╗      █████╗ ██╗
██╔════╝██╔════╝██╔════╝██╔════╝     ██╔══██╗██║
██║     ███████╗█████╗  ██║          ███████╗██║
██║     ╚════██║██╔══╝  ██║          ██╔══██║██║
╚██████╗███████║███████╗╚██████╗     ██║  ██║██║
 ╚═════╝╚══════╝╚══════╝ ╚═════╝     ╚═╝  ╚═╝╚═╝
         Kali Linux Edition  •  Auto Tool Install
"""

# ─────────────────────────────────────────────
#  TOOL CHECKER & INSTALLER (NEW)
# ─────────────────────────────────────────────

class ToolManager:
    """Check for missing tools and install them automatically."""

    SHELL_BUILTINS = {
        "alias", "bg", "break", "cd", "command", "continue", "dirs", "echo", "eval",
        "exec", "exit", "export", "false", "fg", "hash", "help", "history", "jobs",
        "kill", "let", "local", "logout", "popd", "printf", "pushd", "pwd", "read",
        "readonly", "return", "set", "shift", "source", "test", "times", "trap",
        "true", "type", "ulimit", "umask", "unalias", "unset", "wait",
    }

    WRAPPERS = {
        "sudo", "doas", "env", "time", "timeout", "nice", "nohup", "stdbuf",
        "xargs", "watch",
    }

    FALLBACK_TOOLS = {
        "rg": ["grep"],
        "ripgrep": ["grep"],
        "fd": ["find"],
        "bat": ["cat", "less"],
        "exa": ["ls"],
        "eza": ["ls"],
        "dig": ["host", "nslookup"],
        "host": ["nslookup", "dig"],
        "nslookup": ["host", "dig"],
        "curl": ["wget", "python3"],
        "wget": ["curl", "python3"],
        "python": ["python3"],
        "pip": ["pip3", "python3"],
        "nc": ["netcat", "ncat"],
        "netcat": ["nc", "ncat"],
        "ncat": ["nc", "netcat"],
        "ip": ["ifconfig"],
        "ifconfig": ["ip"],
        "ss": ["netstat"],
        "netstat": ["ss"],
        "traceroute": ["tracepath"],
        "tracepath": ["traceroute"],
        "vim": ["vi", "nano"],
    }
    
    def __init__(self, auto_install: bool = True):
        self.auto_install = auto_install
        self.installed_tools = self._check_core_tools()
    
    def _check_core_tools(self) -> set:
        """Check which core Kali tools are already installed."""
        core_tools = ['nmap', 'msfconsole', 'searchsploit', 'sqlmap', 'hydra', 
                      'john', 'nikto', 'gobuster', 'wpscan', 'aircrack-ng']
        installed = set()
        for tool in core_tools:
            if self.check_tool_exists(tool):
                installed.add(tool)
        return installed
    
    def check_tool_exists(self, tool_name: str) -> bool:
        """Check if a tool is installed on the system."""
        if not tool_name:
            return False

        if tool_name in self.SHELL_BUILTINS:
            return True

        if '/' in tool_name:
            return Path(tool_name).exists() and os.access(tool_name, os.X_OK)

        return shutil.which(tool_name) is not None
    
    def get_install_command(self, tool_name: str) -> Optional[str]:
        """Get the installation command for a tool."""
        # Check mapping first
        tool_lower = tool_name.lower()
        if tool_lower in TOOL_INSTALL_MAP:
            return TOOL_INSTALL_MAP[tool_lower]
        
        # Check for common variations
        if tool_lower == 'theharvester':
            return "sudo apt install -y theharvester"
        elif tool_lower == 'metasploit':
            return "sudo apt install -y metasploit-framework"
        elif tool_lower == 'searchsploit':
            return "sudo apt install -y exploitdb"
        
        return None

    def find_alternative_tool(self, tool_name: str) -> Optional[str]:
        """Find an installed tool that can often satisfy the same request."""
        for candidate in self.FALLBACK_TOOLS.get(tool_name.lower(), []):
            if self.check_tool_exists(candidate):
                return candidate
        return None

    def missing_tool_plan(self, tool_name: str) -> str:
        """Return a concise plan when no direct installer is known."""
        return (
            f"No direct installer is known for '{tool_name}'.\n"
            f"Try one of these discovery commands, one at a time:\n"
            f"  sudo apt update\n"
            f"  apt-cache search {shlex.quote(tool_name)}\n"
            f"  python3 -m pip index versions {shlex.quote(tool_name)}"
        )
    
    def install_tool(self, tool_name: str) -> bool:
        """Attempt to install a missing tool."""
        install_cmd = self.get_install_command(tool_name)
        if not install_cmd:
            console.print(Panel(self.missing_tool_plan(tool_name), border_style="yellow", title="Missing Tool"))
            return False
        
        console.print(Panel(
            f"[yellow]⚠️ Tool '{tool_name}' not found[/yellow]\n\n"
            f"Installation command:\n[bold cyan]{install_cmd}[/bold cyan]\n\n"
            f"This may take a few minutes...",
            border_style="yellow",
            title="Missing Tool Detected"
        ))
        
        if not self.auto_install:
            if not Confirm.ask(f"Install {tool_name} now?", default=True):
                return False
        
        # Run installation with real-time output
        console.print(f"\n[cyan]📦 Installing {tool_name}...[/cyan]\n")
        
        # Split multi-command installations
        commands = install_cmd.split(' && ')
        for cmd in commands:
            if cmd.strip():
                console.rule(f"[dim]$ {cmd}[/dim]")
                result = subprocess.run(cmd, shell=True, executable="/bin/bash")
                if result.returncode != 0:
                    console.print(f"[red]Installation step failed: {cmd}[/red]")
                    return False
        
        # Verify installation
        if self.check_tool_exists(tool_name):
            console.print(f"[green]✓ {tool_name} installed successfully![/green]\n")
            return True
        else:
            console.print(f"[red]✗ {tool_name} installation failed or tool not in PATH[/red]")
            return False
    
    def ensure_tool(self, tool_name: str) -> bool:
        """Ensure a tool is installed, installing if necessary."""
        if self.check_tool_exists(tool_name):
            return True
        
        if self.install_tool(tool_name):
            return True
        
        return False


# ─────────────────────────────────────────────
#  API TRACKER
# ─────────────────────────────────────────────

class APITracker:
    def __init__(self):
        self.state: Dict = self._load()
        self.dead: set   = set()

    def _load(self) -> Dict:
        if STATE_FILE.exists():
            try:
                return json.loads(STATE_FILE.read_text())
            except Exception:
                pass
        return {}

    def _save(self):
        STATE_FILE.write_text(json.dumps(self.state, indent=2))

    def mark_dead(self, idx: int):
        self.dead.add(idx)

    def record_limit(self, idx: int, retry_after: float = 5.0):
        self.state[str(idx)] = {
            "available_at": time.time() + retry_after,
            "retry_after":  retry_after,
        }
        self._save()

    def record_success(self, idx: int):
        self.state.pop(str(idx), None)
        self._save()

    def wait_time(self, idx: int) -> float:
        if str(idx) not in self.state:
            return 0.0
        return max(0.0, self.state[str(idx)]["available_at"] - time.time())

    def best(self, n: int) -> Tuple[int, float]:
        times = [(i, self.wait_time(i)) for i in range(n) if i not in self.dead]
        if not times:
            return -1, float("inf")
        return sorted(times, key=lambda x: x[1])[0]


# ─────────────────────────────────────────────
#  GROQ CLIENT
# ─────────────────────────────────────────────

class GroqClient:
    def __init__(self, api_keys: List[str], model: str, temperature: float, max_tokens: int):
        self.api_keys    = api_keys
        self.model       = model
        self.temperature = temperature
        self.max_tokens  = max_tokens
        self.tracker     = APITracker()
        self.tool_manager = ToolManager()  # NEW

    def chat(self, messages: List[Dict]) -> Optional[str]:
        """Send chat messages to Groq API with automatic key rotation."""
        n = len(self.api_keys)
        if n == 0:
            console.print("[red]No API keys configured. Run: csec config[/red]")
            return None
            
        for attempt in range(n * 4):
            idx, wait = self.tracker.best(n)

            if idx == -1:
                console.print("[red]All API keys are invalid or dead. Run: csec config[/red]")
                return None

            if wait > 0:
                console.print(f"[yellow]Rate limited — waiting {wait:.1f}s for key {idx}...[/yellow]")
                time.sleep(wait + 0.3)

            try:
                response = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.api_keys[idx]}",
                        "Content-Type":  "application/json",
                    },
                    json={
                        "model":       self.model,
                        "messages":    messages,
                        "temperature": self.temperature,
                        "max_tokens":  self.max_tokens,
                    },
                    timeout=120,
                )

                if response.status_code == 200:
                    self.tracker.record_success(idx)
                    return response.json()["choices"][0]["message"]["content"]

                elif response.status_code == 429:
                    retry = 5.0
                    try:
                        error_data = response.json()
                        match = re.search(r"try again in ([0-9.]+)s", json.dumps(error_data))
                        if match:
                            retry = float(match.group(1))
                    except Exception:
                        pass
                    self.tracker.record_limit(idx, retry)
                    console.print(f"[yellow]Key {idx} rate limited — retry in {retry:.1f}s[/yellow]")

                elif response.status_code in (401, 403):
                    console.print(f"[red]Key {idx} invalid/unauthorized ({response.status_code}) — blacklisting.[/red]")
                    self.tracker.mark_dead(idx)
                else:
                    console.print(f"[red]API error {response.status_code} on key {idx}[/red]")

            except requests.exceptions.Timeout:
                console.print(f"[red]Key {idx} timed out.[/red]")
            except Exception as e:
                console.print(f"[red]Request error on key {idx}: {e}[/red]")

        console.print("[red]Maximum retries exceeded. Could not get a response from any API key.[/red]")
        return None


# ─────────────────────────────────────────────
#  REAL-TIME COMMAND EXECUTION WITH STREAMING
# ─────────────────────────────────────────────

class CommandExecutor:
    """Execute commands with real-time output streaming."""
    
    def __init__(self, timeout: int = 1800):
        self.timeout = timeout
        self.output_lines = []
        self.is_running = False
        
    def execute_streaming(self, command: str, show_live: bool = True) -> Tuple[str, str, int]:
        """
        Execute command with real-time output streaming.
        Returns (stdout, stderr, returncode)
        """
        self.output_lines = []
        self.is_running = True
        
        if show_live:
            console.rule(f"[bold cyan]$ {command}[/bold cyan]")
            console.print("[dim yellow]⏳ Running command (Ctrl+C to interrupt)...[/dim yellow]\n")
        
        process = None
        stdout_queue = queue.Queue()
        stderr_queue = queue.Queue()
        
        def read_output(stream, q, is_stderr=False):
            """Read output from stream and put in queue."""
            try:
                for line in iter(stream.readline, ''):
                    if line:
                        q.put((line, is_stderr))
                stream.close()
            except Exception:
                pass
        
        try:
            # Start process with pipes for real-time output
            process = subprocess.Popen(
                command,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True,
                executable="/bin/bash",
            )
            
            # Start threads to read output
            stdout_thread = threading.Thread(target=read_output, args=(process.stdout, stdout_queue, False))
            stderr_thread = threading.Thread(target=read_output, args=(process.stderr, stderr_queue, True))
            stdout_thread.daemon = True
            stderr_thread.daemon = True
            stdout_thread.start()
            stderr_thread.start()
            
            # Monitor process with timeout
            start_time = time.time()
            stdout_lines = []
            stderr_lines = []
            
            # Display output in real-time
            while True:
                # Check for timeout
                if time.time() - start_time > self.timeout:
                    if process:
                        process.terminate()
                        time.sleep(2)
                        if process.poll() is None:
                            process.kill()
                    self.is_running = False
                    console.print(f"\n[red]⚠ Command timed out after {self.timeout}s[/red]")
                    return (
                        '\n'.join(stdout_lines),
                        f"Command timed out after {self.timeout}s\n" + '\n'.join(stderr_lines),
                        -1
                    )
                
                # Check if process finished
                if process.poll() is not None:
                    # Get remaining output
                    time.sleep(0.1)  # Allow threads to finish
                    break
                
                # Get new output
                try:
                    while True:
                        line, is_stderr = stdout_queue.get_nowait()
                        if is_stderr:
                            stderr_lines.append(line)
                            if show_live:
                                console.print(f"[red]{line.rstrip()}[/red]")
                        else:
                            stdout_lines.append(line)
                            if show_live:
                                console.print(f"{line.rstrip()}")
                except queue.Empty:
                    pass
                
                time.sleep(0.1)
            
            # Collect any remaining output
            while True:
                try:
                    line, is_stderr = stdout_queue.get_nowait()
                    if is_stderr:
                        stderr_lines.append(line)
                    else:
                        stdout_lines.append(line)
                except queue.Empty:
                    break
            
            returncode = process.poll()
            self.is_running = False
            
            if show_live:
                console.print()  # New line after output
                if returncode != 0:
                    console.print(f"[dim]Command exited with code: {returncode}[/dim]")
            
            return '\n'.join(stdout_lines), '\n'.join(stderr_lines), returncode if returncode is not None else 0
            
        except KeyboardInterrupt:
            if process:
                console.print("\n[yellow]⚠ Interrupted by user - terminating process...[/yellow]")
                process.terminate()
                time.sleep(2)
                if process.poll() is None:
                    process.kill()
            return '\n'.join(stdout_lines), "Command interrupted by user", -1
        except Exception as e:
            return '', str(e), -1
        finally:
            self.is_running = False


# ─────────────────────────────────────────────
#  TOOL RUNNER FUNCTIONS WITH AUTO-INSTALL (UPDATED)
# ─────────────────────────────────────────────

def extract_tool_from_command(command: str) -> Optional[str]:
    """Extract the executable that will handle a shell command."""
    command = command.strip()
    if not command:
        return None

    try:
        parts = shlex.split(command)
    except ValueError:
        parts = command.split()

    if not parts:
        return None

    wrappers = ToolManager.WRAPPERS
    i = 0
    while i < len(parts):
        token = parts[i]
        if "=" in token and not token.startswith("-") and token.split("=", 1)[0].isidentifier():
            i += 1
            continue
        if token in ("bash", "sh", "zsh") and i + 2 < len(parts) and parts[i + 1] in ("-c", "-lc"):
            return extract_tool_from_command(parts[i + 2])
        if token in wrappers:
            i += 1
            while i < len(parts) and parts[i].startswith("-"):
                i += 1
                if token == "timeout" and i < len(parts) and re.match(r"^\d+[smhd]?$", parts[i]):
                    i += 1
            continue
        return Path(token).name

    return None

def replace_command_tool(command: str, old_tool: str, new_tool: str) -> str:
    """Replace the command executable while preserving the rest of the user's command."""
    pattern = re.compile(rf"(^|\s)({re.escape(old_tool)})(?=\s|$)")
    return pattern.sub(lambda m: f"{m.group(1)}{new_tool}", command, count=1)

def run_tool_with_check(command: str, tool_manager: ToolManager, timeout: int = 1800, show_live: bool = True, auto_install: bool = True) -> Tuple[str, str, int]:
    """Run a command, automatically installing missing tools if needed."""
    tool = extract_tool_from_command(command)
    used_alternative = False
    
    # If we can identify a tool and it's not installed
    if tool and not tool_manager.check_tool_exists(tool):
        console.print(f"[yellow]⚠️ Tool '{tool}' not found[/yellow]")

        alternative = tool_manager.find_alternative_tool(tool)
        if alternative:
            fallback_command = replace_command_tool(command, tool, alternative)
            console.print(Panel(
                f"Installed alternative found: [cyan]{alternative}[/cyan]\n\n"
                f"Fallback command:\n[bold cyan]{fallback_command}[/bold cyan]",
                border_style="cyan",
                title="Tool Decision"
            ))
            if Confirm.ask("Use this alternative now?", default=True):
                command = fallback_command
                tool = alternative
                used_alternative = True

        if auto_install and not used_alternative:
            install_cmd = tool_manager.get_install_command(tool)
            if install_cmd:
                console.print(Panel(
                    f"Suggested installation:\n[cyan]{install_cmd}[/cyan]\n\n"
                    f"Would you like to install '{tool}' now?",
                    border_style="yellow",
                    title="Missing Tool"
                ))
                if Confirm.ask("Install now?", default=True):
                    if tool_manager.install_tool(tool):
                        console.print(f"[green]✓ {tool} installed, running your command...[/green]\n")
                    else:
                        console.print(f"[red]Failed to install {tool}. Running anyway may fail.[/red]")
                else:
                    console.print("[dim]Skipping installation, command may fail[/dim]")
            else:
                console.print(Panel(
                    tool_manager.missing_tool_plan(tool),
                    border_style="yellow",
                    title="Suggested Way Forward"
                ))
                if not Confirm.ask("Run original command anyway?", default=False):
                    return "", f"Tool '{tool}' is missing and no installed alternative was selected.", 127
    
    # Execute the command
    executor = CommandExecutor(timeout=timeout)
    return executor.execute_streaming(command, show_live=show_live)

def run_and_analyze(command: str, client: GroqClient, history: List[Dict], analyze: bool = True, show_live: bool = True):
    """Run a command with real-time output, auto-install missing tools, and send to AI."""
    
    # Warn about long-running commands
    if any(keyword in command.lower() for keyword in ['install', 'apt-get', 'apt ', 'upgrade', 'full-upgrade', 'apt update']):
        console.print("[yellow]⚠️  This appears to be an installation command which may take several minutes.[/yellow]")
        console.print("[dim]You can see the installation progress in real-time below.[/dim]\n")
        if not Confirm.ask("Continue with installation?", default=True):
            console.print("[yellow]Command cancelled.[/yellow]")
            return
    
    # Execute with auto-install check
    timeout = cfg.get("command_timeout", 1800)
    stdout, stderr, code = run_tool_with_check(command, client.tool_manager, timeout=timeout, show_live=show_live, auto_install=cfg.get("auto_install_tools", True))
    
    # Build combined output for analysis
    output_parts = []
    if stdout.strip():
        output_parts.append(stdout)
    if stderr.strip():
        output_parts.append(f"[STDERR]\n{stderr}")
    combined = "\n".join(output_parts) if output_parts else ""
    
    # Show summary
    if combined and not show_live:
        console.print(f"\n[dim]Command completed with exit code: {code}[/dim]")
        if len(combined) > 8000:
            console.print(f"[dim]Output size: {len(combined):,} chars (truncated for display)[/dim]")
        else:
            console.print(f"[dim]Output size: {len(combined):,} chars[/dim]")
    
    if not analyze or not combined.strip():
        return
    
    # Send to AI for analysis
    truncated = combined[:5000] + ("\n... [truncated]" if len(combined) > 5000 else "")
    
    # Provide context to AI about what happened
    if code == -1 and "timed out" in stderr:
        context = "\n\nNOTE: This command timed out. The operation may still be running or may have failed."
    elif code == 127:
        context = "\n\nNOTE: This command failed with 'command not found' (exit code 127). The tool may need to be installed."
    else:
        context = ""
    
    msg = (
        f"I ran this command on Kali Linux:\n```bash\n{command}\n```\n"
        f"Exit code: {code}\n\nOutput:\n```\n{truncated}\n```{context}\n\n"
        "Please analyze this output thoroughly. Provide a short summary, key findings, and one suggested next action."
        "If the command failed (exit code 127), explain whether an alternative tool, installation, or discovery command is the best next move."
    )
    history.append({"role": "user", "content": msg})
    
    with console.status("[cyan]🤖 AI analyzing output...[/cyan]"):
        reply = client.chat([{"role": "system", "content": SYSTEM_PROMPT}] + history)
    
    if reply:
        history.append({"role": "assistant", "content": reply})
        console.print(Panel(Markdown(reply), border_style="green", title="[green]📊 AI Analysis[/green]"))


# ─────────────────────────────────────────────
#  CONFIG MANAGEMENT
# ─────────────────────────────────────────────

def load_config() -> Dict:
    """Load configuration from file or return defaults."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    if CONFIG_FILE.exists():
        try:
            cfg = json.loads(CONFIG_FILE.read_text())
            # Add new default keys if missing
            if "auto_install_tools" not in cfg:
                cfg["auto_install_tools"] = True
            return cfg
        except (json.JSONDecodeError, OSError):
            console.print("[yellow]Config file corrupted, using defaults[/yellow]")
    return DEFAULT_CONFIG.copy()

def save_config(cfg: Dict):
    """Save configuration to file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(cfg, indent=2))

def setup_wizard() -> Dict:
    """First-time setup wizard for API keys."""
    console.print(Panel(
        "[bold cyan]CSecAI — First-time setup[/bold cyan]\n\n"
        "Get a free Groq API key at [bold]https://console.groq.com[/bold]\n"
        "Add multiple keys for automatic rotation when rate-limited.\n\n"
        "[dim]Note: Keys are stored locally in ~/.config/csec/config.json[/dim]",
        border_style="cyan",
    ))
    cfg = load_config()
    keys = list(cfg.get("api_keys", []))
    
    console.print("[bold]Enter your Groq API keys:[/bold]")
    while True:
        key = Prompt.ask("API key (blank to finish)", default="", password=True)
        if not key.strip():
            break
        keys.append(key.strip())
        console.print(f"[green]  ✓ Added key #{len(keys)}: {key[:10]}...[/green]")
    
    if keys:
        cfg["api_keys"] = keys
    else:
        console.print("[yellow]No keys added. You can add them later with 'config' command.[/yellow]")
    
    cfg["model"] = Prompt.ask("Model", default=cfg.get("model", "llama-3.3-70b-versatile"))
    cfg["auto_install_tools"] = Confirm.ask("Auto-install missing tools?", default=True)
    save_config(cfg)
    console.print("[green]✓ Configuration saved successfully![/green]\n")
    return cfg

def config_menu():
    """Interactive configuration menu."""
    cfg = load_config()
    t = Table(title="Current Configuration", box=box.SIMPLE, border_style="yellow")
    t.add_column("Setting", style="cyan")
    t.add_column("Value")
    t.add_row("Model",       cfg.get("model", "—"))
    t.add_row("API Keys",    f"{len(cfg.get('api_keys', []))} loaded")
    t.add_row("Temperature", str(cfg.get("temperature", 0.2)))
    t.add_row("Max Tokens",  str(cfg.get("max_tokens", 4096)))
    t.add_row("Command Timeout",  str(cfg.get("command_timeout", 1800)) + "s")
    t.add_row("Auto Install Tools",  "✓ Enabled" if cfg.get("auto_install_tools", True) else "✗ Disabled")
    console.print(t)

    actions = ["add-key", "clear-keys", "model", "temperature", "max-tokens", "timeout", "auto-install", "done"]
    action = Prompt.ask("Action", choices=actions, default="done")
    
    if action == "add-key":
        key = Prompt.ask("New API key", password=True)
        if key.strip():
            cfg.setdefault("api_keys", []).append(key.strip())
            save_config(cfg)
            console.print(f"[green]✓ Key added. Total: {len(cfg['api_keys'])}[/green]")
    elif action == "clear-keys":
        if Confirm.ask("Clear all API keys?", default=False):
            cfg["api_keys"] = []
            save_config(cfg)
            console.print("[yellow]All keys cleared.[/yellow]")
    elif action == "model":
        cfg["model"] = Prompt.ask("Model name", default=cfg.get("model", "llama-3.3-70b-versatile"))
        save_config(cfg)
    elif action == "temperature":
        try:
            temp = float(Prompt.ask("Temperature (0.0–1.0)", default=str(cfg.get("temperature", 0.2))))
            cfg["temperature"] = max(0.0, min(1.0, temp))
            save_config(cfg)
        except ValueError:
            console.print("[red]Invalid temperature value.[/red]")
    elif action == "max-tokens":
        try:
            tokens = int(Prompt.ask("Max tokens (1-8192)", default=str(cfg.get("max_tokens", 4096))))
            cfg["max_tokens"] = max(1, min(8192, tokens))
            save_config(cfg)
        except ValueError:
            console.print("[red]Invalid token count.[/red]")
    elif action == "timeout":
        try:
            timeout = int(Prompt.ask("Command timeout in seconds (300-7200)", default=str(cfg.get("command_timeout", 1800))))
            cfg["command_timeout"] = max(300, min(7200, timeout))
            save_config(cfg)
            console.print(f"[green]Timeout set to {cfg['command_timeout']} seconds[/green]")
        except ValueError:
            console.print("[red]Invalid timeout value.[/red]")
    elif action == "auto-install":
        cfg["auto_install_tools"] = Confirm.ask("Auto-install missing tools?", default=cfg.get("auto_install_tools", True))
        save_config(cfg)
        console.print(f"[green]Auto-install {'enabled' if cfg['auto_install_tools'] else 'disabled'}[/green]")


# ─────────────────────────────────────────────
#  COMMAND EXTRACTION & SUGGESTION (UPDATED)
# ─────────────────────────────────────────────

def extract_commands(text: str) -> List[str]:
    """Extract shell commands from assistant text using fenced blocks and heuristic matching."""
    commands: List[str] = []
    
    # Extract from code blocks
    code_blocks = re.findall(r"```([A-Za-z0-9_-]*)\s*\n(.*?)```", text, re.DOTALL)
    command_fence_languages = {"", "bash", "sh", "zsh", "shell", "command", "console", "terminal"}
    for language, block in code_blocks:
        if language.lower() not in command_fence_languages:
            continue
        for line in block.splitlines():
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            line = re.sub(r'^[\$\#]\s*', '', line)
            if line and looks_like_shell_command(line):
                commands.append(line)
    
    # If no code blocks, try heuristic matching
    if not commands:
        text_without_fences = re.sub(r"```.*?```", "", text, flags=re.DOTALL)
        for line in text_without_fences.splitlines():
            line = line.strip()
            if not line or line.startswith(('#', '`', '//')):
                continue
            line = re.sub(r'^[\$\#]\s*', '', line)
            if looks_like_shell_command(line):
                commands.append(line)
    
    # Remove duplicates
    seen = set()
    unique_commands = []
    for cmd in commands:
        if cmd not in seen:
            seen.add(cmd)
            unique_commands.append(cmd)
    
    return unique_commands[:5]  # Limit to 5 suggested commands

def looks_like_shell_command(line: str) -> bool:
    """Return True for command-shaped one-liners without relying on a fixed tool list."""
    if not line or len(line) > 500:
        return False
    if line.lower().startswith(("summary", "key findings", "next steps", "suggested next action")):
        return False
    if any(marker in line for marker in [";", "&&", "||"]):
        # Keep suggested commands focused on one action unless the user explicitly uses run/shell.
        return False
    try:
        parts = shlex.split(line)
    except ValueError:
        return False
    if not parts:
        return False
    tool = extract_tool_from_command(line)
    if not tool:
        return False
    if re.match(r"^[A-Za-z0-9_./@+-]+$", parts[0]) is None:
        return False
    if len(parts) == 1 and re.match(r"^(?:[a-z0-9-]+\.)+[a-z]{2,}$", parts[0], re.IGNORECASE):
        return False
    prose_words = {"the", "when", "after", "before", "first", "then", "next", "use", "run"}
    return parts[0].lower() not in prose_words

def run_suggested_commands(commands: List[str], client: GroqClient, history: List[Dict]):
    """Execute extracted commands one by one and analyze output."""
    if not commands:
        return
    
    console.print(Panel(
        f"[cyan]Found {len(commands)} suggested command(s)[/cyan]\n" +
        "\n".join(f"[dim]{i+1}. {cmd}[/dim]" for i, cmd in enumerate(commands)),
        border_style="yellow",
        title="[yellow]Suggested Commands[/yellow]",
    ))
    
    first_command = commands[0]
    if Confirm.ask(f"Execute the most relevant command: [bold]{first_command}[/bold]", default=False):
        run_and_analyze(first_command, client, history, analyze=True, show_live=True)
    else:
        console.print(f"[dim]No command executed. Suggested next action: review or run `{first_command}` manually.[/dim]")


# ─────────────────────────────────────────────
#  SESSIONS & REPORTS
# ─────────────────────────────────────────────

def save_session(name: str, history: List[Dict], notes: str = ""):
    """Save current session to disk."""
    SESSIONS_DIR.mkdir(parents=True, exist_ok=True)
    safe_name = re.sub(r'[^\w\-]', '_', name)
    path = SESSIONS_DIR / f"{safe_name}.json"
    data = {
        "name": name,
        "created": datetime.now().isoformat(),
        "notes": notes,
        "history": history,
    }
    path.write_text(json.dumps(data, indent=2))
    console.print(f"[green]✓ Session saved → {path}[/green]")

def load_session(name: str) -> List[Dict]:
    """Load a saved session."""
    path = SESSIONS_DIR / f"{name}.json"
    if not path.exists():
        console.print(f"[red]Session '{name}' not found.[/red]")
        return []
    data = json.loads(path.read_text())
    console.print(f"[green]✓ Loaded '{data['name']}' — {len(data['history'])} messages[/green]")
    return data["history"]

def list_sessions():
    """List all saved sessions."""
    sessions = list(SESSIONS_DIR.glob("*.json"))
    if not sessions:
        console.print("[yellow]No saved sessions found.[/yellow]")
        return
    t = Table(title="Saved Sessions", box=box.SIMPLE_HEAD)
    t.add_column("Name", style="cyan")
    t.add_column("Created", style="dim")
    t.add_column("Messages")
    for s in sorted(sessions, key=lambda x: x.stat().st_mtime, reverse=True):
        try:
            d = json.loads(s.read_text())
            t.add_row(d.get("name", s.stem), d.get("created", "Unknown")[:19], str(len(d.get("history", []))))
        except:
            t.add_row(s.stem, "Corrupted", "?")
    console.print(t)

def export_report(history: List[Dict], filename: str):
    """Export session as a markdown penetration test report."""
    if not history:
        console.print("[yellow]No history to export.[/yellow]")
        return
    if not filename.endswith('.md'):
        filename += '.md'
    lines = ["# CSecAI Penetration Test Report\n", f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n---\n\n"]
    for i, msg in enumerate(history, 1):
        role = msg["role"]
        content = msg["content"]
        if role == "user":
            lines.append(f"### [{i}] Command\n\n```\n{content[:2000]}\n```\n\n")
        elif role == "assistant":
            lines.append(f"### [{i}] Analysis\n\n{content}\n\n---\n\n")
    Path(filename).write_text("\n".join(lines))
    console.print(f"[green]✓ Report exported → {filename}[/green]")


# ─────────────────────────────────────────────
#  QUICK MODES
# ─────────────────────────────────────────────

def quick_scan(target: str, client: GroqClient, history: List[Dict]):
    """Quick nmap scan wizard."""
    console.print(f"\n[cyan]🎯 Target: {target}[/cyan]")
    scan_type = Prompt.ask(
        "Scan type",
        choices=["quick", "full", "stealth", "vuln", "udp", "all-ports"],
        default="quick",
    )
    cmds = {
        "quick":     f"nmap -sV -sC -T4 --open {target}",
        "full":      f"nmap -sV -sC -O -A -T4 {target}",
        "stealth":   f"nmap -sS -sV -T2 -f {target}",
        "vuln":      f"nmap -sV --script vuln {target}",
        "udp":       f"nmap -sU -sV --top-ports 200 {target}",
        "all-ports": f"nmap -sV -sC -p- -T4 {target}",
    }
    run_and_analyze(cmds[scan_type], client, history, show_live=True)

def quick_recon(domain: str, client: GroqClient, history: List[Dict]):
    """Quick reconnaissance suite."""
    console.print(f"\n[cyan]🔍 Recon target: {domain}[/cyan]")
    cmds = [
        f"whois {domain}",
        f"dig {domain} ANY +noall +answer",
        f"host {domain}",
    ]
    for cmd in cmds:
        if Confirm.ask(f"  Run: {cmd}", default=True):
            run_and_analyze(cmd, client, history, show_live=True)
        else:
            console.print(f"  [dim]Skipped[/dim]")

def analyze_file(filepath: str, client: GroqClient, history: List[Dict]):
    """Analyze a file content."""
    p = Path(filepath)
    if not p.exists():
        console.print(f"[red]File not found: {filepath}[/red]")
        return
    try:
        content = p.read_text(errors="replace")[:5000]
    except:
        content = str(p.read_bytes())[:1000]
    console.print(f"[cyan]📄 File: {filepath}[/cyan]")
    context = Prompt.ask("What should I look for? (optional)", default="")
    msg = f"Analyze this file: `{filepath}`\n{f'Focus on: {context}\n' if context else ''}\n```\n{content}\n```"
    history.append({"role": "user", "content": msg})
    with console.status("[cyan]🤖 Analyzing file...[/cyan]"):
        reply = client.chat([{"role": "system", "content": SYSTEM_PROMPT}] + history)
    if reply:
        history.append({"role": "assistant", "content": reply})
        console.print(Panel(Markdown(reply), border_style="green", title="[green]📊 File Analysis[/green]"))


# ─────────────────────────────────────────────
#  HELP & MAIN
# ─────────────────────────────────────────────

def show_help():
    """Display help menu."""
    t = Table(title="[bold cyan]CSecAI — Kali Linux Edition (Auto Tool Install)[/bold cyan]", box=box.SIMPLE_HEAD, border_style="cyan")
    t.add_column("Command", style="cyan bold", min_width=26)
    t.add_column("Description", style="dim")
    rows = [
        ("── 🛠️ TOOL EXECUTION ──", ""),
        ("run <command>", "Run ANY Kali tool → auto-install if missing → AI analysis"),
        ("exec <command>", "Alias for run"),
        ("shell <command>", "Run a command live (interactive, no AI)"),
        ("scan <target>", "nmap scan wizard with real-time progress"),
        ("recon <domain>", "OSINT/DNS recon suite"),
        ("file <path>", "Analyze any log, scan output, or file"),
        ("", ""),
        ("── 🤖 AI ASSISTANCE ──", ""),
        ("ask <question>", "Ask the AI directly (maintains conversation context)"),
        ("ctf", "CTF challenge helper"),
        ("script <description>", "Generate + optionally save a security script"),
        ("chain <goal>", "Full attack chain planner"),
        ("", ""),
        ("── 💾 SESSION & REPORTS ──", ""),
        ("save <name>", "Save current session to disk"),
        ("load <name>", "Load a previous session"),
        ("sessions", "List all saved sessions"),
        ("report <file.md>", "Export session as a markdown pentest report"),
        ("clear", "Clear current session history"),
        ("", ""),
        ("── ⚙️ SETTINGS ──", ""),
        ("config", "Manage API keys, model, auto-install, timeout"),
        ("keys", "Show live API key status"),
        ("help", "Show this help"),
        ("exit / quit", "Exit CSecAI"),
    ]
    for cmd, desc in rows:
        if cmd.startswith("──"):
            t.add_row(f"[dim]{cmd}[/dim]", f"[dim]{desc}[/dim]")
        else:
            t.add_row(cmd, desc)
    console.print(t)

def show_key_status(cfg: Dict, client: GroqClient):
    """Display API key status."""
    t = Table(title="API Key Status", box=box.SIMPLE)
    t.add_column("Key #", style="cyan", justify="right")
    t.add_column("Prefix", style="dim")
    t.add_column("Status")
    t.add_column("Wait Time")
    for i, key in enumerate(cfg.get("api_keys", [])):
        prefix = key[:14] + "..." if len(key) > 14 else key
        if i in client.tracker.dead:
            status, wait = "[red]✗ Dead[/red]", "—"
        else:
            w = client.tracker.wait_time(i)
            status = "[green]✓ Ready[/green]" if w <= 0 else "[yellow]⏳ Limited[/yellow]"
            wait = "Now" if w <= 0 else f"{w:.1f}s"
        t.add_row(str(i), prefix, status, wait)
    console.print(t)

def ctf_mode(client: GroqClient, history: List[Dict]):
    """CTF challenge helper mode."""
    console.print(Panel("[bold cyan]🎯 CTF Mode[/bold cyan]\nDescribe your challenge.", border_style="magenta"))
    desc = Prompt.ask("Challenge description")
    msg = f"CTF Challenge: {desc}\nGuide me through the methodology step by step."
    history.append({"role": "user", "content": msg})
    with console.status("[cyan]🧠 Thinking...[/cyan]"):
        reply = client.chat([{"role": "system", "content": SYSTEM_PROMPT}] + history)
    if reply:
        history.append({"role": "assistant", "content": reply})
        console.print(Panel(Markdown(reply), border_style="magenta", title="[magenta]🎯 CTF Guidance[/magenta]"))

def generate_script(description: str, client: GroqClient, history: List[Dict]):
    """Generate a security script."""
    msg = f"Write a security script for Kali Linux:\n{description}\nInclude shebang, comments, and usage."
    history.append({"role": "user", "content": msg})
    with console.status("[cyan]✍️ Generating script...[/cyan]"):
        reply = client.chat([{"role": "system", "content": SYSTEM_PROMPT}] + history)
    if reply:
        history.append({"role": "assistant", "content": reply})
        console.print(Panel(Markdown(reply), border_style="blue", title="[blue]📝 Generated Script[/blue]"))

def attack_chain(goal: str, client: GroqClient, history: List[Dict]):
    """Plan an attack chain."""
    msg = f"Plan a complete attack chain for: {goal}\nInclude recon, enum, exploit, post-exploit steps with commands."
    history.append({"role": "user", "content": msg})
    with console.status("[cyan]⚔️ Planning...[/cyan]"):
        reply = client.chat([{"role": "system", "content": SYSTEM_PROMPT}] + history)
    if reply:
        history.append({"role": "assistant", "content": reply})
        console.print(Panel(Markdown(reply), border_style="red", title="[red]⚔️ Attack Chain[/red]"))

def shell_passthrough(command: str):
    """Run a command live/interactively."""
    console.rule(f"[bold cyan]$ {command}[/bold cyan]")
    try:
        subprocess.run(command, shell=True, executable="/bin/bash")
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")

def get_current_network_range() -> Optional[str]:
    """Return the current IPv4 network range."""
    result = subprocess.run("ip -o -4 addr show scope global", shell=True, capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if " lo " in line:
            continue
        parts = line.strip().split()
        for i, part in enumerate(parts):
            if part == 'inet' and i + 1 < len(parts):
                try:
                    return str(ipaddress.ip_network(parts[i + 1], strict=False))
                except:
                    pass
    return None

def infer_command_from_request(raw: str) -> Optional[Tuple[str, str]]:
    """Infer a shell command from natural language."""
    crt_match = re.search(r"\bcrt\.sh\b.*?\b([a-z0-9.-]+\.[a-z]{2,})\b", raw.lower())
    if crt_match:
        domain = crt_match.group(1).strip(".")
        script = textwrap.dedent(f"""
            import json, re, sys, urllib.parse, urllib.request
            domain = {domain!r}
            url = "https://crt.sh/?" + urllib.parse.urlencode({{"q": "%." + domain, "output": "json"}})
            try:
                data = json.loads(urllib.request.urlopen(url, timeout=120).read().decode("utf-8", "replace"))
            except Exception as exc:
                print(f"crt.sh lookup failed: {{exc}}", file=sys.stderr)
                sys.exit(1)
            names = set()
            for item in data:
                for name in str(item.get("name_value", "")).splitlines():
                    name = name.strip().lower().lstrip("*.").rstrip(".")
                    if name == domain or name.endswith("." + domain):
                        names.add(name)
            for name in sorted(names):
                print(name)
        """).strip()
        command = "python3 -c " + shlex.quote(script)
        return command, f"crt.sh subdomain lookup for {domain}"

    if "network scan" in raw.lower():
        network = get_current_network_range()
        if network:
            return f"nmap -sS -T4 --open {network}", network
    return None

def maybe_execute_natural_language(raw: str, client: GroqClient, history: List[Dict]) -> bool:
    """Try to interpret free-form request as a command."""
    result = infer_command_from_request(raw)
    if not result:
        return False
    command, label = result
    console.print(Panel(f"Detected task: {label}\nCommand: {command}", border_style="cyan"))
    if Confirm.ask("Proceed?", default=True):
        run_and_analyze(command, client, history, analyze=True, show_live=True)
    return True

def decide_single_action(raw: str, client: GroqClient, history: List[Dict]) -> bool:
    """Let the AI decide whether a free-form request needs one command or a direct answer."""
    decision_prompt = (
        "Decide how to handle this user request in a Kali Linux terminal assistant.\n"
        "If it should run a command, output exactly:\n"
        "ACTION: COMMAND\nCOMMAND: <one shell command>\nREASON: <short reason>\n\n"
        "If it should only be answered in text, output exactly:\n"
        "ACTION: ANSWER\nANSWER: <short helpful answer>\n\n"
        "Rules:\n"
        "- Use one command only.\n"
        "- Do not use command chains with &&, ||, or semicolons. A simple pipeline is allowed when it is the right single action.\n"
        "- Match the user's specific request.\n"
        "- If the user asks to use a named public lookup source like crt.sh, choose a command that actually queries that source.\n"
        "- Do not invent or assume command output.\n"
        "- If a tool may be missing, still choose the best command; the local tool manager will decide fallback/install.\n\n"
        f"User request: {raw}"
    )

    reply = client.chat([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": decision_prompt},
    ])
    if not reply:
        return False

    action = ""
    selected_command = ""
    answer_lines = []
    for line in reply.splitlines():
        if line.startswith("ACTION:"):
            action = line.replace("ACTION:", "", 1).strip().upper()
        elif line.startswith("COMMAND:"):
            selected_command = line.replace("COMMAND:", "", 1).strip()
        elif line.startswith("ANSWER:"):
            answer_lines.append(line.replace("ANSWER:", "", 1).strip())
        elif answer_lines:
            answer_lines.append(line.strip())

    if action == "COMMAND" and selected_command and looks_like_shell_command(selected_command):
        console.print(Panel(
            f"Task: {raw}\nCommand decision: [bold cyan]{selected_command}[/bold cyan]",
            border_style="cyan",
            title="AI Decision"
        ))
        if Confirm.ask("Run this command?", default=True):
            run_and_analyze(selected_command, client, history, analyze=True, show_live=True)
        return True

    if action == "ANSWER":
        answer = "\n".join(answer_lines).strip() or reply
        history.append({"role": "user", "content": raw})
        history.append({"role": "assistant", "content": answer})
        console.print(Panel(Markdown(answer), border_style="green", title="[green]🤖 CSecAI[/green]"))
        return True

    return False


# ─────────────────────────────────────────────
#  MAIN LOOP
# ─────────────────────────────────────────────

def main():
    """Main entry point."""
    global cfg
    cfg = load_config()

    if not cfg.get("api_keys"):
        cfg = setup_wizard()
        if not cfg.get("api_keys"):
            console.print("[red]No API keys configured. Exiting.[/red]")
            sys.exit(1)

    client = GroqClient(
        api_keys=cfg["api_keys"],
        model=cfg.get("model", "llama-3.3-70b-versatile"),
        temperature=cfg.get("temperature", 0.2),
        max_tokens=cfg.get("max_tokens", 4096),
    )
    history: List[Dict] = []

    console.print(Text(BANNER, style="bold cyan"))
    console.print(Panel(
        f"[bold]Model:[/bold] {cfg['model']}   "
        f"[bold]Keys:[/bold] {len(cfg['api_keys'])} active   "
        f"[bold]Timeout:[/bold] {cfg.get('command_timeout', 1800)}s   "
        f"[bold]Auto-Install:[/bold] {'✓' if cfg.get('auto_install_tools', True) else '✗'}\n"
        f"[dim]Type [cyan]help[/cyan] for commands  •  Auto tool detection & installation[/dim]",
        border_style="cyan",
    ))
    console.print("[yellow]⚠️  Legal Warning: Use only on authorized systems.[/yellow]\n")

    # Non-interactive mode
    if len(sys.argv) > 1 and sys.argv[1] != "config":
        cli_cmd = sys.argv[1].lower()
        raw = " ".join(sys.argv[2:]) if cli_cmd in ("run", "exec", "shell", "ask") else " ".join(sys.argv[1:])
        if cli_cmd in ("run", "exec") and raw:
            run_and_analyze(raw, client, history, analyze=True, show_live=True)
        elif cli_cmd == "shell" and raw:
            shell_passthrough(raw)
        else:
            history.append({"role": "user", "content": raw})
            with console.status("[cyan]🤖 Thinking...[/cyan]"):
                reply = client.chat([{"role": "system", "content": SYSTEM_PROMPT}] + history)
            if reply:
                console.print(Markdown(reply))
                cmds = extract_commands(reply)
                if cmds:
                    run_suggested_commands(cmds, client, history)
        return
    
    if len(sys.argv) > 1 and sys.argv[1] == "config":
        config_menu()
        return

    # Interactive loop
    while True:
        try:
            raw = Prompt.ask("\n[bold cyan]csec[/bold cyan]").strip()
        except (KeyboardInterrupt, EOFError):
            console.print("\n[cyan]Goodbye![/cyan]")
            break

        if not raw:
            continue

        parts = raw.split(None, 1)
        cmd = parts[0].lower()
        arg = parts[1].strip() if len(parts) > 1 else ""

        if cmd in ("exit", "quit", "q"):
            if history and Confirm.ask("Save session?", default=False):
                name = Prompt.ask("Session name", default=f"session_{datetime.now().strftime('%Y%m%d_%H%M')}")
                save_session(name, history, "")
            break
        elif cmd == "help":
            show_help()
        elif cmd == "clear":
            if Confirm.ask("Clear history?", default=False):
                history.clear()
                console.print("[green]Cleared.[/green]")
        elif cmd == "config":
            config_menu()
            cfg = load_config()
            client = GroqClient(cfg["api_keys"], cfg.get("model", "llama-3.3-70b-versatile"), cfg.get("temperature", 0.2), cfg.get("max_tokens", 4096))
            # Update tool manager auto-install setting
            client.tool_manager.auto_install = cfg.get("auto_install_tools", True)
        elif cmd == "keys":
            show_key_status(cfg, client)
        elif cmd == "sessions":
            list_sessions()
        elif cmd == "save":
            name = arg or f"session_{datetime.now().strftime('%Y%m%d_%H%M')}"
            save_session(name, history, "")
        elif cmd == "load":
            name = arg or Prompt.ask("Session name")
            if name:
                loaded = load_session(name)
                if loaded:
                    history = loaded
        elif cmd == "report":
            fname = arg or f"csec_report_{datetime.now().strftime('%Y%m%d_%H%M')}.md"
            export_report(history, fname)
        elif cmd in ("run", "exec"):
            command = arg or Prompt.ask("Command to run")
            if command:
                run_and_analyze(command, client, history, analyze=True, show_live=True)
        elif cmd == "shell":
            command = arg or Prompt.ask("Command")
            if command:
                shell_passthrough(command)
        elif cmd == "scan":
            target = arg or Prompt.ask("Target")
            if target:
                quick_scan(target, client, history)
        elif cmd == "recon":
            domain = arg or Prompt.ask("Domain")
            if domain:
                quick_recon(domain, client, history)
        elif cmd == "file":
            path = arg or Prompt.ask("File path")
            if path:
                analyze_file(path, client, history)
        elif cmd == "ctf":
            ctf_mode(client, history)
        elif cmd == "script":
            desc = arg or Prompt.ask("Script description")
            if desc:
                generate_script(desc, client, history)
        elif cmd == "chain":
            goal = arg or Prompt.ask("Goal")
            if goal:
                attack_chain(goal, client, history)
        elif cmd == "ask":
            question = arg or Prompt.ask("Question")
            if question:
                history.append({"role": "user", "content": question})
                with console.status("[cyan]🤖 Thinking...[/cyan]"):
                    reply = client.chat([{"role": "system", "content": SYSTEM_PROMPT}] + history)
                if reply:
                    history.append({"role": "assistant", "content": reply})
                    console.print(Panel(Markdown(reply), border_style="green", title="[green]🤖 CSecAI[/green]"))
                    cmds = extract_commands(reply)
                    if cmds:
                        run_suggested_commands(cmds, client, history)
        else:
            if maybe_execute_natural_language(raw, client, history):
                continue
            with console.status("[cyan]🤖 Deciding the best single action...[/cyan]"):
                if decide_single_action(raw, client, history):
                    continue
            history.append({"role": "user", "content": raw})
            with console.status("[cyan]🤖 Thinking...[/cyan]"):
                reply = client.chat([{"role": "system", "content": SYSTEM_PROMPT}] + history)
            if reply:
                history.append({"role": "assistant", "content": reply})
                console.print(Panel(Markdown(reply), border_style="green", title="[green]🤖 CSecAI[/green]"))
                cmds = extract_commands(reply)
                if cmds:
                    run_suggested_commands(cmds, client, history)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Fatal error: {e}[/red]")
        sys.exit(1)
