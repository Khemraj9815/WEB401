"""
Secure Web CLI
A small web application that lets a user run a FIXED, SAFE set of
diagnostic commands (ping, nslookup, whoami, date) through a browser,
with multiple safeguards against command injection.
"""

import ipaddress
import re
import subprocess
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# SAFEGUARD 1: Allowlist of commands.
# The user can ONLY run commands we explicitly approve. The browser sends a
# short keyword (e.g. "ping"), never a raw shell string. This maps the
# keyword to a real program path. Anything not in this dict is rejected.
# ---------------------------------------------------------------------------
ALLOWED_COMMANDS = {
    "ping":     ["ping", "-c", "2"],   # needs 1 host argument
    "nslookup": ["nslookup"],       # needs 1 host argument
    "whoami":   ["whoami"],          # takes no argument
    "date":     ["date"],                # takes no argument
}

# Commands that accept a single user-supplied argument (a hostname/IP)
COMMANDS_NEEDING_HOST = {"ping", "nslookup"}

# SAFEGUARD 2: Strict input validation (allowlist of characters).
# A valid hostname/IP contains only letters, digits, dots and hyphens.
# Shell metacharacters like ; | & $ ` > < are therefore impossible.
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9.\-]{1,253}$")


def is_valid_target(target: str) -> bool:
    """Accept the argument only if it is a clean hostname or IP address."""
    if not HOSTNAME_RE.match(target):
        return False
    # Extra check: if it looks like an IP, make sure it is actually valid.
    if re.match(r"^[0-9.]+$", target):
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return False
    return True


@app.route("/")
def index():
    return render_template("index.html", commands=list(ALLOWED_COMMANDS))


@app.route("/run", methods=["POST"])
def run():
    command = (request.form.get("command") or "").strip()
    target = (request.form.get("target") or "").strip()

    # SAFEGUARD 1 in action: reject anything not on the allowlist.
    if command not in ALLOWED_COMMANDS:
        return jsonify(ok=False, output="Error: command not allowed."), 400

    # Build the argument LIST (never a single string).
    args = list(ALLOWED_COMMANDS[command])

    if command in COMMANDS_NEEDING_HOST:
        if not is_valid_target(target):
            return jsonify(ok=False, output="Error: invalid host. Only letters, digits, dots and hyphens are allowed."), 400
        args.append(target)

    # ---------------------------------------------------------------------
    # SAFEGUARD 3: Run WITHOUT a shell.
    # subprocess.run(args, shell=False) passes each item as a separate
    # argument directly to the program. There is no shell to interpret
    # ; | & etc., so command injection cannot happen even if validation
    # were bypassed. We also set a timeout to prevent hanging.
    # ---------------------------------------------------------------------
    try:
        result = subprocess.run(
            args,
            shell=False,            # <-- the single most important line
            capture_output=True,
            text=True,
            timeout=8,
        )
        output = result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        output = "Error: command timed out."
    except Exception as e:
        output = f"Error: {e}"

    return jsonify(ok=True, output=output or "(no output)")


if __name__ == "__main__":
    # SAFEGUARD 4 (deployment): run as a low-privilege user, not root,
    # so that even a successful attack has limited power.
    app.run(host="127.0.0.1", port=5000, debug=False)   