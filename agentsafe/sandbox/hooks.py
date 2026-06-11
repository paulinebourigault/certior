import sys
import os
import contextvars
from contextlib import contextmanager
from typing import Optional, List, Dict, Any

from .token_manager import verify_and_decode_token

# Store the currently active capability token for the execution thread/context.
_current_agent_token = contextvars.ContextVar('certior_capability_token', default=None)

class CertiorSecurityError(Exception):
    """Raised when an agent attempts an action that its capability token does not permit."""
    pass

def _certior_audit_hook(event: str, args: tuple):
    """
    Python runtime audit hook (PEP 578).

    Intercepts low-level execution calls (socket, fs, exec) and enforces
    the current Certior capability boundaries.
    """
    token_str = _current_agent_token.get()
    
    # If no token is set, we bypass (assuming this is main framework logic).
    # In a strict environment, default-deny can be enforced.
    if token_str is None:
        return

    # Verify cryptographic signature of the token from the Glass Box
    try:
        payload = verify_and_decode_token(token_str)
    except ValueError as e:
        raise CertiorSecurityError(f"[Certior Sandbox] Invalid Capability Token: {e}")

    permissions = payload.get("permissions", [])
    agent_id = payload.get("agent_id", "unknown")

    # Hook: Network Egress
    if event == "socket.connect":
        if "network_send" not in permissions and "admin:network_all" not in permissions:
            host, port = args[0] if len(args) > 0 and isinstance(args[0], tuple) else ("unknown", 0)
            raise CertiorSecurityError(f"[Certior Sandbox] INTERCEPTED: Agent {agent_id} attempted network_send to {host}:{port} without capability.")
            
    # Hook: Process Execution
    if event in ("subprocess.Popen", "os.system", "os.execv", "os.spawnv"):
        if "system_execute" not in permissions:
            cmd = args[0] if len(args) > 0 else "unknown"
            raise CertiorSecurityError(f"[Certior Sandbox] INTERCEPTED: Agent {agent_id} attempted to execute system command '{cmd}' without system_execute capability.")

    # Hook: File System Writes
    if event == "open" and len(args) >= 2:
        path, mode = args[0], args[1]
        mode_str = str(mode)
        is_write = 'w' in mode_str or 'a' in mode_str or '+' in mode_str
        if is_write and "write_fs" not in permissions:
            raise CertiorSecurityError(f"[Certior Sandbox] INTERCEPTED: Agent {agent_id} attempted to write to {path} without write_fs capability.")

    # Hook: Arbitrary URL requests standard library
    if event == "urllib.Request":
        if "network_send" not in permissions:
             raise CertiorSecurityError(f"[Certior Sandbox] INTERCEPTED: Agent {agent_id} attempted urllib Request without network_send capability.")

def enable_sandbox():
    """
    Registers the cryptographic interception audit hook.
    This should be called as early as possible during the application boot. 
    It cannot be unregistered (by design in Python).
    """
    try:
        sys.addaudithook(_certior_audit_hook)
    except Exception as e:
        # sys.addaudithook might throw if called multiple times or restricted
        pass

@contextmanager
def sandbox_context(signed_token: str):
    """
    A context manager to wrap the execution of a multi-agent step.
    Sets the cryptographically signed token into the execution context.
    The interceptor will validate this token on any system call.
    """
    token_var = _current_agent_token.set(signed_token)
    try:
        yield
    finally:
        _current_agent_token.reset(token_var)
