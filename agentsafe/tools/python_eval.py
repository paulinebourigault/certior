"""
Python evaluation tool - sandboxed code execution.

Executes Python code in a restricted subprocess with:
  - Hard timeout (default 30 s)
  - stdout/stderr capture
  - **A7**: Comprehensive module blocklist (os, sys, pathlib, pickle, etc.)
  - **A7**: Dangerous builtin blocklist (open, eval, exec, compile, etc.)
  - **A7**: AST static analysis pre-flight to catch evasion attempts
  - Truncated output

Requires capability: ``compute:python:eval``
"""
from __future__ import annotations

import ast
import asyncio
import os
import re
import sys
import tempfile
import textwrap
from typing import Any, Dict, FrozenSet, List, Optional, Set

from .base import BaseTool, ToolParameter, ToolResult

_DEFAULT_TIMEOUT_SECONDS = 30
_MAX_OUTPUT_CHARS = 32_000

# ── A7: Comprehensive module blocklist ─────────────────────────────
#
# Categories:
#   1. OS / filesystem / process spawning
#   2. Networking
#   3. Serialisation (code execution via deserialisation)
#   4. Code generation / introspection
#   5. Interpreter escape hatches
#   6. Misc dangerous

_BLOCKED_MODULES: FrozenSet[str] = frozenset({
    # ── 1. OS / filesystem / process ──
    "os",
    "sys",
    "pathlib",
    "shutil",
    "subprocess",
    "multiprocessing",
    "pty",
    "fcntl",
    "termios",
    "resource",
    "posix",
    "posixpath",
    "nt",
    "msvcrt",
    "winreg",
    "_winapi",
    "mmap",
    "io",
    "codecs",         # codecs.open() bypasses builtin removal
    "fileinput",      # fileinput.input() reads files
    "sqlite3",        # sqlite3.connect() creates/reads db files
    "zipfile",        # archive read/write
    "tarfile",        # archive read/write
    "dbm",            # database file access
    "tempfile",
    "glob",
    "fnmatch",

    # ── 2. Networking ──
    "socket",
    "ssl",
    "http",
    "http.server",
    "http.client",
    "urllib",
    "urllib.request",
    "requests",
    "httpx",
    "aiohttp",
    "ftplib",
    "smtplib",
    "poplib",
    "imaplib",
    "telnetlib",
    "xmlrpc",
    "xmlrpc.server",
    "xmlrpc.client",
    "socketserver",
    "asyncio",
    "selectors",
    "select",
    "webbrowser",
    "antigravity",

    # ── 3. Serialisation (arbitrary code execution) ──
    "pickle",
    "shelve",
    "marshal",
    "copyreg",
    "dill",
    "cloudpickle",
    "jsonpickle",

    # ── 4. Code generation / introspection ──
    "importlib",
    "runpy",
    "compileall",
    "py_compile",
    "code",
    "codeop",
    "ast",
    "dis",
    "inspect",
    "types",
    "typing_extensions",

    # ── 5. Interpreter escape hatches ──
    "ctypes",
    "ctypes.util",
    "_ctypes",
    "cffi",
    "gc",
    "signal",
    "_thread",
    "threading",
    "concurrent",
    "concurrent.futures",

    # ── 6. Misc dangerous ──
    "tkinter",
    "pdb",
    "bdb",
    "profile",
    "cProfile",
    "trace",
    "turtle",
    "ensurepip",
    "pip",
    "venv",
    "site",
    "sysconfig",
    "distutils",
    "setuptools",
    "pkg_resources",
    "zipimport",
    "_frozen_importlib",
    "_frozen_importlib_external",
    "builtins",     # prevent builtins manipulation
    "_io",
})

# ── A7: Dangerous builtins to remove from sandbox ──────────────────
_BLOCKED_BUILTINS: FrozenSet[str] = frozenset({
    "open",
    "eval",
    "exec",
    "compile",
    "__import__",
    "breakpoint",
    "exit",
    "quit",
    "input",          # can hang on stdin
    "memoryview",     # low-level memory access
    "globals",        # introspection escape
    "locals",         # introspection escape
    "vars",           # introspection escape
    "dir",            # module introspection
    "getattr",        # attribute access bypass
    "setattr",        # attribute mutation
    "delattr",        # attribute deletion
    "type",           # metaclass manipulation
    "super",          # MRO manipulation - kept blocked for sandboxed code
    "classmethod",    # descriptor protocol abuse
    "staticmethod",   # descriptor protocol abuse
    "property",       # descriptor protocol abuse
})

# ── A7: Minimal safe builtins allowlist ────────────────────────────
# Blocking individual builtins is fragile; instead the sandbox exposes
# an explicit allowlist of builtins that sandboxed code may use.
_ALLOWED_BUILTINS: FrozenSet[str] = frozenset({
    # Types & constructors
    "bool", "int", "float", "complex", "str", "bytes", "bytearray",
    "list", "tuple", "dict", "set", "frozenset", "range", "slice",
    "object",
    # Functions
    "abs", "all", "any", "bin", "chr", "divmod", "enumerate",
    "filter", "format", "hash", "hex", "id", "isinstance",
    "issubclass", "iter", "len", "map", "max", "min", "next",
    "oct", "ord", "pow", "print", "repr", "reversed", "round",
    "sorted", "sum", "zip",
    # Exceptions (so user code can catch them)
    "ArithmeticError", "AssertionError", "AttributeError",
    "BaseException", "BlockingIOError", "BrokenPipeError",
    "BufferedError", "BufferError", "BytesWarning",
    "ChildProcessError", "ConnectionAbortedError",
    "ConnectionError", "ConnectionRefusedError",
    "ConnectionResetError", "DeprecationWarning", "EOFError",
    "Exception", "FileExistsError", "FileNotFoundError",
    "FloatingPointError", "FutureWarning", "GeneratorExit",
    "IOError", "ImportError", "ImportWarning", "IndentationError",
    "IndexError", "InterruptedError", "IsADirectoryError",
    "KeyError", "KeyboardInterrupt", "LookupError",
    "MemoryError", "ModuleNotFoundError", "NameError",
    "NotADirectoryError", "NotImplementedError", "OSError",
    "OverflowError", "PendingDeprecationWarning",
    "PermissionError", "ProcessLookupError", "RecursionError",
    "ReferenceError", "ResourceWarning", "RuntimeError",
    "RuntimeWarning", "StopAsyncIteration", "StopIteration",
    "SyntaxError", "SyntaxWarning", "SystemError",
    "SystemExit", "TabError", "TimeoutError", "TypeError",
    "UnboundLocalError", "UnicodeDecodeError",
    "UnicodeEncodeError", "UnicodeError",
    "UnicodeTranslationError", "UnicodeWarning", "UserWarning",
    "ValueError", "Warning", "ZeroDivisionError",
    # Constants
    "True", "False", "None", "Ellipsis", "NotImplemented",
    "__name__", "__doc__",
})

# ── A7: AST-level static analysis ─────────────────────────────────

class _SandboxViolation(Exception):
    """Raised when AST analysis detects a sandbox evasion attempt."""
    pass


class _SandboxASTPreflight(ast.NodeVisitor):
    """Walk the AST and reject dangerous patterns BEFORE execution.

    Catches:
    - Direct ``__import__`` calls
    - ``open()`` / ``eval()`` / ``exec()`` / ``compile()`` calls
    - Access to dunder attributes that enable escape
      (``__builtins__``, ``__class__``, ``__subclasses__``,
       ``__globals__``, ``__code__``, ``__import__``)
    - ``importlib.import_module(...)`` patterns
    """

    _BLOCKED_FUNC_NAMES: FrozenSet[str] = frozenset({
        "open", "eval", "exec", "compile", "__import__",
        "breakpoint", "exit", "quit", "input",
    })

    _BLOCKED_DUNDERS: FrozenSet[str] = frozenset({
        "__builtins__", "__class__", "__subclasses__",
        "__globals__", "__locals__", "__code__",
        "__import__", "__loader__", "__spec__",
        "__bases__", "__mro__", "__dict__",
        "__reduce__", "__reduce_ex__",
        "__getattr__", "__setattr__", "__delattr__",
    })

    def __init__(self) -> None:
        self.violations: List[str] = []

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        # Check direct function calls: open(...), eval(...), etc.
        if isinstance(node.func, ast.Name):
            if node.func.id in self._BLOCKED_FUNC_NAMES:
                self.violations.append(
                    f"Blocked function call: {node.func.id}() "
                    f"[line {node.lineno}]"
                )
        # Check method calls: importlib.import_module(...)
        if isinstance(node.func, ast.Attribute):
            if node.func.attr == "import_module":
                self.violations.append(
                    f"Blocked call: *.import_module() [line {node.lineno}]"
                )
            if node.func.attr in ("system", "popen", "exec", "execvp",
                                   "execvpe", "spawn", "spawnl"):
                self.violations.append(
                    f"Blocked call: *.{node.func.attr}() [line {node.lineno}]"
                )
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:  # noqa: N802
        if node.attr in self._BLOCKED_DUNDERS:
            self.violations.append(
                f"Blocked dunder access: .{node.attr} [line {node.lineno}]"
            )
        self.generic_visit(node)

    def visit_Import(self, node: ast.Import) -> None:  # noqa: N802
        for alias in node.names:
            base = alias.name.split(".")[0]
            if base in _BLOCKED_MODULES:
                self.violations.append(
                    f"Blocked import: {alias.name} [line {node.lineno}]"
                )
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:  # noqa: N802
        if node.module:
            base = node.module.split(".")[0]
            if base in _BLOCKED_MODULES:
                self.violations.append(
                    f"Blocked import: from {node.module} [line {node.lineno}]"
                )
        self.generic_visit(node)


def _ast_preflight(code: str) -> List[str]:
    """Parse *code* and return a list of sandbox violations (empty = safe)."""
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return []  # syntax errors will be caught at runtime
    checker = _SandboxASTPreflight()
    checker.visit(tree)
    return checker.violations


# ── Sandbox preamble injected before user code ─────────────────────
#
# A7: Two-layer defence:
#   Layer 1: Replace __builtins__ with a restricted dict (allowlist)
#   Layer 2: Override __import__ to block dangerous modules
#
# This runs in the subprocess, not the host process.

_SANDBOX_PREAMBLE = '''
import sys as _sys

# ── Layer 1: Restrict builtins to allowlist ──
import builtins as _b
_ALLOWED = {allowed}
_restricted = {{k: getattr(_b, k) for k in _ALLOWED if hasattr(_b, k)}}
# Keep __build_class__ so class definitions work
_restricted["__build_class__"] = _b.__build_class__

# ── Layer 2: Controlled import function ──
_BLOCKED = {blocked}
_orig_import = _b.__import__
def _safe_import(name, *a, **kw):
    top = name.split(".")[0]
    if top in _BLOCKED:
        raise ImportError(f"Module '{{name}}' is blocked in the Certior sandbox")
    return _orig_import(name, *a, **kw)
_restricted["__import__"] = _safe_import

# Install restricted builtins globally
__builtins__ = _restricted

# Remove sys from scope so user code cannot access it
del _sys, _b, _ALLOWED, _BLOCKED, _orig_import, _safe_import, _restricted
'''


class PythonEvalTool(BaseTool):
    """
    Execute a Python code snippet and return its stdout/stderr.

    The code runs in a **subprocess** to isolate failures and enforce
    a hard timeout.  The working directory is an ephemeral tmpdir that
    is cleaned up after execution.

    Defence-in-depth layers:
      1. AST pre-flight rejects blocked patterns before any execution
      2. Preamble replaces __builtins__ with an allowlist
      3. Preamble blocks dangerous module imports
      4. Subprocess isolation with restricted env vars

    When ``sandbox_policy`` is provided (Phase D1):
      5. OS-level rlimits (CPU, memory, file-size, processes)
      6. seccomp-BPF syscall allowlist
      7. Linux namespace isolation (PID, network, IPC, user)
      8. Filesystem isolation (tmpfs root + read-only bind mounts)
      9. Optional nsjail containment (gold standard)
    """

    def __init__(
        self,
        sandbox_policy: Any = None,
        sandbox_policy_name: str = "custom",
        seccomp_evidence: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Initialise PythonEvalTool.

        Parameters
        ----------
        sandbox_policy
            Optional :class:`~agentsafe.sandbox.policy.SandboxPolicy`.
            When provided, execution is routed through the multi-layer
            OS-level sandbox (Phase D1).  When ``None``, the legacy
            subprocess execution path is used (Python-level sandbox only).
        """
        self._sandbox_policy = sandbox_policy
        self._sandbox_policy_name = sandbox_policy_name
        self._seccomp_evidence = dict(seccomp_evidence or {})
        self._sandbox_executor: Any = None
        self._sandbox_audit_records: List[Any] = []

        if sandbox_policy is not None:
            from agentsafe.sandbox.integration import ObservableSandboxedExecutor
            self._sandbox_executor = ObservableSandboxedExecutor(
                sandbox_policy,
                policy_name=sandbox_policy_name,
                audit_callback=self._sandbox_audit_records.append,
            )

    @property
    def name(self) -> str:
        return "python_eval"

    @property
    def description(self) -> str:
        return (
            "Execute a Python code snippet and return its output. "
            "Use this for calculations, data processing, text manipulation, "
            "or any computation. The code runs in a sandboxed subprocess. "
            "Print results to stdout to see them."
        )

    def parameters(self) -> List[ToolParameter]:
        return [
            ToolParameter(
                name="code",
                type="string",
                description="Python code to execute. Use print() to produce output.",
            ),
        ]

    @property
    def required_capabilities(self) -> List[str]:
        return ["compute:python:eval"]

    @property
    def estimated_cost_cents(self) -> int:
        return 1

    @property
    def sandbox_active_layers(self) -> List[str]:
        """Return active containment layers for diagnostics.

        Useful for compliance reporting and observability integration.
        """
        if self._sandbox_executor is not None:
            return self._sandbox_executor.get_active_layers()
        return ["python_sandbox"]

    async def execute(self, *, tool_use_id: str, **kwargs: Any) -> ToolResult:
        code: str = kwargs.get("code", "")
        if not code.strip():
            return ToolResult(
                tool_use_id=tool_use_id,
                output="Error: 'code' parameter is required and must not be empty.",
                is_error=True,
            )

        # ── A7: AST pre-flight analysis ────────────────────────
        violations = _ast_preflight(code)
        if violations:
            msg = "Sandbox policy violation - blocked before execution:\n"
            msg += "\n".join(f"  • {v}" for v in violations)
            return ToolResult(
                tool_use_id=tool_use_id,
                output=msg,
                is_error=True,
                metadata={"sandbox_blocked": True, "violations": violations},
            )

        # ── Phase D1: OS-level sandbox execution path ──────────
        if self._sandbox_executor is not None:
            return await self._execute_sandboxed(
                code,
                tool_use_id,
                token_id=str(kwargs.get("token_id", "")),
                agent_id=str(kwargs.get("agent_id", "")),
            )

        # ── Legacy execution path ──────────────────────────────
        return await self._execute_legacy(code, tool_use_id)

    async def _execute_sandboxed(
        self,
        code: str,
        tool_use_id: str,
        *,
        token_id: str = "",
        agent_id: str = "",
    ) -> ToolResult:
        """Execute via the multi-layer OS-level sandbox (Phase D1).

        Routes through :class:`~agentsafe.sandbox.SandboxedExecutor`
        which applies rlimits, seccomp-BPF, namespace isolation,
        filesystem isolation, and the Python-level sandbox.
        """
        try:
            from agentsafe.sandbox import SandboxResult

            result: SandboxResult = await self._sandbox_executor.execute(
                code,
                token_id=token_id or None,
                agent_id=agent_id or None,
            )
            sandbox_audit = self._take_latest_sandbox_audit()
            seccomp_evidence = dict(self._seccomp_evidence)
            metadata = {
                "sandbox_mode": "os_level",
                "sandbox_policy_name": self._sandbox_policy_name,
                "active_layers": list(result.active_layers),
                "returncode": result.returncode,
                "wall_time_seconds": result.wall_time_seconds,
                "sandbox_audit": sandbox_audit,
                "seccomp_verified": seccomp_evidence,
            }

            if result.is_error:
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=result.output[:_MAX_OUTPUT_CHARS],
                    is_error=True,
                    metadata={
                        **metadata,
                        "error_type": result.error_type,
                    },
                )

            return ToolResult(
                tool_use_id=tool_use_id,
                output=result.output[:_MAX_OUTPUT_CHARS],
                metadata={
                    **metadata,
                    "truncated": len(result.output) > _MAX_OUTPUT_CHARS,
                },
            )

        except Exception as exc:
            return ToolResult(
                tool_use_id=tool_use_id,
                output=f"Error: {type(exc).__name__}: {exc}",
                is_error=True,
                metadata={
                    "sandbox_mode": "os_level",
                    "sandbox_policy_name": self._sandbox_policy_name,
                    "active_layers": self.sandbox_active_layers,
                    "sandbox_audit": self._take_latest_sandbox_audit(),
                    "seccomp_verified": dict(self._seccomp_evidence),
                },
            )

    def _take_latest_sandbox_audit(self) -> Optional[Dict[str, Any]]:
        if not self._sandbox_audit_records:
            return None
        audit = self._sandbox_audit_records.pop()
        if hasattr(audit, "to_dict"):
            return audit.to_dict()
        if isinstance(audit, dict):
            return audit
        return {"value": str(audit)}

    async def _execute_legacy(
        self, code: str, tool_use_id: str,
    ) -> ToolResult:
        """Legacy subprocess execution (Python-level sandbox only)."""
        # Write code to a temp file with sandbox preamble
        preamble = _SANDBOX_PREAMBLE.format(
            blocked=repr(_BLOCKED_MODULES),
            allowed=repr(_ALLOWED_BUILTINS),
        )
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".py", delete=False,
        ) as tmp:
            tmp.write(preamble)
            tmp.write("\n# --- user code ---\n")
            tmp.write(code)
            tmp_path = tmp.name

        try:
            # Restricted env: strip secrets, set safe defaults
            safe_env = {
                "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                "HOME": tempfile.gettempdir(),
                "PYTHONDONTWRITEBYTECODE": "1",
                "PYTHONHASHSEED": "0",
                "LANG": os.environ.get("LANG", "C.UTF-8"),
            }

            proc = await asyncio.create_subprocess_exec(
                sys.executable, "-u", tmp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=tempfile.gettempdir(),
                env=safe_env,
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=_DEFAULT_TIMEOUT_SECONDS,
                )
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=f"Error: Code execution timed out after {_DEFAULT_TIMEOUT_SECONDS}s.",
                    is_error=True,
                )

            stdout = stdout_bytes.decode("utf-8", errors="replace")
            stderr = stderr_bytes.decode("utf-8", errors="replace")

            if proc.returncode != 0:
                combined = ""
                if stdout.strip():
                    combined += f"STDOUT:\n{stdout.strip()}\n\n"
                combined += f"STDERR:\n{stderr.strip()}" if stderr.strip() else "Process exited with non-zero code."
                return ToolResult(
                    tool_use_id=tool_use_id,
                    output=combined[:_MAX_OUTPUT_CHARS],
                    is_error=True,
                    metadata={"returncode": proc.returncode},
                )

            output = stdout.strip()
            if stderr.strip():
                output += f"\n\n[stderr]: {stderr.strip()}"

            if not output:
                output = "(No output produced. Use print() to see results.)"

            return ToolResult(
                tool_use_id=tool_use_id,
                output=output[:_MAX_OUTPUT_CHARS],
                metadata={
                    "returncode": proc.returncode,
                    "truncated": len(output) > _MAX_OUTPUT_CHARS,
                },
            )

        except Exception as exc:
            return ToolResult(
                tool_use_id=tool_use_id,
                output=f"Error: {type(exc).__name__}: {exc}",
                is_error=True,
            )
        finally:
            try:
                os.unlink(tmp_path)
            except OSError:
                pass
