from __future__ import annotations

import ast
from pathlib import Path

SENSOR_DIR = Path(__file__).resolve().parents[1] / "src" / "aegis_nexus" / "sensors"
PROTOCOL_MODULES = (
    "ssh_decoy.py",
    "web_decoy.py",
    "legacy.py",
    "smtp_decoy.py",
    "redis_decoy.py",
    "mysql_decoy.py",
    "smb_decoy.py",
    "generic_tcp.py",
)
BANNED_IMPORTS = {"subprocess", "pty", "pickle", "marshal"}
BANNED_CALLS = {
    "eval",
    "exec",
    "compile",
    "os.system",
    "os.popen",
    "subprocess.run",
    "subprocess.call",
    "subprocess.Popen",
    "subprocess.check_call",
    "subprocess.check_output",
    "pty.spawn",
    "pickle.loads",
    "marshal.loads",
}


def _call_name(node: ast.Call) -> str:
    target = node.func
    if isinstance(target, ast.Name):
        return target.id
    parts: list[str] = []
    while isinstance(target, ast.Attribute):
        parts.append(target.attr)
        target = target.value
    if isinstance(target, ast.Name):
        parts.append(target.id)
    return ".".join(reversed(parts))


def test_protocol_decoys_do_not_import_or_call_execution_primitives():
    violations: list[str] = []
    for filename in PROTOCOL_MODULES:
        path = SENSOR_DIR / filename
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.split(".", 1)[0] in BANNED_IMPORTS:
                        violations.append(f"{filename}:{node.lineno}: import {alias.name}")
            elif isinstance(node, ast.ImportFrom):
                module = (node.module or "").split(".", 1)[0]
                if module in BANNED_IMPORTS:
                    violations.append(f"{filename}:{node.lineno}: from {node.module} import ...")
            elif isinstance(node, ast.Call):
                name = _call_name(node)
                if name in BANNED_CALLS:
                    violations.append(f"{filename}:{node.lineno}: {name}()")
                if name.startswith("subprocess."):
                    violations.append(f"{filename}:{node.lineno}: {name}()")
    assert violations == []
