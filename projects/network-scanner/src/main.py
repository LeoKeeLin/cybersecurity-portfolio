"""Default non-transmitting planning; live scanning requires --execute."""

import argparse
import hashlib
import json
import os
from pathlib import Path, PureWindowsPath
import sys
import tempfile

from scope import ScopeError, load_scope, validate_response_grace


TOOL_VERSION = "0.3.0"
DEFAULT_OUTPUT_DIR = Path("evidence")
# Relative to the process working directory, not the location of main.py.
# In workbench, running from / makes this the supplied /evidence mount.


def output_path(value):
    """Resolve a relative filename/subpath within the local evidence directory."""
    path = Path(value)
    # An output argument is a path *within* evidence, never an arbitrary host
    # path. Check Windows-style paths too, even when running on Linux/macOS.
    if (not value or not path.name or value.endswith(("/", "\\"))
            or path.is_absolute() or PureWindowsPath(value).drive
            or "\\" in value or ".." in path.parts):
        raise ScopeError("Output must be a relative file path inside evidence/; no absolute paths or '..'")
    if DEFAULT_OUTPUT_DIR.is_symlink():
        raise ScopeError("The evidence directory must not be a symbolic link")
    try:
        root = DEFAULT_OUTPUT_DIR.resolve()
        destination = root / path
        resolved = destination.resolve()
    except RuntimeError as error:
        raise ScopeError("Output contains a symbolic-link loop") from error
    # Resolving follows existing symlinks: a harmless-looking subfolder could
    # otherwise redirect the write outside evidence. This is not a race-proof
    # sandbox against another process changing links after the check.
    if resolved == root or root not in resolved.parents:
        raise ScopeError("Output must not escape evidence/ through symbolic links")
    return destination


def build_plan(scope, response_grace=None):
    """Describe effective settings without constructing or sending probes."""
    return {
        "mode": "dry-run",
        "tool_version": TOOL_VERSION,
        "scope_id": scope["scope_id"],
        "option": scope["option"],
        "environment": scope["environment"],
        "parameters": {
            "target": scope["target"],
            "ports": sorted(scope["ports"]),
            "interface": scope["interface"],
            "rate_pps": scope["maximum_rate_pps"],
            "attempts": scope["maximum_attempts"],
            "timeout_seconds": scope["timeout_seconds"],
            "response_grace_seconds": response_grace,
        },
        "notice": "Plan only. No packets sent; no scan observations collected.",
    }


def main(argv=None):
    # argv=None reads the terminal arguments; a supplied list lets tests call
    # this entry point directly without launching another Python process.
    parser = argparse.ArgumentParser(
        description="Plan a bounded TCP SYN scan, or explicitly execute it in the authorised lab."
    )
    parser.add_argument("--scope", required=True, type=Path, help="Scope JSON file")
    parser.add_argument(
        "--output",
        help="Save JSON beneath evidence/ (e.g. rehearsal/result.json); required for execution",
    )
    parser.add_argument("--execute", action="store_true", help="Send probes in the authorised lab")
    parser.add_argument(
        "--response-grace", type=float,
        help="Optional seconds to observe after a matched TCP verdict (e.g. 0.1); default is full timeout",
    )
    parser.add_argument("--version", action="version", version=TOOL_VERSION)
    args = parser.parse_args(argv)
    if args.execute and args.output is None:
        parser.error("--execute requires --output")

    temporary = None
    try:
        scope = load_scope(args.scope)
        validate_response_grace(args.response_grace, scope["timeout_seconds"])
        destination = output_path(args.output) if args.output is not None else None
        if args.output is not None:
            # resolve catches pathname/symlink aliases; samefile also catches
            # hard links (different names that refer to the same physical file).
            same_path = args.scope.resolve() == destination.resolve()
            same_file = destination.exists() and args.scope.samefile(destination)
            if same_path or same_file:
                raise ScopeError("Output must not replace the scope file")
        if args.execute:
            # Practice plans may be replaced, but each live measurement needs
            # a fresh path so rerunning cannot silently destroy old evidence.
            if destination.exists():
                raise ScopeError("Live result output already exists; choose a new filename")
            destination.parent.mkdir(parents=True, exist_ok=True)
            # Check output access before sending and write successful results
            # atomically. Failed runs do not leave a misleading result file.
            with tempfile.NamedTemporaryFile(
                mode="w", dir=destination.parent, prefix=".scan-", delete=False,
                encoding="utf-8",
            ) as stream:
                temporary = Path(stream.name)
            # Import only in live mode: dry-run needs no Scapy or raw sockets.
            from scanner import run_scan
            scope_hash = hashlib.sha256(args.scope.read_bytes()).hexdigest()
            result = run_scan(scope, TOOL_VERSION, response_grace=args.response_grace)
            result["scope_sha256"] = scope_hash
            result["command"] = [sys.executable, sys.argv[0]] + (
                list(argv) if argv is not None else sys.argv[1:]
            )
        else:
            result = build_plan(scope, args.response_grace)
        serialized = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
        # Stable ordering makes fixed test inputs reproducible. Actual run
        # timestamps and randomly chosen probe IDs will naturally differ.
        if args.output is not None:
            destination.parent.mkdir(parents=True, exist_ok=True)
            if temporary is not None:
                temporary.write_text(serialized, encoding="utf-8")
                # The temporary file is in the destination directory, allowing
                # a same-filesystem rename to publish the complete JSON at once.
                os.replace(temporary, destination)
            else:
                destination.write_text(serialized, encoding="utf-8")
    except (ScopeError, OSError, ValueError, RuntimeError, ImportError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("Execution interrupted; no complete result saved", file=sys.stderr)
        return 130
    finally:
        # Also runs after errors, returns and Ctrl+C; avoid abandoned temp files.
        if temporary is not None and temporary.exists():
            temporary.unlink()

    print(serialized, end="")
    if args.output is not None:
        label = "Result" if args.execute else "Plan"
        print(f"{label} saved to {destination}")
    return 0


if __name__ == "__main__":
    # Run the CLI only when this file is executed, not when imported by tests.
    sys.exit(main())
