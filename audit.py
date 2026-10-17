#!/usr/bin/env python3
import json
import os
import pathlib
import re
import subprocess
import sys
import tempfile

MACHO_MAGICS = {
    b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
}
PATTERNS = {
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
    "github_token": re.compile(r"gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,}"),
    "live_key": re.compile(r"sk_live_[A-Za-z0-9]{16,}"),
    "absolute_path": re.compile(r"/(?:Users|Volumes)/[^\s\x00]{2,}"),
    "debug_path": re.compile(r"/(?:private/tmp|tmp|var/folders)/[^\s\x00]{2,}"),
    "url": re.compile(r"https?://[^\s\x00]{6,}"),
}
SENSITIVE_ENV = re.compile(r"(?:^|_)(?:TOKEN|SECRET|PASSWORD|PRIVATE_KEY|API_KEY)(?:_|$)", re.I)

def sanitized_env():
    return {key: value for key, value in os.environ.items() if not SENSITIVE_ENV.search(key)}

def run_capture(argv, timeout=15, max_output_bytes=8 * 1024 * 1024):
    env = sanitized_env()
    try:
        with tempfile.TemporaryFile() as output:
            result = subprocess.run(
                argv,
                stdout=output,
                stderr=subprocess.DEVNULL,
                env=env,
                check=False,
                timeout=timeout,
            )
            if result.returncode != 0:
                return result.returncode, b""
            output.seek(0, os.SEEK_END)
            size = output.tell()
            if size > max_output_bytes:
                return 126, b""
            output.seek(0)
            return 0, output.read(max_output_bytes)
    except (OSError, subprocess.SubprocessError):
        return 127, b""

def is_macho(path):
    try:
        with path.open("rb") as f:
            return f.read(4) in MACHO_MAGICS
    except OSError:
        return False

def image_paths(app):
    paths = []
    for path in app.rglob("*"):
        if path.is_file() and is_macho(path):
            paths.append(path)
    return sorted(paths, key=lambda p: (0 if p.name == app.stem else 1, -p.stat().st_size))

def image_audit(path, root):
    rel = path.relative_to(root).as_posix()
    public = {
        "size_bytes": path.stat().st_size,
        "swift_section_count": 0,
        "objc_metadata_section_count": 0,
        "debug_section_count": 0,
        "llvm_section_count": 0,
        "function_start_command_count": 0,
        "export_command_count": 0,
        "code_signature_command_count": 0,
        "encryption_command_count": 0,
        "encrypted_flag_count": 0,
        "rpath_count": 0,
        "test_framework_count": 0,
        "writable_executable_segment_count": 0,
        "defined_symbol_count": 0,
        "undefined_symbol_count": 0,
        "string_count": 0,
        "url_string_count": 0,
        "absolute_path_string_count": 0,
        "debug_path_string_count": 0,
        "secret_shape_count": 0,
        "tool_failure_count": 0,
        "string_scan_failed_count": 0,
        "string_scan_truncated_count": 0,
    }
    private = {
        "path": rel,
        "sections": [],
        "defined_symbols": [],
        "undefined_symbols": [],
        "interesting_strings": [],
        "headers": "",
        "tool_failures": [],
    }

    code, headers = run_capture(["llvm-objdump", "--macho", "--private-headers", str(path)], 15)
    if code == 0:
        text = headers.decode("utf-8", "replace")
        private["headers"] = text
        public["swift_section_count"] = len(re.findall(r"__swift5_[A-Za-z0-9_]+", text))
        public["objc_metadata_section_count"] = len(re.findall(r"__objc_(?:classlist|classname|methname|methtype|data|const)", text))
        public["debug_section_count"] = len(re.findall(r"__debug_|__DWARF", text))
        public["llvm_section_count"] = len(re.findall(r"__LLVM|__bitcode|__bundle|__cmdline|__llvm_prf_", text))
        public["function_start_command_count"] = len(re.findall(r"LC_FUNCTION_STARTS", text))
        public["export_command_count"] = len(re.findall(r"LC_DYLD_(?:EXPORTS_TRIE|INFO_ONLY)", text))
        public["code_signature_command_count"] = len(re.findall(r"LC_CODE_SIGNATURE", text))
        public["encryption_command_count"] = len(re.findall(r"LC_ENCRYPTION_INFO(?:_64)?", text))
        public["encrypted_flag_count"] = len(re.findall(r"\bcryptid\s+1\b", text))
        public["rpath_count"] = len(re.findall(r"LC_RPATH", text))
        public["test_framework_count"] = len(re.findall(r"XCTest|Testing\.framework|libXCTestSwiftSupport", text, re.I))
        public["writable_executable_segment_count"] = len(re.findall(r"(?:initprot|maxprot)\s+rwx", text))
        private["sections"] = sorted(set(re.findall(r"\b__[A-Za-z0-9_]+", text)))
    else:
        public["tool_failure_count"] += 1
        private["tool_failures"].append("macho_headers_failed")

    code, defined = run_capture(["llvm-nm", "--macho", "--defined-only", str(path)], 15)
    if code == 0:
        lines = [x for x in defined.decode("utf-8", "replace").splitlines() if x.strip()]
        public["defined_symbol_count"] = len(lines)
        private["defined_symbols"] = [x.rsplit(" ", 1)[-1] for x in lines[:500]]
    else:
        public["tool_failure_count"] += 1
        private["tool_failures"].append("defined_symbols_failed")

    code, undefined = run_capture(["llvm-nm", "--macho", "--undefined-only", str(path)], 15)
    if code == 0:
        lines = [x for x in undefined.decode("utf-8", "replace").splitlines() if x.strip()]
        public["undefined_symbol_count"] = len(lines)
        private["undefined_symbols"] = [x.rsplit(" ", 1)[-1] for x in lines[:500]]
    else:
        public["tool_failure_count"] += 1
        private["tool_failures"].append("undefined_symbols_failed")

    with tempfile.TemporaryFile() as tmp:
        env = sanitized_env()
        try:
            result = subprocess.run(
                ["strings", "-a", "-n", "8", str(path)],
                stdout=tmp,
                stderr=subprocess.DEVNULL,
                env=env,
                check=False,
                timeout=30,
            )
        except (OSError, subprocess.SubprocessError):
            result = None
        if result is not None and result.returncode == 0:
            tmp.seek(0)
            max_scan_bytes = 32 * 1024 * 1024
            scanned_bytes = 0
            while scanned_bytes < max_scan_bytes:
                raw_line = tmp.readline(min(1024 * 1024, max_scan_bytes - scanned_bytes + 1))
                if not raw_line:
                    break
                scanned_bytes += len(raw_line)
                if scanned_bytes > max_scan_bytes:
                    public["string_scan_truncated_count"] = 1
                    break
                line = raw_line.decode("utf-8", "replace").rstrip("\r\n")
                if not line:
                    continue
                public["string_count"] += 1
                for key, pattern in PATTERNS.items():
                    if pattern.search(line):
                        if key in ("private_key", "github_token", "live_key"):
                            public["secret_shape_count"] += 1
                        elif key == "url":
                            public["url_string_count"] += 1
                        elif key == "absolute_path":
                            public["absolute_path_string_count"] += 1
                        elif key == "debug_path":
                            public["debug_path_string_count"] += 1
                lower = line.lower()
                if len(private["interesting_strings"]) < 500 and any(token in lower for token in (
                    "debug", "trace", "assert", "sandbox", "instrument", "profile",
                    "coverage", "testflight", "staging", "localhost", "127.0.0.1",
                )):
                    private["interesting_strings"].append(line[:512])
            if scanned_bytes >= max_scan_bytes and tmp.read(1):
                public["string_scan_truncated_count"] = 1
        else:
            public["tool_failure_count"] += 1
            public["string_scan_failed_count"] = 1
            private["tool_failures"].append("strings_failed")

    return {"public": public, "private": private}

def main():
    if len(sys.argv) != 2:
        print("usage: audit.py APP_BUNDLE", file=sys.stderr)
        return 2
    app = pathlib.Path(sys.argv[1]).resolve()
    if not app.is_dir() or app.suffix != ".app":
        print("invalid app", file=sys.stderr)
        return 2

    images = image_paths(app)
    if not images:
        print("no Mach-O images", file=sys.stderr)
        return 1

    max_images = max(1, int(os.environ.get("MAX_MACHO_IMAGES", "12")))
    selected_images = images[:max_images]
    rows = []
    for index, path in enumerate(selected_images, start=1):
        print("[{}/{}] Processing Mach-O image {}".format(index, len(selected_images), path.name), file=sys.stderr, flush=True)
        rows.append(image_audit(path, app))

    public = {
        "schema": 1,
        "image_count": len(rows),
        "total_image_bytes": sum(r["public"]["size_bytes"] for r in rows),
        "swift_sections": sum(r["public"]["swift_section_count"] for r in rows),
        "objc_metadata_sections": sum(r["public"]["objc_metadata_section_count"] for r in rows),
        "debug_sections": sum(r["public"]["debug_section_count"] for r in rows),
        "llvm_sections": sum(r["public"]["llvm_section_count"] for r in rows),
        "function_start_commands": sum(r["public"]["function_start_command_count"] for r in rows),
        "export_commands": sum(r["public"]["export_command_count"] for r in rows),
        "code_signature_commands": sum(r["public"]["code_signature_command_count"] for r in rows),
        "encryption_commands": sum(r["public"]["encryption_command_count"] for r in rows),
        "encrypted_flags": sum(r["public"]["encrypted_flag_count"] for r in rows),
        "rpaths": sum(r["public"]["rpath_count"] for r in rows),
        "test_framework_links": sum(r["public"]["test_framework_count"] for r in rows),
        "writable_executable_segments": sum(r["public"]["writable_executable_segment_count"] for r in rows),
        "defined_symbols": sum(r["public"]["defined_symbol_count"] for r in rows),
        "undefined_symbols": sum(r["public"]["undefined_symbol_count"] for r in rows),
        "strings": sum(r["public"]["string_count"] for r in rows),
        "url_strings": sum(r["public"]["url_string_count"] for r in rows),
        "absolute_path_strings": sum(r["public"]["absolute_path_string_count"] for r in rows),
        "debug_path_strings": sum(r["public"]["debug_path_string_count"] for r in rows),
        "secret_shapes": sum(r["public"]["secret_shape_count"] for r in rows),
        "tool_failure_count": sum(r["public"]["tool_failure_count"] for r in rows),
        "string_scan_failed_count": sum(r["public"]["string_scan_failed_count"] for r in rows),
        "string_scan_truncated_count": sum(r["public"]["string_scan_truncated_count"] for r in rows),
    }
    private = {"schema": 1, "images": rows}
    print(json.dumps({"public": public, "private": private}, separators=(",", ":")))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
