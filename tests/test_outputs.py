import subprocess
import os
import ctypes
import pytest

SYSLOG = "/tmp/test_syslog"
ENV = {**os.environ, "SYSLOG_PATH": SYSLOG}


def _write_syslog(content):
    with open(SYSLOG, "w") as f:
        f.write(content)


def _run_analyze():
    return subprocess.run(
        ["ruby", "/app/analyze.rb"],
        capture_output=True, text=True, env=ENV
    )


def test_files_exist():
    """Verify engine.so, analyze.rb, and salt.txt were created by the agent."""
    assert os.path.exists("/app/engine.so"),  "engine.so not found at /app/engine.so"
    assert os.path.exists("/app/analyze.rb"), "analyze.rb not found at /app/analyze.rb"
    assert os.path.exists("/app/salt.txt"),   "salt.txt not found at /app/salt.txt"


def test_salt_file_value():
    """Verify salt.txt contains the integer 7 on its first line."""
    val = int(open("/app/salt.txt").read().strip())
    assert val == 7, f"salt.txt must contain 7, got {val}"


def test_engine_built_with_cargo():
    """
    Verify engine.so was produced by a Rust/cargo build by checking for
    the __rustc_debug_gdb_scripts_section__ or rust_metadata symbol that
    rustc always embeds in compiled shared objects.
    """
    result = subprocess.run(
        ["strings", "/app/engine.so"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, f"strings failed: {result.stderr}"
    rust_markers = ["rustc", "rust_metadata", "__rustc", "GCC: (GNU)"]
    # Must contain at least one rustc marker and must NOT be pure GCC
    has_rustc = any(m in result.stdout for m in ["rustc", "rust_metadata", "__rustc"])
    assert has_rustc, (
        "engine.so does not appear to be compiled by rustc. "
        "Ensure the library is built with `cargo build --release` and crate-type=[\"cdylib\"]."
    )


def test_symbols_exported():
    """Verify all three FFI functions are exported from engine.so with C linkage via nm -D."""
    result = subprocess.run(["nm", "-D", "/app/engine.so"], capture_output=True, text=True)
    assert result.returncode == 0, f"nm failed: {result.stderr}"
    for sym in ("count_pattern", "count_pattern_ci", "count_lines_with_pattern"):
        assert sym in result.stdout, (
            f"Symbol '{sym}' not found in engine.so exports. "
            "Ensure it is #[no_mangle] pub extern \"C\"."
        )


def test_analyze_rb_uses_ffi():
    """
    Use Ruby's built-in Ripper AST parser to verify that analyze.rb:
    - requires fiddle
    - loads /app/engine.so via dlload
    - declares all three FFI functions
    - reads /app/salt.txt
    - does not use .scan or .count { } to count text in Ruby
    """
    ripper_script = r"""
require 'ripper'
require 'json'

source = File.read('/app/analyze.rb')
sexp   = Ripper.sexp(source)
flat   = sexp.inspect

results = {
  has_fiddle:    source.downcase.include?('fiddle'),
  has_engine_so: source.include?('/app/engine.so'),
  has_salt_txt:  source.include?('/app/salt.txt'),
  has_count_pattern:            source.include?('count_pattern'),
  has_count_pattern_ci:         source.include?('count_pattern_ci'),
  has_count_lines_with_pattern: source.include?('count_lines_with_pattern'),
  parse_ok: !sexp.nil?,
}

# Detect prohibited Ruby counting via AST: look for :method_add_arg nodes
# containing scan or count method calls on string/variable receivers
prohibited = false
source.scan(/\.(scan|count)\s*[\({]/) { prohibited = true }
results[:no_ruby_counting] = !prohibited

puts results.to_json
"""
    result = subprocess.run(
        ["ruby", "-e", ripper_script],
        capture_output=True, text=True
    )
    assert result.returncode == 0, f"Ripper script failed: {result.stderr}"

    import json
    checks = json.loads(result.stdout)

    assert checks["parse_ok"],                   "analyze.rb failed to parse as valid Ruby"
    assert checks["has_fiddle"],                 "analyze.rb must require 'fiddle'"
    assert checks["has_engine_so"],              "analyze.rb must dlload '/app/engine.so'"
    assert checks["has_salt_txt"],               "analyze.rb must read from '/app/salt.txt'"
    assert checks["has_count_pattern"],          "analyze.rb must call count_pattern via FFI"
    assert checks["has_count_pattern_ci"],       "analyze.rb must call count_pattern_ci via FFI"
    assert checks["has_count_lines_with_pattern"], "analyze.rb must call count_lines_with_pattern via FFI"
    assert checks["no_ruby_counting"],           "analyze.rb must not use .scan or .count{} to count in Ruby"


def test_ffi_enforced_at_runtime():
    """
    Runtime proof that analyze.rb delegates all counting to engine.so via FFI.

    Replaces /app/engine.so with a sentinel C library returning fixed values:
      count_pattern=42, count_pattern_ci=99, count_lines_with_pattern=17
    checksum = 42 XOR 99 XOR 17 = 88, salted exact = 42+7 = 49.
    Expected: 'exact=49 ci=99 lines=17 checksum=88'
    A pure-Ruby implementation cannot produce these sentinel-derived values.
    """
    sentinel_src = "/tmp/sentinel.c"
    sentinel_so  = "/app/sentinel_engine.so"
    with open(sentinel_src, "w") as f:
        f.write(
            '#include <stddef.h>\n'
            'int count_pattern(const char *p, const char *t) { return 42; }\n'
            'int count_pattern_ci(const char *p, const char *t) { return 99; }\n'
            'int count_lines_with_pattern(const char *p, const char *t) { return 17; }\n'
        )
    compile = subprocess.run(
        ["gcc", "-shared", "-fPIC", "-o", sentinel_so, sentinel_src],
        capture_output=True, text=True
    )
    assert compile.returncode == 0, f"Failed to compile sentinel: {compile.stderr}"

    backup = "/app/engine_backup.so"
    subprocess.run(["cp", "-f", "/app/engine.so", backup], check=True)
    subprocess.run(["cp", "-f", sentinel_so, "/app/engine.so"], check=True)
    try:
        _write_syslog("INFO: no errors here")
        result = _run_analyze()
        out = result.stdout.strip()
        assert out == "exact=49 ci=99 lines=17 checksum=88", (
            f"Expected 'exact=49 ci=99 lines=17 checksum=88' but got {out!r}. "
            f"analyze.rb is not delegating to engine.so via FFI. stderr: {result.stderr}"
        )
    finally:
        subprocess.run(["cp", "-f", backup, "/app/engine.so"], check=True)


def test_zero_match_case():
    """Verify output when syslog has no ERROR entries: exact=7 ci=0 lines=0 checksum=0."""
    _write_syslog("INFO: all good\nDEBUG: nothing wrong\nWARN: minor issue")
    result = _run_analyze()
    out = result.stdout.strip()
    assert out == "exact=7 ci=0 lines=0 checksum=0", (
        f"Expected 'exact=7 ci=0 lines=0 checksum=0', got {out!r}\nstderr: {result.stderr}"
    )


def test_salt_applied_to_exact_only():
    """With 1 ERROR: exact_raw=1, salt=7 gives exact=8; ci=1, lines=1, checksum=1^1^1=1."""
    _write_syslog("ERROR: single occurrence")
    result = _run_analyze()
    out = result.stdout.strip()
    assert out == "exact=8 ci=1 lines=1 checksum=1", (
        f"Expected 'exact=8 ci=1 lines=1 checksum=1', got {out!r}\nstderr: {result.stderr}"
    )


def test_functionality_mixed_case():
    """Verify counts on mixed-case fixture: 2 exact, 4 ci, 3 lines, checksum=2^4^3=5."""
    _write_syslog("ERROR: disk ERROR: full\nerror: lowercase\nError: mixed\nINFO: ok")
    result = _run_analyze()
    out = result.stdout.strip()
    assert out == "exact=9 ci=4 lines=3 checksum=5", (
        f"Expected 'exact=9 ci=4 lines=3 checksum=5', got {out!r}\nstderr: {result.stderr}"
    )


def test_analyze_log_written():
    """Verify analyze.rb appends '<unix_timestamp> | <result_line>' to /app/analyze.log."""
    if os.path.exists("/app/analyze.log"):
        os.remove("/app/analyze.log")

    _write_syslog("ERROR: test\nerror: ci\nINFO: skip")
    result = _run_analyze()
    stdout_line = result.stdout.strip()

    assert os.path.exists("/app/analyze.log"), \
        "analyze.rb must create /app/analyze.log"
    log_line = open("/app/analyze.log").read().strip().splitlines()[-1]
    assert " | " in log_line, \
        f"Log line must be '<timestamp> | <result>', got: {log_line!r}"
    ts_str, logged_result = log_line.split(" | ", 1)
    assert ts_str.strip().isdigit(), \
        f"Timestamp must be a Unix integer, got: {ts_str!r}"
    assert logged_result == stdout_line, \
        f"Logged result must match stdout: '{logged_result}' != '{stdout_line}'"


def test_null_pointer_guard():
    """Verify all three Rust functions return -1 for null pointer inputs via ctypes."""
    lib = ctypes.CDLL("/app/engine.so")
    for fn_name in ("count_pattern", "count_pattern_ci", "count_lines_with_pattern"):
        fn = getattr(lib, fn_name)
        fn.restype = ctypes.c_int
        fn.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        assert fn(None, None) == -1,     f"{fn_name}(null, null) must return -1"
        assert fn(b"ERROR", None) == -1, f"{fn_name}(pattern, null) must return -1"
        assert fn(None, b"text") == -1,  f"{fn_name}(null, text) must return -1"