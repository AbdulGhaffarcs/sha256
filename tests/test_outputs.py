import subprocess
import os
import ctypes
import json
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


def test_engine_built_with_rust():
    """
    Verify engine.so was compiled by rustc and not a plain C compiler.
    Uses 'strings' to detect rustc-specific markers always embedded by the
    Rust compiler (rustc version strings, rust_metadata section).
    """
    result = subprocess.run(
        ["strings", "/app/engine.so"],
        capture_output=True, text=True
    )
    assert result.returncode == 0, f"strings failed: {result.stderr}"
    has_rustc = any(
        marker in result.stdout
        for marker in ["rustc", "rust_metadata", "__rustc"]
    )
    assert has_rustc, (
        "engine.so does not contain rustc compiler markers. "
        "Build with `cargo build --release` and crate-type=[\"cdylib\"]."
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
    Use Ruby's built-in Ripper AST parser to verify analyze.rb structure:
    requires fiddle, loads engine.so, declares all three FFI functions,
    reads salt.txt, and does not invoke .scan/.count/.match on text in Ruby.
    All checks are performed via Ripper.sexp AST traversal — no regex.
    """
    ripper_script = r"""
require 'ripper'
require 'json'

source = File.read('/app/analyze.rb')
sexp   = Ripper.sexp(source)

results = { parse_ok: !sexp.nil? }

def walk(node, &block)
  return unless node.is_a?(Array)
  block.call(node)
  node.each { |child| walk(child, &block) }
end

# Detect prohibited Ruby counting methods via AST :call nodes
prohibited_calls = []
walk(sexp) do |node|
  if node[0] == :call
    method_node = node[3]
    if method_node.is_a?(Array) && method_node[0] == :@ident
      name = method_node[1]
      prohibited_calls << name if ['scan', 'count', 'match'].include?(name)
    end
  end
end

# Detect require statements via AST :command nodes
require_args = []
walk(sexp) do |node|
  if node[0] == :command
    cmd = node[1]
    if cmd.is_a?(Array) && cmd[0] == :@ident && cmd[1] == 'require'
      walk(node[2]) do |n|
        require_args << n[1] if n.is_a?(Array) && n[0] == :@tstring_content
      end
    end
  end
end

# Detect string literals referencing key paths via AST :@tstring_content nodes
string_literals = []
walk(sexp) do |node|
  string_literals << node[1] if node.is_a?(Array) && node[0] == :@tstring_content
end

# Detect method identifiers (FFI extern declarations and calls) via :@ident nodes
ident_names = []
walk(sexp) do |node|
  ident_names << node[1] if node.is_a?(Array) && node[0] == :@ident
end

results[:has_fiddle]                   = require_args.any? { |r| r.include?('fiddle') }
results[:has_engine_so]                = string_literals.any? { |s| s.include?('/app/engine.so') }
results[:has_salt_txt]                 = string_literals.any? { |s| s.include?('/app/salt.txt') }
results[:has_count_pattern]            = ident_names.include?('count_pattern')
results[:has_count_pattern_ci]         = ident_names.include?('count_pattern_ci')
results[:has_count_lines_with_pattern] = ident_names.include?('count_lines_with_pattern')
results[:no_ruby_counting]             = prohibited_calls.empty?
results[:prohibited_calls]             = prohibited_calls

puts results.to_json
"""
    result = subprocess.run(["ruby", "-e", ripper_script], capture_output=True, text=True)
    assert result.returncode == 0, f"Ripper script failed: {result.stderr}"

    checks = json.loads(result.stdout)
    assert checks["parse_ok"],                      "analyze.rb is not valid Ruby"
    assert checks["has_fiddle"],                    "analyze.rb must require 'fiddle'"
    assert checks["has_engine_so"],                 "analyze.rb must reference '/app/engine.so'"
    assert checks["has_salt_txt"],                  "analyze.rb must read from '/app/salt.txt'"
    assert checks["has_count_pattern"],             "analyze.rb must call count_pattern via FFI"
    assert checks["has_count_pattern_ci"],          "analyze.rb must call count_pattern_ci via FFI"
    assert checks["has_count_lines_with_pattern"],  "analyze.rb must call count_lines_with_pattern via FFI"
    assert checks["no_ruby_counting"], (
        f"analyze.rb must not call .scan/.count/.match on text in Ruby "
        f"(found: {checks['prohibited_calls']}). Delegate all counting to Rust."
    )


def test_ffi_enforced_at_runtime():
    """
    Runtime proof that analyze.rb delegates all counting to engine.so via FFI.

    Replaces /app/engine.so with a sentinel C library returning fixed values:
      count_pattern=42, count_pattern_ci=99, count_lines_with_pattern=17
    checksum = 42 XOR 99 XOR 17 = 88, salted exact = 42+7 = 49.
    Expected output: 'exact=49 ci=99 lines=17 checksum=88'
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