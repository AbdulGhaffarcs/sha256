# Systems Integration: Rust-Ruby FFI

Create a high-performance string pattern counter in Rust and bridge it to Ruby.

### Requirements:
1. Initialize a Rust library that exports **three** C-compatible functions:
   - `count_pattern(pattern: *const c_char, text: *const c_char) -> i32` — exact-case occurrences of pattern in text
   - `count_pattern_ci(pattern: *const c_char, text: *const c_char) -> i32` — same but case-insensitive
   - `count_lines_with_pattern(pattern: *const c_char, text: *const c_char) -> i32` — number of lines containing the pattern (case-insensitive, each line counted once)
2. Compile all three into `/app/engine.so` using `cargo` with `crate-type = ["cdylib"]`.
3. Write `/app/analyze.rb` using Ruby's **`fiddle`** library to load `/app/engine.so` and call all three functions via FFI.
4. The script must:
   - Read the syslog file at `SYSLOG_PATH` env var (default: `/var/log/syslog`)
   - Read the integer salt from `/app/salt.txt` (first line)
   - Call all three Rust functions with pattern `'ERROR'` / `'error'`
   - Compute `checksum = exact_raw XOR ci_count XOR lines_count` (raw counts, before salt)
   - Print one line: `exact=<exact_raw+salt> ci=<ci_count> lines=<lines_count> checksum=<checksum>`
5. All counting must be done in Rust — `analyze.rb` must not scan or count text in Ruby.

### Constraints:
- Return `-1` from all three functions if either pointer is null.
- Do **not** use Python or JS for any core solution logic.
- `/app/salt.txt` must be created as part of the solution containing the value `7`.
- After printing to stdout, append the result line to `/app/analyze.log` prefixed with a Unix timestamp: `<timestamp> | <result_line>` (e.g. `1234567890 | exact=9 ci=4 lines=3 checksum=5`).