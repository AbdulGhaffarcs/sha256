# SHA-256 From Scratch in C

Implement the SHA-256 cryptographic hash function entirely from scratch in C — no OpenSSL, no system crypto headers, no external libraries.

### Requirements

1. Implement SHA-256 in a C source file. Your implementation must include:
   - The 8 initial hash values (H0–H7) and 64 round constants (K)
   - Message padding: append `0x80`, zero bytes, then 64-bit big-endian bit-length
   - Message schedule expansion: 64 words per block
   - Compression function: all 64 rounds with Ch, Maj, Σ0, Σ1, σ0, σ1 operations
   - Final digest assembly in big-endian byte order

2. Compile your implementation into the binary `/app/sha256`.

3. The binary must support two usage modes:
   - **File mode**: `./sha256 <filepath>` — hash the contents of the file
   - **Stdin mode**: `./sha256 -` — read from stdin until EOF

4. Output exactly one line: the 64-character lowercase hex digest followed by a newline.

### Constraints
- Do **not** use any cryptographic library functions (OpenSSL, libgcrypt, libsodium, etc.)
- Do **not** use `sha256sum` or any system utility as a subprocess
- The binary must be compiled with `gcc` from your C source
- No Python, Go, or JavaScript

### Output Format
```
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```