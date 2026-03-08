# SHA-256 with XOR Preprocessing in C

Implement the SHA-256 cryptographic hash function entirely from scratch in C, with a byte-level XOR preprocessing stage.

### Requirements

1. Implement SHA-256 in C from scratch. Your implementation must include:
   - The 8 initial hash values (H0–H7) and 64 round constants (K)
   - Message padding: append `0x80`, zero bytes, then 64-bit big-endian bit-length
   - Message schedule: 64 words per block
   - Compression function: all 64 rounds with Ch, Maj, Σ0, Σ1, σ0, σ1
   - Final digest in big-endian byte order

2. Before hashing, XOR every byte of the input with the key byte stored in `/app/xor_key`. The key file contains a single line with a two-character lowercase hex value (e.g. `07`). Read this file at startup.

3. Compile your implementation to `/app/sha256` using `gcc`.

4. The binary supports two modes:
   - **File mode**: `./sha256 <filepath>` — XOR then hash the file
   - **Stdin mode**: `./sha256 -` — XOR then hash stdin until EOF

5. Output exactly one line: the 64-character lowercase hex digest followed by a newline.

6. `solve.sh` must create `/app/xor_key` containing `07`.

### Constraints
- Do **not** use OpenSSL, libgcrypt, libsodium, or any crypto library
- Do **not** call `sha256sum` or any subprocess for hashing
- Compiled with `gcc` from C source — no shell scripts as the binary
- No Python, Go, or JavaScript