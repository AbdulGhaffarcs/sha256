import subprocess
import hashlib
import os
import random
import tempfile
import pytest

XOR_KEY = 0x07  # value stored in /app/xor_key by solve.sh


def _xor(data: bytes, key: int) -> bytes:
    """XOR every byte of data with key — mirrors the binary's preprocessing."""
    return bytes(b ^ key for b in data)


def _expected(data: bytes) -> str:
    """Compute expected digest: SHA-256(data XOR 0x07) using hashlib as ground truth."""
    return hashlib.sha256(_xor(data, XOR_KEY)).hexdigest()


def _run_stdin(data: bytes) -> str:
    """Feed data to /app/sha256 via stdin (-) and return the stripped digest."""
    result = subprocess.run(
        ["/app/sha256", "-"], input=data, capture_output=True
    )
    assert result.returncode == 0, f"non-zero exit: {result.stderr.decode()}"
    return result.stdout.decode().strip()


def _run_file(data: bytes) -> str:
    """Write data to a temp file, run /app/sha256 <path>, return the stripped digest."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        path = f.name
    try:
        result = subprocess.run(["/app/sha256", path], capture_output=True)
        assert result.returncode == 0, f"non-zero exit: {result.stderr.decode()}"
        return result.stdout.decode().strip()
    finally:
        os.unlink(path)


def test_binary_exists():
    """Verify /app/sha256 was compiled and exists as an executable ELF binary."""
    assert os.path.exists("/app/sha256"), "/app/sha256 not found"
    assert os.access("/app/sha256", os.X_OK), "/app/sha256 not executable"
    result = subprocess.run(["file", "/app/sha256"], capture_output=True, text=True)
    assert "ELF" in result.stdout, (
        f"/app/sha256 is not an ELF binary (got: {result.stdout.strip()}). "
        "Must be compiled from C source with gcc, not a shell script."
    )


def test_xor_key_file():
    """Verify /app/xor_key exists and contains the two-character hex value '07'."""
    assert os.path.exists("/app/xor_key"), "/app/xor_key not found"
    val = open("/app/xor_key").read().strip()
    assert val == "07", f"xor_key must contain '07', got '{val}'"


def test_no_crypto_lib():
    """
    Verify /app/sha256 does not dynamically link any cryptographic library.
    The SHA-256 implementation must be from scratch — no OpenSSL, libgcrypt, etc.
    """
    result = subprocess.run(["ldd", "/app/sha256"], capture_output=True, text=True)
    assert result.returncode == 0, f"ldd failed: {result.stderr}"
    output = result.stdout.lower()
    for lib in ["libssl", "libcrypto", "libgcrypt", "libsodium", "libmbedcrypto"]:
        assert lib not in output, (
            f"Binary links against forbidden crypto library '{lib}'. "
            "Implement SHA-256 from scratch."
        )


def test_output_format():
    """Verify output is exactly 64 lowercase hex characters followed by a newline."""
    result = subprocess.run(["/app/sha256", "-"], input=b"test", capture_output=True)
    assert result.returncode == 0
    raw = result.stdout.decode()
    assert raw.endswith("\n"), "Output must end with newline"
    digest = raw.strip()
    assert len(digest) == 64, f"Digest must be 64 chars, got {len(digest)}"
    assert digest == digest.lower(), "Digest must be lowercase"
    assert all(c in "0123456789abcdef" for c in digest), "Digest must be valid hex"


def test_xor_applied_empty():
    """Verify SHA-256(XOR(empty, 0x07)) — XOR of empty input is still empty."""
    got = _run_stdin(b"")
    assert got == _expected(b""), f"empty: got {got}"


def test_xor_applied_abc():
    """Verify SHA-256(XOR('abc', 0x07)) differs from plain SHA-256('abc'), proving XOR is applied."""
    plain_sha256 = hashlib.sha256(b"abc").hexdigest()
    got = _run_stdin(b"abc")
    assert got == _expected(b"abc"), f"xor+sha256('abc'): got {got}"
    assert got != plain_sha256, (
        "Output matches plain SHA-256 of 'abc' — XOR preprocessing was not applied."
    )


def test_xor_correctness_known_vector():
    """Verify XOR+SHA-256 of the NIST 'abc' vector with key 0x07 matches expected."""
    data = b"abc"
    got = _run_stdin(data)
    assert got == _expected(data), f"got {got}"


def test_55_byte_boundary():
    """
    Verify 55-byte input (padding boundary: fits in one SHA-256 block after pad).
    XOR preprocessing must be applied before SHA-256 padding.
    """
    data = b"B" * 55
    got = _run_stdin(data)
    assert got == _expected(data), f"55-byte: got {got}"


def test_56_byte_boundary():
    """
    Verify 56-byte input forces the SHA-256 length field into a second block.
    Many incorrect implementations fail this boundary after XOR preprocessing.
    """
    data = b"B" * 56
    got = _run_stdin(data)
    assert got == _expected(data), f"56-byte: got {got}"


def test_64_byte_boundary():
    """Verify 64-byte input (exactly one full SHA-256 block) with XOR preprocessing."""
    data = b"C" * 64
    got = _run_stdin(data)
    assert got == _expected(data), f"64-byte: got {got}"


def test_multi_block():
    """Verify multi-block input (1000 bytes) processes all blocks correctly after XOR."""
    data = b"abcdefgh" * 125
    got = _run_stdin(data)
    assert got == _expected(data), f"1000-byte: got {got}"


def test_binary_input():
    """Verify XOR+SHA-256 of all 256 possible byte values catches endianness bugs."""
    data = bytes(range(256))
    got = _run_stdin(data)
    assert got == _expected(data), f"binary 0-255: got {got}"


def test_xor_key_zero_identity():
    """
    Verify behavior is consistent: if key were 0x00, XOR would be identity.
    Here we confirm the binary correctly reads and applies the actual key 0x07,
    not 0x00, by checking output differs from plain SHA-256.
    """
    data = b"identity check"
    got = _run_stdin(data)
    plain = hashlib.sha256(data).hexdigest()
    assert got != plain, "XOR key 0x07 must change the output vs plain SHA-256"
    assert got == _expected(data), f"got {got}"


def test_random_inputs():
    """Verify XOR+SHA-256 matches expected for 10 random inputs (prevents hardcoding)."""
    rng = random.Random(99)
    for _ in range(10):
        length = rng.randint(0, 600)
        data = bytes(rng.randint(0, 255) for _ in range(length))
        got = _run_stdin(data)
        assert got == _expected(data), f"random {length}-byte failed: got {got}"


def test_file_mode_matches_stdin():
    """Verify file mode and stdin mode produce identical digests for the same input."""
    data = b"The quick brown fox jumps over the lazy dog"
    assert _run_file(data) == _run_stdin(data), "File mode and stdin mode disagree"


def test_file_mode_binary():
    """Verify file mode correctly handles binary data (1024 bytes of all byte values)."""
    data = bytes(range(256)) * 4
    got = _run_file(data)
    assert got == _expected(data), f"file mode binary: got {got}"