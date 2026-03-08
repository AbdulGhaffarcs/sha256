import subprocess
import hashlib
import os
import random
import tempfile
import pytest


def _sha256(binary_data: bytes) -> str:
    """Compute expected SHA-256 using Python hashlib as ground truth."""
    return hashlib.sha256(binary_data).hexdigest()


def _run(data: bytes) -> str:
    """Feed data to /app/sha256 via stdin and return stdout stripped."""
    result = subprocess.run(
        ["/app/sha256", "-"],
        input=data,
        capture_output=True
    )
    assert result.returncode == 0, f"Binary exited non-zero: {result.stderr}"
    return result.stdout.decode().strip()


def _run_file(data: bytes) -> str:
    """Write data to a temp file, run /app/sha256 <file>, return stdout stripped."""
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(data)
        path = f.name
    try:
        result = subprocess.run(
            ["/app/sha256", path],
            capture_output=True
        )
        assert result.returncode == 0, f"Binary exited non-zero: {result.stderr}"
        return result.stdout.decode().strip()
    finally:
        os.unlink(path)


def test_binary_exists():
    """Verify /app/sha256 binary was compiled and exists at the required path."""
    assert os.path.exists("/app/sha256"), "/app/sha256 binary not found"
    assert os.access("/app/sha256", os.X_OK), "/app/sha256 is not executable"


def test_no_crypto_lib():
    """
    Verify /app/sha256 does not dynamically link any cryptographic library.
    The implementation must be from scratch — no OpenSSL, libgcrypt, libsodium.
    """
    result = subprocess.run(
        ["ldd", "/app/sha256"],
        capture_output=True, text=True
    )
    output = result.stdout.lower()
    forbidden = ["libssl", "libcrypto", "libgcrypt", "libsodium", "libmbedcrypto"]
    for lib in forbidden:
        assert lib not in output, (
            f"engine links against forbidden crypto library '{lib}'. "
            "Implement SHA-256 from scratch without crypto libraries."
        )


def test_output_format():
    """Verify output is exactly 64 lowercase hex characters followed by a newline."""
    result = subprocess.run(["/app/sha256", "-"], input=b"test", capture_output=True)
    assert result.returncode == 0
    out = result.stdout.decode()
    assert out.endswith("\n"), "Output must end with a newline"
    hex_part = out.strip()
    assert len(hex_part) == 64, f"Digest must be 64 hex chars, got {len(hex_part)}"
    assert hex_part == hex_part.lower(), "Digest must be lowercase hex"
    assert all(c in "0123456789abcdef" for c in hex_part), "Digest must be valid hex"


def test_empty_input():
    """Verify SHA-256 of empty input matches the NIST test vector."""
    got = _run(b"")
    assert got == _sha256(b""), f"Empty input: got {got}"


def test_abc():
    """Verify SHA-256 of 'abc' matches the NIST FIPS 180-4 test vector."""
    got = _run(b"abc")
    assert got == _sha256(b"abc"), f"'abc': got {got}"


def test_nist_long_vector():
    """Verify SHA-256 of the 448-bit NIST FIPS 180-4 test vector (56 bytes)."""
    data = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
    got = _run(data)
    assert got == _sha256(data), f"NIST long: got {got}"


def test_55_byte_boundary():
    """
    Verify SHA-256 of a 55-byte input (padding boundary edge case).
    55 bytes + 0x80 + 8-byte length = exactly 64 bytes (one block, no overflow).
    This is the last length that fits in a single block.
    """
    data = b"x" * 55
    got = _run(data)
    assert got == _sha256(data), f"55-byte: got {got}"


def test_56_byte_boundary():
    """
    Verify SHA-256 of a 56-byte input (padding boundary edge case).
    56 bytes forces the length field into a second block.
    Many incorrect implementations fail here.
    """
    data = b"x" * 56
    got = _run(data)
    assert got == _sha256(data), f"56-byte: got {got}"


def test_64_byte_boundary():
    """
    Verify SHA-256 of a 64-byte input (exactly one full block).
    The padding and length must go into a second block.
    """
    data = b"a" * 64
    got = _run(data)
    assert got == _sha256(data), f"64-byte: got {got}"


def test_multi_block():
    """Verify SHA-256 of a 1000-byte input requiring multiple compression rounds."""
    data = b"abcdefgh" * 125  # 1000 bytes
    got = _run(data)
    assert got == _sha256(data), f"1000-byte: got {got}"


def test_binary_data():
    """Verify SHA-256 handles arbitrary binary (non-ASCII) input correctly."""
    data = bytes(range(256))  # all 256 byte values
    got = _run(data)
    assert got == _sha256(data), f"binary 0-255: got {got}"


def test_random_inputs():
    """Verify SHA-256 output matches hashlib for 10 random inputs of varying length."""
    rng = random.Random(42)
    for _ in range(10):
        length = rng.randint(0, 500)
        data = bytes(rng.randint(0, 255) for _ in range(length))
        got = _run(data)
        assert got == _sha256(data), f"random {length}-byte input failed: got {got}"


def test_file_mode():
    """Verify file mode (./sha256 <filepath>) produces the same digest as stdin mode."""
    data = b"The quick brown fox jumps over the lazy dog"
    stdin_result = _run(data)
    file_result  = _run_file(data)
    assert file_result == stdin_result, (
        f"File mode and stdin mode disagree: file={file_result} stdin={stdin_result}"
    )


def test_file_mode_binary():
    """Verify file mode correctly hashes a binary file with non-ASCII content."""
    data = bytes(range(256)) * 4  # 1024 bytes of all byte values
    got = _run_file(data)
    assert got == _sha256(data), f"file mode binary: got {got}"