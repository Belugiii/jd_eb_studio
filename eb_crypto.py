"""AES-CBC eb parameter crypto, matching JDUtils.java."""

from __future__ import annotations

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

DEFAULT_KEY_HEX = "39323332393637333930303832363137"
DEFAULT_IV = b"0102030405060708"
BLOCK_SIZE = AES.block_size


class CryptoError(ValueError):
    pass


def hex_decode(value: str) -> bytes:
    if value is None:
        raise CryptoError("密钥不能为空")
    cleaned = "".join(value.split())
    if not cleaned:
        raise CryptoError("密钥不能为空")
    if len(cleaned) % 2 == 1:
        raise CryptoError("十六进制长度必须为偶数")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise CryptoError("密钥不是合法十六进制") from exc


def encrypt(plaintext: str, key_hex: str = DEFAULT_KEY_HEX, iv: bytes = DEFAULT_IV) -> str:
    if plaintext is None or plaintext == "":
        raise CryptoError("明文不能为空")
    if key_hex is None or key_hex == "":
        raise CryptoError("密钥不能为空")
    key = hex_decode(key_hex)
    if len(key) not in (16, 24, 32):
        raise CryptoError("AES 密钥长度必须是 16 / 24 / 32 字节")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(plaintext.encode("utf-8"), BLOCK_SIZE))
    return encrypted.hex().upper()


def decrypt(ciphertext_hex: str, key_hex: str = DEFAULT_KEY_HEX, iv: bytes = DEFAULT_IV) -> str:
    if ciphertext_hex is None or ciphertext_hex.strip() == "":
        raise CryptoError("密文不能为空")
    if key_hex is None or key_hex == "":
        raise CryptoError("密钥不能为空")
    key = hex_decode(key_hex)
    if len(key) not in (16, 24, 32):
        raise CryptoError("AES 密钥长度必须是 16 / 24 / 32 字节")
    cleaned = "".join(ciphertext_hex.split())
    try:
        encrypted_bytes = bytes.fromhex(cleaned.lower())
    except ValueError as exc:
        raise CryptoError("密文不是合法十六进制") from exc
    if len(encrypted_bytes) == 0 or len(encrypted_bytes) % BLOCK_SIZE != 0:
        raise CryptoError("密文长度必须是 16 字节的整数倍")
    cipher = AES.new(key, AES.MODE_CBC, iv)
    try:
        decrypted = unpad(cipher.decrypt(encrypted_bytes), BLOCK_SIZE)
    except ValueError as exc:
        raise CryptoError("解密失败，请检查密钥、IV 或密文") from exc
    return decrypted.decode("utf-8")


def inspect(plaintext: str | None, ciphertext_hex: str | None, key_hex: str) -> dict:
    key = hex_decode(key_hex or DEFAULT_KEY_HEX)
    info = {
        "algorithm": "AES/CBC/PKCS5Padding",
        "keyHex": key.hex().upper(),
        "keyBytes": len(key),
        "keyBits": len(key) * 8,
        "iv": DEFAULT_IV.decode("ascii"),
        "ivHex": DEFAULT_IV.hex().upper(),
        "blockSize": BLOCK_SIZE,
    }
    if plaintext:
        raw = plaintext.encode("utf-8")
        padded_len = ((len(raw) // BLOCK_SIZE) + 1) * BLOCK_SIZE
        info["plainBytes"] = len(raw)
        info["paddedBytes"] = padded_len
        info["cipherBlocks"] = padded_len // BLOCK_SIZE
    if ciphertext_hex:
        cleaned = "".join(ciphertext_hex.split())
        info["cipherHexLen"] = len(cleaned)
        info["cipherBytes"] = len(cleaned) // 2
    return info
