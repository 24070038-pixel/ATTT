"""
Module: aes_cipher_modes.py
Mo ta: Cai dat cac che do hoat dong khoi (Cipher Modes) va co che dem (Padding)
- PKCS#7 Padding & Unpadding
- Che do Cipher Block Chaining (CBC)
- Che do Counter (CTR)
- Dong goi payload an toan: IV + Ciphertext (dinh dang Base64)
"""

import os
import base64
from aes_core import AES128


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Co che dem du lieu PKCS#7:
    Bo sung cac byte co gia tri bang so byte can dem de do dai la boi so cua block_size (16).
    Neu du lieu da chia het cho 16, them mot khoi dem day du 16 byte co gia tri 0x10 (16).
    """
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    Kiem tra va loai bo dem PKCS#7:
    Nem ra ValueError neu du lieu rong, khong chia het cho 16, hoac byte dem khong hop le.
    """
    if not data or len(data) % block_size != 0:
        raise ValueError("Du lieu can unpad khong dung dinh dang khoi hop le!")

    pad_len = data[-1]
    if pad_len < 1 or pad_len > block_size:
        raise ValueError(f"Gia tri dem PKCS#7 khong hop le: {pad_len}")

    # Kiem tra toan bo cac byte dem co dung bang pad_len khong
    if data[-pad_len:] != bytes([pad_len] * pad_len):
        raise ValueError("Cau truc byte dem PKCS#7 bi loi hoac bi thay doi!")

    return data[:-pad_len]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """XOR hai chuoi byte co cung do dai"""
    return bytes(x ^ y for x, y in zip(a, b))


class AESCipherMode:
    """
    Lop xu ly cac che do ma hoa khoi cap cao voi AES-128
    """
    def __init__(self, key: bytes):
        if len(key) != 16:
            raise ValueError("Khoa phai co do dai 16 bytes (AES-128)!")
        self.key = key
        self.aes = AES128(key)

    # ------------------ CHE DO CBC (CIPHER BLOCK CHAINING) ------------------ #

    def encrypt_cbc(self, plaintext: bytes, iv: bytes | None = None) -> tuple[bytes, bytes]:
        """
        Ma hoa du lieu o che do CBC:
        1. Tu dong dem PKCS#7.
        2. Sinh IV ngau nhien bang CSPRNG neu khong truyen vao.
        3. C_1 = Encrypt(P_1 ^ IV), C_i = Encrypt(P_i ^ C_{i-1}).
        Tra ve: (iv, ciphertext)
        """
        if iv is None:
            iv = os.urandom(16)
        elif len(iv) != 16:
            raise ValueError("Vector khoi tao IV phai dung 16 bytes!")

        padded_data = pkcs7_pad(plaintext)
        blocks = [padded_data[i:i + 16] for i in range(0, len(padded_data), 16)]

        ciphertext = bytearray()
        prev_block = iv

        for block in blocks:
            xored = xor_bytes(block, prev_block)
            encrypted = self.aes.encrypt_block(xored)
            ciphertext.extend(encrypted)
            prev_block = encrypted

        return iv, bytes(ciphertext)

    def decrypt_cbc(self, ciphertext: bytes, iv: bytes) -> bytes:
        """
        Giai ma du lieu o che do CBC:
        1. P_1 = Decrypt(C_1) ^ IV, P_i = Decrypt(C_i) ^ C_{i-1}.
        2. Loai bo PKCS#7 unpad.
        """
        if len(iv) != 16:
            raise ValueError("Vector khoi tao IV phai dung 16 bytes!")
        if len(ciphertext) == 0 or len(ciphertext) % 16 != 0:
            raise ValueError("Ciphertext khong chia het cho 16 bytes!")

        blocks = [ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)]
        decrypted_padded = bytearray()
        prev_block = iv

        for block in blocks:
            decrypted_block = self.aes.decrypt_block(block)
            xored = xor_bytes(decrypted_block, prev_block)
            decrypted_padded.extend(xored)
            prev_block = block

        return pkcs7_unpad(bytes(decrypted_padded))

    # ------------------ CHE DO CTR (COUNTER MODE) ------------------ #

    def encrypt_ctr(self, plaintext: bytes, nonce: bytes | None = None) -> tuple[bytes, bytes]:
        """
        Ma hoa du lieu o che do CTR:
        Che do dong (stream mode) khong can pad du lieu.
        Keystream = Encrypt(Nonce || Counter).
        Tra ve: (nonce, ciphertext)
        """
        if nonce is None:
            # 8 bytes nonce + 8 bytes counter = 16 bytes block
            nonce = os.urandom(8)
        elif len(nonce) != 8:
            raise ValueError("Nonce cho CTR yeu cau dung 8 bytes!")

        ciphertext = bytearray()
        counter = 0

        for i in range(0, len(plaintext), 16):
            chunk = plaintext[i:i + 16]
            counter_bytes = counter.to_bytes(8, byteorder="big")
            counter_block = nonce + counter_bytes
            keystream = self.aes.encrypt_block(counter_block)

            ciphertext.extend(xor_bytes(chunk, keystream[:len(chunk)]))
            counter += 1

        return nonce, bytes(ciphertext)

    def decrypt_ctr(self, ciphertext: bytes, nonce: bytes) -> bytes:
        """
        Giai ma che do CTR: Phep giai ma tuong dong hoan toan phep ma hoa (XOR keystream)
        """
        nonce_ret, plaintext = self.encrypt_ctr(ciphertext, nonce=nonce)
        return plaintext

    # ------------------ DONG GOI CHUAN DE LUU TRU / TRUYEN TIN ------------------ #

    def encrypt_to_base64_payload(self, plaintext_str: str) -> str:
        """
        Tien ich dong goi hoan chinh:
        Chuyen chuoi plaintext -> Ma hoa CBC -> Ghap IV (16B) + Ciphertext -> Base64 string
        """
        data = plaintext_str.encode("utf-8")
        iv, ct = self.encrypt_cbc(data)
        packed = iv + ct
        return base64.b64encode(packed).decode("utf-8")

    def decrypt_from_base64_payload(self, payload_b64: str) -> str:
        """
        Giai ma tu chuoi Base64 chua [IV || Ciphertext] ve chuoi plaintext UTF-8
        """
        raw = base64.b64decode(payload_b64.encode("utf-8"))
        if len(raw) < 32:  # Toi thieu 16 bytes IV + 16 bytes Ciphertext (1 khoi da pad)
            raise ValueError("Payload khong du do dai toi thieu 32 bytes!")
        iv = raw[:16]
        ct = raw[16:]
        plain_bytes = self.decrypt_cbc(ct, iv)
        return plain_bytes.decode("utf-8")
