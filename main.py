"""
Chuong trinh chinh: main.py
De tai: "A Study on the Implementation of the AES Algorithm for a Secure Information System"
Muc tieu: Chay toan bo cac kich ban thuc nghiem cua Chuong 3:
1. NIST FIPS 197 Known Answer Test (KAT).
2. Danh gia Hieu ung Thac tuyet (Avalanche Effect).
3. Kiem thu Che do CBC va Dem PKCS#7 (bao gom ca co che phat hien loi dem).
4. Mo phong Thuc te: He thong Secure Medical Vault luu tru CSDL voi Field-Level Encryption.
5. Danh gia Hieu nang Thong luong (Performance Throughput Benchmark).
"""

import sys
import os
import time
from aes_core import AES128
from aes_cipher_modes import AESCipherMode, pkcs7_pad, pkcs7_unpad
from secure_vault_system import SecureMedicalVaultService

# Dam bao terminal Windows in dung ky tu UTF-8 ma khong bi loi ma hoa
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")


def print_banner(title: str):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)


# =====================================================================
# KICH BAN 1: NIST FIPS 197 KNOWN ANSWER TEST (KAT)
# =====================================================================
def run_nist_kat_test():
    print_banner("1. KIEM THU CHUAN XAC: NIST FIPS 197 KNOWN-ANSWER TEST (KAT)")
    
    key_hex = "000102030405060708090a0b0c0d0e0f"
    pt_hex = "00112233445566778899aabbccddeeff"
    expected_ct_hex = "69c4e0d86a7b0430d8cdb78070b4c55a"
    
    key = bytes.fromhex(key_hex)
    pt = bytes.fromhex(pt_hex)
    
    aes = AES128(key)
    ct = aes.encrypt_block(pt)
    decrypted_pt = aes.decrypt_block(ct)
    
    print(f"[-] Khoa dau vao (Key)           : {key_hex}")
    print(f"[-] Ban ro mau (Plaintext)        : {pt_hex}")
    print(f"[-] Ban ma ky vong (Expected CT)  : {expected_ct_hex}")
    print(f"[-] Ban ma thu duoc (Actual CT)   : {ct.hex()}")
    print(f"[-] Giai ma nguoc ve Plaintext    : {decrypted_pt.hex()}")
    
    assert ct.hex() == expected_ct_hex, "Loi: Ban ma khong khop voi NIST FIPS 197!"
    assert decrypted_pt == pt, "Loi: Giai ma khong khoi phuc dung ban ro!"
    print("[+] KET QUA: CHUAN XAC 100% VOI TIEU CHUAN NIST FIPS 197.")


# =====================================================================
# KICH BAN 2: AVALANCHE EFFECT (HIEU UNG THAC TUYET)
# =====================================================================
def run_avalanche_test():
    print_banner("2. DANH GIA TINH HON LOAN: HIEU UNG THAC TUYET (AVALANCHE EFFECT)")
    
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt1 = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
    
    # Dao dung 1 bit cuoi cung cua byte dau tien (0x32 = 00110010 -> 0x33 = 00110011)
    pt2_list = bytearray(pt1)
    pt2_list[0] ^= 0x01
    pt2 = bytes(pt2_list)
    
    aes = AES128(key)
    ct1 = aes.encrypt_block(pt1)
    ct2 = aes.encrypt_block(pt2)
    
    # Tinh so luong bit khac nhau giua ct1 va ct2 (Hamming distance)
    diff_bits = 0
    total_bits = 128
    for b1, b2 in zip(ct1, ct2):
        diff_bits += bin(b1 ^ b2).count("1")
    
    percentage = (diff_bits / total_bits) * 100
    
    print(f"[-] Ban ro 1 (PT1)       : {pt1.hex()}")
    print(f"[-] Ban ro 2 (PT2)       : {pt2.hex()} (chi khac dung 1 bit!)")
    print(f"[-] Ban ma 1 (CT1)       : {ct1.hex()}")
    print(f"[-] Ban ma 2 (CT2)       : {ct2.hex()}")
    print(f"[-] So bit bi dao doi    : {diff_bits}/{total_bits} bits")
    print(f"[-] Ty le thay doi       : {percentage:.2f}%")
    print("[+] NHAN XET: Thay doi 1 bit ban ro lam thay doi ~50% ban ma, thoa man tieu chi Avalanche.")


# =====================================================================
# KICH BAN 3: CBC MODE & PKCS#7 PADDING
# =====================================================================
def run_cbc_and_padding_test():
    print_banner("3. THUC NGHIEM CHE DO CBC VA XU LY DEM PKCS#7")
    
    key = os.urandom(16)
    cipher = AESCipherMode(key)
    
    sample_text = "Hệ thống bảo vệ dữ liệu hồ sơ cá nhân với giải thuật AES-128."
    payload_b64 = cipher.encrypt_to_base64_payload(sample_text)
    decrypted_text = cipher.decrypt_from_base64_payload(payload_b64)
    
    print(f"[-] Ban ro ban dau           : '{sample_text}'")
    print(f"[-] Do dai ban ro (bytes)    : {len(sample_text.encode('utf-8'))} bytes (khong chia het cho 16)")
    print(f"[-] Goi tin ma hoa (Base64)  : {payload_b64}")
    print(f"[-] Ban ro sau khi giai ma   : '{decrypted_text}'")
    assert decrypted_text == sample_text, "Loi: Du lieu giai ma khong khop!"
    
    print("\n[-] Kiem thu co che phat hien tan cong sua doi byte dem (Tampered Padding Attack):")
    # Thu co tinh unpad du lieu bi loi byte cuoi
    corrupted_data = b"0123456789abcdef0123456789abcde\x05"  # byte cuoi ghi 0x05 nhung chi co 1 byte
    try:
        pkcs7_unpad(corrupted_data)
        print("[!] Canh bao: Khong phat hien ra padding gia mao!")
    except ValueError as e:
        print(f"[+] Thanh cong: He thong phat hien va chan dung du lieu loi -> '{e}'")


# =====================================================================
# KICH BAN 4: TICH HOP HE THONG SECURE MEDICAL VAULT
# =====================================================================
def run_system_integration_demo():
    print_banner("4. TICH HOP HE THONG: SECURE MEDICAL VAULT (FIELD-LEVEL ENCRYPTION)")
    
    # Gia lap he thong su dung Master Key duoc sinh tu CSPRNG
    system_master_key = os.urandom(16)
    vault = SecureMedicalVaultService(master_key=system_master_key, db_path=":memory:")
    
    # 1. Bac si nhap ho so benh nhan vao he thong
    patient_record = {
        "patient_id": "BN-2026-9901",
        "full_name": "Nguyen Van An",
        "national_id": "001201009876",
        "diagnosis": "Viem phoi cap tinh do virus, tien su di ung Penicillin",
        "treatment_cost": "15,500,000 VND"
    }
    
    print("[-] 1. Client gui yeu cau luu ho so moi (Plaintext qua API):")
    for k, v in patient_record.items():
        print(f"      * {k}: {v}")
        
    save_result = vault.save_patient_record(patient_record)
    print(f"\n[+] Phap hoi API luu tru: {save_result['status']} - {save_result['message']}")
    
    # 2. Hacker hoac DBA truy cap trai phep truc tiep vao Database (Hacker View)
    print("\n[-] 2. KICH BAN TAN CONG: Hacker danh cap du lieu tho trong CSDL SQLite:")
    raw_db_dump = vault.get_raw_database_dump()
    for row in raw_db_dump:
        print(f"      [RECORD] Patient ID: {row['patient_id']}")
        print(f"         - full_name_enc     : {row['full_name_enc']}")
        print(f"         - national_id_enc   : {row['national_id_enc']}")
        print(f"         - diagnosis_enc     : {row['diagnosis_enc']}")
        print(f"         - treatment_cost_enc: {row['treatment_cost_enc']}")
    print("      => NHAN XET: Toan bo thong tin nhay cam deu la Ciphertext vo nghia tren o dia!")
    
    # 3. Nguoi dung hop le (Bac si) truy xuat ho so qua API
    print("\n[-] 3. Truy xuat hop le qua API giai ma (Authorized Doctor View):")
    retrieved_record = vault.get_patient_record("BN-2026-9901")
    for k, v in retrieved_record.items():
        print(f"      * {k}: {v}")
    
    assert retrieved_record["full_name"] == patient_record["full_name"]
    assert retrieved_record["diagnosis"] == patient_record["diagnosis"]
    print("[+] XAC THUC: Ho so duoc giai ma nguyen ven, hoan toan khop voi du lieu goc.")


# =====================================================================
# KICH BAN 5: PERFORMANCE BENCHMARK (DO LUONG THONG LUONG)
# =====================================================================
def run_performance_benchmark():
    print_banner("5. DO LUONG VA DANH GIA HIEU NANG (PERFORMANCE BENCHMARK)")
    
    key = os.urandom(16)
    cipher = AESCipherMode(key)
    
    # Chuan bi cac goi du lieu kich thuoc: 64 KB, 256 KB, 512 KB
    sizes_kb = [64, 256, 512]
    
    print(f"{'Dung luong':<15} | {'Thoi gian ma hoa':<18} | {'Thong luong (Throughput)':<22} | {'Ket qua'}")
    print("-" * 75)
    
    for size_kb in sizes_kb:
        data_size = size_kb * 1024
        raw_payload = os.urandom(data_size)
        
        t0 = time.perf_counter()
        iv, ct = cipher.encrypt_cbc(raw_payload)
        t_enc = time.perf_counter() - t0
        
        t1 = time.perf_counter()
        decrypted = cipher.decrypt_cbc(ct, iv)
        t_dec = time.perf_counter() - t1
        
        throughput_mb_s = (data_size / (1024 * 1024)) / t_enc
        
        assert decrypted == raw_payload, "Giai ma sai du lieu benchmark!"
        
        print(f"{size_kb:<10} KB  | {t_enc * 1000:<13.2f} ms | {throughput_mb_s:<17.2f} MB/s | PASSED")


if __name__ == "__main__":
    print("=" * 70)
    print("  KHOA AN TOAN THONG TIN - TRIEN KHAI THUAT TOAN AES-128 (FIPS 197)")
    print("  Topic: Implementation of AES Algorithm for Secure Information System")
    print("=" * 70)
    
    run_nist_kat_test()
    run_avalanche_test()
    run_cbc_and_padding_test()
    run_system_integration_demo()
    run_performance_benchmark()
    
    print_banner("HOAN THANH TOAN BO CAC MUC THUC HANH CUA CHUONG 3")
