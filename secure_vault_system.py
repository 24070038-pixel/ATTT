"""
Module: secure_vault_system.py
Mo ta: Tich hop Module AES vao He thong Thong tin quan ly Ho so Benh an An toan (Secure Medical Vault System)
Dap ung muc 3.5:
- Quy trinh ma hoa truoc khi luu xuong CSDL (Field-level encryption).
- Quy trinh giai ma khi co yeu cau truy xuat duoc uy quyen.
- Giao dien API / Service chuan cho he thong chinh.
"""

import sqlite3
import datetime
import json
from aes_cipher_modes import AESCipherMode


class SecureMedicalVaultService:
    """
    Dich vu luu tru va quan ly ho so bao mat (Secure Data Vault)
    Su dung co che Field-Level Encryption (FLE) bang AES-128-CBC de bao ve du lieu nhay cam.
    """
    def __init__(self, master_key: bytes, db_path: str = ":memory:"):
        """
        Khoi tao he thong voi Master Key va ket noi CSDL SQLite
        """
        if len(master_key) != 16:
            raise ValueError("Master key phai dung 16 bytes (AES-128)!")
        self.crypto_engine = AESCipherMode(master_key)
        self.db_path = db_path
        self.conn = sqlite3.connect(db_path)
        self._init_database()

    def _init_database(self):
        """Khoi tao cau truc bang CSDL luu tru cac truong ma hoa"""
        with self.conn:
            self.conn.execute("""
                CREATE TABLE IF NOT EXISTS patient_records (
                    patient_id TEXT PRIMARY KEY,
                    full_name_enc TEXT NOT NULL,
                    national_id_enc TEXT NOT NULL,
                    diagnosis_enc TEXT NOT NULL,
                    treatment_cost_enc TEXT NOT NULL,
                    created_at TEXT NOT NULL
                )
            """)

    def save_patient_record(self, patient_data: dict) -> dict:
        """
        API luu ho so benh an:
        1. Kiem tra truong bat buoc.
        2. Thuc hien ma hoa AES tung truong nhay cam truoc khi luu vao DB.
        3. Ghi xuong CSDL o dang Ciphertext + IV (Base64).
        """
        required_fields = ["patient_id", "full_name", "national_id", "diagnosis", "treatment_cost"]
        for f in required_fields:
            if f not in patient_data:
                raise ValueError(f"Thieu truong bat buoc: {f}")

        # Thuc hien quy trinh ma hoa truoc khi luu tru (Encryption-before-storage)
        full_name_enc = self.crypto_engine.encrypt_to_base64_payload(str(patient_data["full_name"]))
        national_id_enc = self.crypto_engine.encrypt_to_base64_payload(str(patient_data["national_id"]))
        diagnosis_enc = self.crypto_engine.encrypt_to_base64_payload(str(patient_data["diagnosis"]))
        treatment_cost_enc = self.crypto_engine.encrypt_to_base64_payload(str(patient_data["treatment_cost"]))
        created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()

        with self.conn:
            self.conn.execute("""
                INSERT OR REPLACE INTO patient_records 
                (patient_id, full_name_enc, national_id_enc, diagnosis_enc, treatment_cost_enc, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                patient_data["patient_id"],
                full_name_enc,
                national_id_enc,
                diagnosis_enc,
                treatment_cost_enc,
                created_at
            ))

        return {
            "status": "SUCCESS",
            "message": f"Ho so {patient_data['patient_id']} da duoc ma hoa AES va luu tru an toan vao CSDL.",
            "patient_id": patient_data["patient_id"],
            "timestamp": created_at
        }

    def get_patient_record(self, patient_id: str) -> dict:
        """
        API truy xuat ho so benh an:
        1. Doc ban ghi tu CSDL (dang Ciphertext).
        2. Thuc hien quy trinh giai ma AES (Decryption-on-retrieval).
        3. Tra ve ban ro cho nguoi dung da duoc xac thuc.
        """
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT full_name_enc, national_id_enc, diagnosis_enc, treatment_cost_enc, created_at
            FROM patient_records
            WHERE patient_id = ?
        """, (patient_id,))
        row = cursor.fetchone()

        if not row:
            raise KeyError(f"Khong tim thay benh nhan voi ma: {patient_id}")

        full_name_enc, national_id_enc, diagnosis_enc, treatment_cost_enc, created_at = row

        # Giai ma tung truong
        full_name = self.crypto_engine.decrypt_from_base64_payload(full_name_enc)
        national_id = self.crypto_engine.decrypt_from_base64_payload(national_id_enc)
        diagnosis = self.crypto_engine.decrypt_from_base64_payload(diagnosis_enc)
        treatment_cost = self.crypto_engine.decrypt_from_base64_payload(treatment_cost_enc)

        return {
            "patient_id": patient_id,
            "full_name": full_name,
            "national_id": national_id,
            "diagnosis": diagnosis,
            "treatment_cost": treatment_cost,
            "created_at": created_at
        }

    def get_raw_database_dump(self) -> list[dict]:
        """
        Kiem toan an toan (Security Audit):
        Lay du lieu tho dang duoc luu tren o dia de chung minh du lieu da duoc ma hoa hoan toan.
        """
        cursor = self.conn.cursor()
        cursor.execute("SELECT * FROM patient_records")
        rows = cursor.fetchall()
        result = []
        for r in rows:
            result.append({
                "patient_id": r[0],
                "full_name_enc": r[1],
                "national_id_enc": r[2],
                "diagnosis_enc": r[3],
                "treatment_cost_enc": r[4],
                "created_at": r[5]
            })
        return result
