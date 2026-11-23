"""Autentikasi pengguna: hashing password bcrypt dan pengelolaan sesi login.

Password tidak pernah disimpan apa adanya. Modul ini mengubahnya menjadi hash
bcrypt (salt acak + cost factor tersimpan di dalam string hash) lalu memeriksa
kecocokan saat pengguna login.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any

import bcrypt
import streamlit as st

import database as db

# Cost factor bcrypt. Higher = more secure but slower to compute.
COST_BCRYPT = 12

PANJANG_MIN_PASSWORD = 8
# bcrypt hanya memproses 72 byte pertama password.
PANJANG_MAKS_BYTE_PASSWORD = 72

KUNCI_ID = "auth_id_pengguna"
KUNCI_USERNAME = "auth_username"
KUNCI_LOGIN_AT = "auth_login_at"


class KesalahanAutentikasi(Exception):
    """Kesalahan autentikasi yang aman ditampilkan ke pengguna."""


def validasi_password(password: str) -> None:
    """Memastikan password memenuhi aturan panjang."""
    if len(password) < PANJANG_MIN_PASSWORD:
        raise KesalahanAutentikasi(
            f"Password minimal {PANJANG_MIN_PASSWORD} karakter."
        )
    if len(password.encode("utf-8")) > PANJANG_MAKS_BYTE_PASSWORD:
        raise KesalahanAutentikasi(
            f"Password maksimal {PANJANG_MAKS_BYTE_PASSWORD} byte."
        )


def hash_password(password: str) -> str:
    """Mengubah password menjadi hash bcrypt."""
    validasi_password(password)
    return bcrypt.hashpw(
        password.encode("utf-8"), bcrypt.gensalt(rounds=COST_BCRYPT)
    ).decode("ascii")


def verify_password(password: str, password_hash: str) -> bool:
    """Memeriksa password terhadap hash yang tersimpan."""
    try:
        return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("ascii"))
    except (ValueError, TypeError):
        return False


def buat_akun(username: str, password: str) -> dict[str, Any]:
    """Membuat akun pengguna baru dari password mentah."""
    return db.buat_pengguna(username, hash_password(password))


def ganti_password(id_user: int, password_lama: str, password_baru: str) -> None:
    """Mengganti password setelah password lama diverifikasi."""
    pengguna = db.ambil_pengguna(id_user)
    if pengguna is None:
        raise KesalahanAutentikasi("Pengguna tidak ditemukan.")
    if not verify_password(password_lama, pengguna["password_hash"]):
        raise KesalahanAutentikasi("Password lama salah.")
    if password_lama == password_baru:
        raise KesalahanAutentikasi("Password baru harus berbeda dari password lama.")
    db.ubah_password_pengguna(id_user, hash_password(password_baru))


def buka_sesi(pengguna: dict[str, Any]) -> dict[str, Any]:
    """Membuka sesi login untuk pengguna yang sudah terautentikasi."""
    db.catat_login_pengguna(pengguna["id_user"])
    st.session_state[KUNCI_ID] = pengguna["id_user"]
    st.session_state[KUNCI_USERNAME] = pengguna["username"]
    st.session_state[KUNCI_LOGIN_AT] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    return pengguna


def login(username: str, password: str) -> dict[str, Any]:
    """Memeriksa kredensial lalu membuka sesi login."""
    pengguna = db.cari_pengguna(username)
    if pengguna is None or not verify_password(password, pengguna["password_hash"]):
        raise KesalahanAutentikasi("Username atau password salah.")
    if not pengguna["aktif"]:
        raise KesalahanAutentikasi(
            "Akun ini sedang dinonaktifkan. Hubungi administrator sistem."
        )
    return buka_sesi(pengguna)


def logout() -> None:
    """Menutup sesi login yang sedang aktif."""
    for kunci in (KUNCI_ID, KUNCI_USERNAME, KUNCI_LOGIN_AT):
        st.session_state.pop(kunci, None)


def sudah_login() -> bool:
    """True bila ada sesi login aktif pada sesi Streamlit ini."""
    return bool(st.session_state.get(KUNCI_ID))


def pengguna_sekarang() -> str:
    """Username pengguna yang sedang login."""
    return str(st.session_state.get(KUNCI_USERNAME, "-"))


def waktu_login() -> str:
    """Waktu login pengguna aktif."""
    return str(st.session_state.get(KUNCI_LOGIN_AT, "-"))
