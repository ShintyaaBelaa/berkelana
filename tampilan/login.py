"""Halaman gerbang login.

Dua mode tampilan:
- Belum ada pengguna sama sekali -> form pembuatan akun pertama.
- Sudah ada pengguna            -> form login biasa.
"""

from __future__ import annotations

import streamlit as st

import auth
import components as ui
import database as db


def _kartu(judul: str, subjudul: str) -> None:
    logo = ui.logo_data_uri()
    if logo:
        st.markdown(
            f'<div class="bk-login-logo"><img src="{logo}" alt="Logo Berkelana Travel"></div>',
            unsafe_allow_html=True,
        )
    st.markdown(
        f'<div class="bk-login-title"><h2>{ui.esc(judul)}</h2>'
        f"<p>{ui.esc(subjudul)}</p></div>",
        unsafe_allow_html=True,
    )


def _form_akun_pertama() -> None:
    st.markdown(
        """
        <div class="bk-note">
            <b>Belum ada akun.</b> Buat akun petugas pertama untuk mulai memakai
            sistem. Password disimpan sebagai hash bcrypt, bukan teks biasa.
        </div>
        """,
        unsafe_allow_html=True,
    )
    with st.form("form_akun_pertama", clear_on_submit=True):
        username = st.text_input(
            "Username *",
            placeholder="Contoh: athifah",
            help="3-30 karakter: huruf, angka, titik, garis bawah, atau tanda hubung.",
        )
        password = st.text_input(
            "Password *",
            type="password",
            placeholder="Minimal 8 karakter",
        )
        konfirmasi = st.text_input(
            "Ulangi password *",
            type="password",
        )
        st.caption("* Wajib diisi. Password di-hash dengan bcrypt (cost factor 12).")
        disimpan = st.form_submit_button("Buat akun & masuk", type="primary")

    if not disimpan:
        return

    if password != konfirmasi:
        st.error("Konfirmasi password tidak sama dengan password.")
        return
    try:
        pengguna = auth.buat_akun(username, password)
    except db.KesalahanBisnis as exc:
        st.error(str(exc))
        return
    except auth.KesalahanAutentikasi as exc:
        st.error(str(exc))
        return

    auth.buka_sesi(pengguna)
    ui.set_flash("success", f"Akun {pengguna['username']} dibuat. Selamat datang!")
    st.rerun()


def _form_login() -> None:
    with st.form("form_login"):
        username = st.text_input(
            "Username *",
            placeholder="Masukkan username",
            key="login_username",
        )
        password = st.text_input(
            "Password *",
            type="password",
            placeholder="Masukkan password",
            key="login_password",
        )
        masuk = st.form_submit_button("Masuk", type="primary")

    if not masuk:
        return

    try:
        pengguna = auth.login(username, password)
    except auth.KesalahanAutentikasi as exc:
        st.error(str(exc))
        return

    ui.set_flash("success", f"Login berhasil. Halo, {pengguna['username']}!")
    st.rerun()


def render() -> None:
    _, tengah, _ = st.columns([1, 1.15, 1])
    with tengah:
        with st.container(key="bk_login_card"):
            belum_ada_akun = not db.daftar_pengguna()
            if belum_ada_akun:
                _kartu("Buat Akun Pertama", "Satu langkah lagi sebelum masuk ke sistem")
                _form_akun_pertama()
            else:
                _kartu("Login Berkelana Travel", "Masuk untuk mengelola data perjalanan")
                _form_login()
        st.markdown(
            '<div class="bk-login-foot">Berkelana Travel · Sistem Administrasi Perjalanan</div>',
            unsafe_allow_html=True,
        )
