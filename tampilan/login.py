"""Halaman gerbang login.

Dua tab: Sign In untuk akun yang sudah terdaftar dan Sign Up untuk
membuat akun baru. Saat tabel pengguna masih kosong, tab Sign Up
dibuka lebih dulu karena belum ada akun yang bisa masuk.
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


def _form_daftar() -> None:
    with st.form("form_daftar", clear_on_submit=True):
        username = st.text_input(
            "Username *",
            placeholder="Contoh: athifah",
            key="daftar_username",
            help="3-30 karakter: huruf, angka, titik, garis bawah, atau tanda hubung.",
        )
        password = st.text_input(
            "Password *",
            type="password",
            placeholder="Minimal 8 karakter",
            key="daftar_password",
        )
        konfirmasi = st.text_input(
            "Ulangi password *",
            type="password",
            key="daftar_konfirmasi",
        )
        st.caption("* Wajib diisi. Password di-hash dengan bcrypt (cost factor 12).")
        daftar = st.form_submit_button("Daftar sekarang", type="primary")

    if not daftar:
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
    ui.set_flash("success", f"Akun {pengguna['username']} berhasil dibuat. Selamat datang!")
    st.rerun()


def _form_login() -> None:
    with st.form("form_login"):
        username = st.text_input(
            "Username *",
            placeholder="Contoh: bela",
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
            _kartu(
                "Berkelana Travel",
                "Sistem Administrasi Perjalanan"
                if belum_ada_akun
                else "Masuk atau daftar untuk mengelola data perjalanan",
            )

            if belum_ada_akun:
                st.markdown(
                    """
                    <div class="bk-note">
                        <b>Belum ada akun.</b> Daftarkan akun petugas pertama untuk
                        mulai memakai sistem. Password disimpan sebagai hash bcrypt,
                        bukan teks biasa.
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                tab_daftar, tab_masuk = st.tabs(["Sign Up", "Sign In"])
                with tab_daftar:
                    _form_daftar()
                with tab_masuk:
                    _form_login()
            else:
                tab_masuk, tab_daftar = st.tabs(["Sign In", "Sign Up"])
                with tab_masuk:
                    _form_login()
                with tab_daftar:
                    _form_daftar()
        st.markdown(
            '<div class="bk-login-foot">Berkelana Travel · Sistem Administrasi Perjalanan</div>',
            unsafe_allow_html=True,
        )
