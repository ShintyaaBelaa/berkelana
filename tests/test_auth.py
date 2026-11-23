"""Pengujian autentikasi: hashing bcrypt, sesi login, dan CRUD pengguna.

Jalankan dari folder proyek:
    python -m unittest discover -s tests -v
"""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

_TMP = tempfile.TemporaryDirectory()
os.environ.setdefault("BERKELANA_DB", str(Path(_TMP.name) / "berkelana_auth_test.db"))

import auth  # noqa: E402  (environment harus diset sebelum import)
import database as db  # noqa: E402


class BasisUji(unittest.TestCase):
    def setUp(self) -> None:
        self._env_asli = os.environ.get("BERKELANA_DB")
        os.environ["BERKELANA_DB"] = str(Path(_TMP.name) / f"auth_{self.id()}.db")
        path = Path(os.environ["BERKELANA_DB"])
        for suffix in ("", "-wal", "-shm"):
            berkas = Path(str(path) + suffix)
            if berkas.exists():
                berkas.unlink()
        db.init_db(seed=False)

        self.session: dict = {}
        self._st_asli = auth.st
        auth.st = SimpleNamespace(session_state=self.session)

    def tearDown(self) -> None:
        auth.st = self._st_asli
        if self._env_asli is None:
            os.environ.pop("BERKELANA_DB", None)
        else:
            os.environ["BERKELANA_DB"] = self._env_asli

    def akun(self, username: str = "athifah", password: str = "rahasia123") -> dict:
        return auth.buat_akun(username, password)


class UjiHashing(unittest.TestCase):
    def test_hash_tidak_sama_dengan_password(self) -> None:
        hash_pw = auth.hash_password("rahasia123")
        self.assertNotIn("rahasia123", hash_pw)
        self.assertTrue(hash_pw.startswith("$2b$"))

    def test_salt_acak_menghasilkan_hash_berbeda(self) -> None:
        self.assertNotEqual(
            auth.hash_password("rahasia123"),
            auth.hash_password("rahasia123"),
        )

    def test_verify_password(self) -> None:
        hash_pw = auth.hash_password("rahasia123")
        self.assertTrue(auth.verify_password("rahasia123", hash_pw))
        self.assertFalse(auth.verify_password("rahasiaSalah", hash_pw))

    def test_verify_password_hash_rusak_tidak_melempar(self) -> None:
        self.assertFalse(auth.verify_password("rahasia123", "bukan-hash"))

    def test_tolak_password_terlalu_pendek(self) -> None:
        with self.assertRaises(auth.KesalahanAutentikasi):
            auth.hash_password("pendek1")

    def test_tolak_password_lebih_dari_72_byte(self) -> None:
        with self.assertRaises(auth.KesalahanAutentikasi):
            auth.hash_password("a" * 73)


class UjiPengguna(BasisUji):
    def test_buat_akun_hash_password(self) -> None:
        pengguna = self.akun()
        tersimpan = db.cari_pengguna("athifah")
        self.assertIsNotNone(tersimpan)
        self.assertNotEqual(tersimpan["password_hash"], "rahasia123")
        self.assertTrue(auth.verify_password("rahasia123", tersimpan["password_hash"]))
        self.assertEqual(pengguna["username"], "athifah")

    def test_tolak_username_ganda_serta_huruf_besar(self) -> None:
        self.akun()
        with self.assertRaises(db.KesalahanBisnis):
            self.akun(username="ATHIFAH")

    def test_tolak_username_pola_terlarang(self) -> None:
        for username in ("ab", "spasi username", "nama@domai"):
            with self.assertRaises(db.KesalahanBisnis):
                self.akun(username=username)

    def test_ganti_password_mengubah_hash(self) -> None:
        pengguna = self.akun()
        auth.ganti_password(pengguna["id_user"], "rahasia123", "rahasia456")
        tersimpan = db.ambil_pengguna(pengguna["id_user"])
        self.assertTrue(auth.verify_password("rahasia456", tersimpan["password_hash"]))
        self.assertFalse(auth.verify_password("rahasia123", tersimpan["password_hash"]))

    def test_ganti_password_menolak_password_lama_salah(self) -> None:
        pengguna = self.akun()
        with self.assertRaises(auth.KesalahanAutentikasi):
            auth.ganti_password(pengguna["id_user"], "salahbanget", "rahasia456")

    def test_ganti_password_menolak_password_baru_sama_lama(self) -> None:
        pengguna = self.akun()
        with self.assertRaises(auth.KesalahanAutentikasi):
            auth.ganti_password(pengguna["id_user"], "rahasia123", "rahasia123")

    def test_akun_terakhir_tidak_bisa_dinonaktifkan(self) -> None:
        pengguna = self.akun()
        with self.assertRaises(db.KesalahanBisnis):
            db.atur_status_pengguna(pengguna["id_user"], False)

    def test_akun_terakhir_tidak_bisa_dihapus(self) -> None:
        pengguna = self.akun()
        with self.assertRaises(db.KesalahanBisnis):
            db.hapus_pengguna(pengguna["id_user"])

    def test_nonaktifkan_akun_lain_berhasil(self) -> None:
        pertama = self.akun("athifah")
        kedua = self.akun("diza", "rahasia456")
        db.atur_status_pengguna(kedua["id_user"], False)
        self.assertEqual(db.jumlah_pengguna_aktif(), 1)
        self.assertFalse(db.ambil_pengguna(kedua["id_user"])["aktif"])
        self.assertTrue(db.ambil_pengguna(pertama["id_user"])["aktif"])

    def test_hapus_pengguna(self) -> None:
        self.akun("athifah")
        kedua = self.akun("diza", "rahasia456")
        db.hapus_pengguna(kedua["id_user"])
        self.assertIsNone(db.cari_pengguna("diza"))
        self.assertEqual(len(db.daftar_pengguna()), 1)

    def test_login_terakhir_tercatat(self) -> None:
        pengguna = self.akun()
        auth.login("athifah", "rahasia123")
        tersimpan = db.ambil_pengguna(pengguna["id_user"])
        self.assertIsNotNone(tersimpan["login_terakhir"])


class UjiSesi(BasisUji):
    def test_login_berhasil_membuka_sesi(self) -> None:
        self.akun()
        pengguna = auth.login("athifah", "rahasia123")
        self.assertEqual(auth.pengguna_sekarang(), "athifah")
        self.assertTrue(auth.sudah_login())
        self.assertEqual(self.session[auth.KUNCI_ID], pengguna["id_user"])

    def test_login_gagal_tidak_membuka_sesi(self) -> None:
        self.akun()
        with self.assertRaises(auth.KesalahanAutentikasi):
            auth.login("athifah", "salahbanget")
        self.assertFalse(auth.sudah_login())

    def test_login_gagal_username_tidak_dikenal(self) -> None:
        self.akun()
        with self.assertRaises(auth.KesalahanAutentikasi):
            auth.login("entah", "rahasia123")
        self.assertFalse(auth.sudah_login())

    def test_login_akun_nonaktif_ditolak(self) -> None:
        pengguna = self.akun("athifah")
        self.akun("diza", "rahasia456")
        db.atur_status_pengguna(pengguna["id_user"], False)
        with self.assertRaises(auth.KesalahanAutentikasi):
            auth.login("athifah", "rahasia123")
        self.assertFalse(auth.sudah_login())

    def test_logout_menutup_sesi(self) -> None:
        self.akun()
        auth.login("athifah", "rahasia123")
        auth.logout()
        self.assertFalse(auth.sudah_login())
        self.assertNotIn(auth.KUNCI_ID, self.session)


if __name__ == "__main__":
    unittest.main()
