import unittest

from .helpers import fake_secrets
from triage.redact import MASK, redact


class RedactTest(unittest.TestCase):
    def setUp(self):
        self.secrets = fake_secrets()

    def assert_masked(self, text: str, secret: str):
        result = redact(text)
        self.assertNotIn(secret, result, text)
        self.assertIn(MASK, result)

    def test_cle_aws(self):
        self.assert_masked(f'var key = "{self.secrets["aws"]}";', self.secrets["aws"])

    def test_token_github(self):
        self.assert_masked(f"git clone https://x@github.com avec {self.secrets['github']}", self.secrets["github"])

    def test_jwt_et_en_tete_bearer(self):
        self.assert_masked(f"Authorization: Bearer {self.secrets['jwt']}", self.secrets["jwt"])
        self.assert_masked(f"const t = '{self.secrets['jwt']}'", self.secrets["jwt"])

    def test_chaine_de_connexion(self):
        password = self.secrets["password"]
        self.assert_masked(f"Host=db;Username=app;Password={password};Database=clinic", password)
        self.assert_masked(f"postgres://app:{password}@db.internal:5432/clinic", password)

    def test_affectations_json_et_code(self):
        password = self.secrets["password"]
        self.assert_masked(f'"JwtSecret": "{password}"', password)
        self.assert_masked(f"api_key = '{password}'", password)
        self.assert_masked(f"DB_PASSWORD={password}", password)

    def test_cle_privee(self):
        body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"
        pem = "-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END " + "PRIVATE KEY-----"
        self.assert_masked(pem, body)

    def test_longue_chaine_aleatoire_et_hache(self):
        self.assert_masked(f'Signer("{self.secrets["random"]}")', self.secrets["random"])
        digest = "9f86d081884c7d659a2feaa0c55ad015" + "a3bf4f1b2b0b822cd15d6c15b0f00a08"
        self.assert_masked(f"sha256:{digest}", digest)

    def test_le_code_normal_reste_lisible(self):
        code = 'var rows = db.Appointments.FromSqlRaw("SELECT * FROM Appointments WHERE Id = " + id);'
        self.assertEqual(redact(code), code)
        path = "api/Controllers/AppointmentsController.cs"
        self.assertEqual(redact(path), path)

    def test_idempotent(self):
        once = redact(f"Password={self.secrets['password']}")
        self.assertEqual(redact(once), once)


if __name__ == "__main__":
    unittest.main()
