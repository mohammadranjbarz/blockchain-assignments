import unittest

from main import generate_key_pair, sign, verify


class TestSum(unittest.TestCase):

    def test_generate_key_pair(self):
        secret = 'secrettt'
        keys = generate_key_pair(secret)
        private_key = keys[0]
        public_key = keys[1]
        self.assertTrue("-----BEGIN ENCRYPTED PRIVATE KEY-----" in private_key.decode("utf-8"))
        self.assertTrue("-----BEGIN PUBLIC KEY-----" in public_key.decode("utf-8"))

    def test_sign_and_verify(self):
        secret = 'secret'
        keys = generate_key_pair(secret)
        private_key = keys[0]
        public_key = keys[1]
        plain_text = "I'm a plain text, sign me if you can haahaa"
        signed = sign(private_key, secret, plain_text)
        self.assertIsNotNone(signed)
        is_sign_valid = verify(public_key, plain_text, signed)
        self.assertTrue(is_sign_valid)

    def test_sign_and_verify_fail_scenario(self):
        # We sign with private key but try to validate it with another public key
        secret = 'secret'
        keys = generate_key_pair(secret)
        private_key = keys[0]
        plain_text = "I'm a plain text, sign me if you can haahaa"
        signed = sign(private_key, secret, plain_text)
        self.assertIsNotNone(signed)
        another_public_key = generate_key_pair(secret)[1]
        is_sign_valid = verify(another_public_key, plain_text, signed)
        self.assertFalse(is_sign_valid)


if __name__ == '__main__':
    unittest.main()
