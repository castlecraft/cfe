# /home/revant/Projects/cfe-bench/development/frappe-bench/apps/castlecraft/tests/test_jwt_new_user.py
import time
import unittest
from unittest.mock import MagicMock, patch

from castlecraft import auth
from tests.conftest import MockDoc


class TestJWTNewUser(unittest.TestCase):
    def setUp(self):
        self.mock_jwt_idp = MockDoc(
            dict(
                doctype="CFE Identity Provider",
                authorization_type="JWT Verification",
                email_key="email",
                create_user=True,
                fetch_user_info=False,  # Explicitly define this to prevent AttributeError
                jwks_endpoint="https://idp.example.com/.well-known/jwks.json",
                audience_claim_key="aud",
                allowed_audience=[MockDoc(dict(aud="test-audience"))],
                first_name_key="given_name",
                full_name_key="name",
                user_roles=[],
                user_fields=[],
            )
        )

    @patch("castlecraft.auth.requests")
    @patch(
        "castlecraft.auth.frappe.get_value"
    )  # Mock frappe.get_value for pre-validation
    @patch("castlecraft.auth.jwt")
    @patch("castlecraft.auth.create_and_save_user")
    @patch("castlecraft.auth.get_b64_decoded_json")
    @patch("castlecraft.auth.get_idp")
    def test_jwt_verification_new_user_creation(
        self,
        mock_get_idp,
        mock_b64_decode,
        mock_create_user,
        mock_jwt,
        mock_get_value,
        mock_requests,
    ):
        """Test JWT verification with user creation for a new user."""
        # --- Arrange ---
        new_user_email = "new.jwt.user@example.com"
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJuZXcuand0LnVzZXJAZXhhbXBsZS5jb20iLCJpYXQiOjE1MTYyMzkwMjIsImF1ZCI6InRlc3QtYXVkaWVuY2UifQ.signature_part"  # noqa: E501

        auth.frappe.get_request_header.return_value = f"Bearer {jwt_token}"
        mock_get_idp.return_value = self.mock_jwt_idp
        # User is not found after successful JWT decoding
        mock_get_value.return_value = None

        decoded_payload = {
            "email": new_user_email,
            "exp": time.time() + 3600,
            "aud": "test-audience",
            "sub": "new-user-sub-456",  # Ensure sub is present for cache_user_from_sub
        }
        mock_b64_decode.return_value = decoded_payload

        # Mock the internal dependencies of validate_signature
        mock_requests.get.return_value.json.return_value = {
            "keys": [{"kid": "test-kid"}]
        }
        mock_jwt.get_unverified_header.return_value = {"kid": "test-kid"}
        mock_jwt.algorithms.RSAAlgorithm.from_jwk.return_value = MagicMock()
        mock_jwt.decode.return_value = decoded_payload

        mock_user = MockDoc(dict(email=new_user_email))
        mock_create_user.return_value = mock_user

        # --- Act ---
        auth.validate()

        # --- Assert ---
        mock_jwt.decode.assert_called_once()
        mock_create_user.assert_called_once_with(decoded_payload, self.mock_jwt_idp)
        auth.frappe.set_user.assert_called_once_with(new_user_email)
