import time
import unittest
from unittest.mock import MagicMock, patch

from castlecraft import auth
from tests.conftest import MockDoc


class TestJWTExistingUser(unittest.TestCase):
    def setUp(self):
        self.test_user_email = "test@example.com"
        self.mock_jwt_idp = MockDoc(
            dict(
                doctype="CFE Identity Provider",
                authorization_type="JWT Verification",
                email_key="email",
                jwks_endpoint="https://idp.example.com/.well-known/jwks.json",
                fetch_user_info=False,  # Ensure this is a JWT-only flow
                audience_claim_key="aud",
                allowed_audience=[MockDoc(dict(aud="test-audience"))],
            )
        )

    @patch("castlecraft.auth.requests")
    @patch(
        "castlecraft.auth.frappe.get_value"
    )  # Mock frappe.get_value for pre-validation
    @patch("castlecraft.auth.jwt")
    @patch("castlecraft.auth.get_b64_decoded_json")
    @patch("castlecraft.auth.get_idp")
    def test_jwt_verification_existing_user(
        self, mock_get_idp, mock_b64_decode, mock_jwt, mock_get_value, mock_requests
    ):
        """Test JWT verification with a valid token for an existing user."""
        # --- Arrange --- Use a valid-looking JWT structure for the token
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiaWF0IjoxNTE2MjM5MDIyLCJhdWQiOiJ0ZXN0LWF1ZGllbmNlIn0.signature_part"  # noqa: E501
        auth.frappe.get_request_header.return_value = f"Bearer {jwt_token}"
        mock_get_idp.return_value = self.mock_jwt_idp

        # Reset side_effect for this specific test to ensure isolation
        auth.frappe.get_value.reset_mock()
        mock_get_value.return_value = self.test_user_email

        decoded_payload = {
            "email": self.test_user_email,
            "exp": time.time() + 3600,
            "aud": "test-audience",
            "sub": "jwt-user-sub",
        }
        mock_b64_decode.return_value = decoded_payload

        # Mock the internal dependencies of validate_signature
        mock_requests.get.return_value.json.return_value = {
            "keys": [{"kid": "test-kid"}]
        }
        mock_jwt.get_unverified_header.return_value = {"kid": "test-kid"}
        mock_jwt.algorithms.RSAAlgorithm.from_jwk.return_value = MagicMock()
        mock_jwt.decode.return_value = decoded_payload

        # --- Act ---
        auth.validate()

        # --- Assert ---
        mock_jwt.decode.assert_called_once()
        auth.frappe.set_user.assert_called_once_with(self.test_user_email)
        auth.frappe.cache().set_value.assert_called()
