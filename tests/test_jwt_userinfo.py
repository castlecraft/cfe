import time
import unittest
from unittest.mock import MagicMock, patch

from castlecraft import auth
from tests.conftest import MockDoc


class TestJWTUserInfo(unittest.TestCase):
    def setUp(self):
        self.test_user_email = "test@example.com"
        self.access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiaWF0IjoxNTE2MjM5MDIyLCJhdWQiOiJ0ZXN0LWF1ZGllbmNlIn0.signature_part"  # noqa: E501
        self.mock_jwt_idp = MockDoc(
            dict(
                doctype="CFE Identity Provider",
                authorization_type="JWT Verification",
                email_key="email",
                create_user=True,
                fetch_user_info=True,
                profile_endpoint="https://idp.example.com/userinfo",
                jwks_endpoint="https://idp.example.com/.well-known/jwks.json",
                audience_claim_key="aud",
                allowed_audience=[MockDoc(dict(aud="test-audience"))],
            )
        )

    @patch(
        "castlecraft.auth.frappe.get_value"
    )  # Mock frappe.get_value for pre-validation
    @patch("castlecraft.auth.requests")
    @patch("castlecraft.auth.jwt")
    @patch("castlecraft.auth.request_user_info")
    @patch("castlecraft.auth.get_b64_decoded_json")
    @patch("castlecraft.auth.get_idp")
    def test_jwt_with_userinfo_existing_user(
        self,
        mock_get_idp,
        mock_b64_decode,
        mock_request_user_info,
        mock_jwt,
        mock_requests,
        mock_get_value,
    ):
        """Test JWT with userinfo for an existing user."""
        # --- Arrange ---
        auth.frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_jwt_idp
        # After userinfo is fetched, the user is found
        mock_get_value.return_value = self.test_user_email

        jwt_payload = {
            "sub": "user-sub-123",
            "exp": time.time() + 3600,
            "aud": "test-audience",
            "email": self.test_user_email,  # Ensure email is in payload for frappe.get_value
        }
        # Mock the internal dependencies of validate_signature
        mock_requests.get.return_value.json.return_value = {
            "keys": [{"kid": "test-kid"}]
        }
        mock_jwt.get_unverified_header.return_value = {"kid": "test-kid"}
        mock_jwt.algorithms.RSAAlgorithm.from_jwk.return_value = MagicMock()
        mock_jwt.decode.return_value = jwt_payload
        userinfo_payload = {"email": self.test_user_email, "name": "Test User"}
        mock_b64_decode.return_value = jwt_payload
        mock_request_user_info.return_value = userinfo_payload

        # --- Act ---
        auth.validate()

        # --- Assert ---
        # JWT is always validated first
        mock_jwt.decode.assert_called_once()
        mock_request_user_info.assert_called_once_with(
            self.access_token, self.mock_jwt_idp
        )
        auth.frappe.set_user.assert_called_once_with(self.test_user_email)

    @patch("castlecraft.auth.requests")
    @patch(
        "castlecraft.auth.frappe.get_value"
    )  # Mock frappe.get_value for pre-validation
    @patch("castlecraft.auth.jwt")
    @patch("castlecraft.auth.create_and_save_user")
    @patch("castlecraft.auth.request_user_info")
    @patch("castlecraft.auth.get_b64_decoded_json")
    @patch("castlecraft.auth.get_idp")
    def test_jwt_with_userinfo_new_user_creation(
        self,
        mock_get_idp,
        mock_b64_decode,  # Corrected order
        mock_request_user_info,
        mock_create_user,
        mock_jwt,
        mock_get_value,
        mock_requests,
    ):
        """Test JWT with userinfo creates a new user."""
        # --- Arrange ---
        auth.frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_jwt_idp
        # After userinfo is fetched, user is not found, triggering creation
        mock_get_value.return_value = None

        jwt_payload = {
            "sub": "new-user-sub-456",
            "exp": time.time() + 3600,
            "aud": "test-audience",
            "email": self.test_user_email,  # Ensure email is in payload for frappe.get_value
        }
        # Mock the internal dependencies of validate_signature
        mock_requests.get.return_value.json.return_value = {
            "keys": [{"kid": "test-kid"}]
        }
        mock_jwt.get_unverified_header.return_value = {"kid": "test-kid"}
        mock_jwt.algorithms.RSAAlgorithm.from_jwk.return_value = MagicMock()
        mock_jwt.decode.return_value = jwt_payload
        userinfo_payload = {"email": self.test_user_email, "given_name": "New"}
        mock_b64_decode.return_value = jwt_payload
        mock_request_user_info.return_value = userinfo_payload

        mock_user = MockDoc(dict(email=self.test_user_email))
        mock_create_user.return_value = mock_user

        # --- Act ---
        auth.validate()

        # --- Assert ---
        mock_jwt.decode.assert_called_once()
        mock_request_user_info.assert_called_once()
        # When creating a user from userinfo, only the userinfo payload is passed
        mock_create_user.assert_called_once_with(userinfo_payload, self.mock_jwt_idp)
        auth.frappe.set_user.assert_called_once_with(self.test_user_email)
