import unittest
from unittest.mock import MagicMock, patch

from castlecraft import auth
from tests.conftest import MockDoc


class TestJWTInvalid(unittest.TestCase):
    def setUp(self):
        self.access_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiaWF0IjoxNTE2MjM5MDIyLCJhdWQiOiJ0ZXN0LWF1ZGllbmNlIn0.another_invalid_signature_part"  # noqa: E501
        self.mock_jwt_idp = MockDoc(
            dict(
                doctype="CFE Identity Provider",
                authorization_type="JWT Verification",
                jwks_endpoint="https://idp.example.com/.well-known/jwks.json",
                fetch_user_info=False,  # Set to False to force JWT decoding path
                profile_endpoint="https://idp.example.com/userinfo",
                audience_claim_key="aud",
                allowed_audience=[MockDoc(dict(aud="test-audience"))],
            )
        )

    @patch(
        "castlecraft.auth.frappe.get_value", return_value=None
    )  # Ensure no user is found in pre-validation
    @patch("castlecraft.auth.requests")
    @patch("castlecraft.auth.jwt")
    @patch("castlecraft.auth.get_idp")
    def test_jwt_verification_invalid_signature(
        self, mock_get_idp, mock_jwt, mock_requests, mock_get_value
    ):
        """Test JWT verification fails with an invalid signature."""
        # --- Arrange --- Use a valid-looking JWT structure for the token
        jwt_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InRlc3Qta2lkIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJ0ZXN0QGV4YW1wbGUuY29tIiwiaWF0IjoxNTE2MjM5MDIyLCJhdWQiOiJ0ZXN0LWF1ZGllbmNlIn0.another_invalid_signature_part"  # noqa: E501
        auth.frappe.get_request_header.return_value = f"Bearer {jwt_token}"
        mock_get_idp.return_value = self.mock_jwt_idp

        # Mock the internal calls of validate_signature to simulate failure
        mock_requests.get.return_value.json.return_value = {
            "keys": [{"kid": "test-kid"}]
        }
        mock_jwt.get_unverified_header.return_value = {"kid": "test-kid"}
        mock_jwt.algorithms.RSAAlgorithm.from_jwk.return_value = MagicMock()
        mock_jwt.decode.side_effect = Exception("Invalid signature")

        with patch("castlecraft.auth.get_b64_decoded_json"):
            # --- Act ---
            auth.validate()

        # --- Assert ---
        auth.frappe.set_user.assert_not_called()

    @patch(
        "castlecraft.auth.frappe.get_value", return_value=None
    )  # Ensure no user is found in pre-validation
    @patch("castlecraft.auth.requests")
    @patch("castlecraft.auth.jwt")
    @patch("castlecraft.auth.request_user_info")
    @patch("castlecraft.auth.get_idp")
    def test_jwt_with_userinfo_invalid_signature(
        self,
        mock_get_idp,
        mock_request_user_info,
        mock_jwt,
        mock_requests,
        mock_get_value,
    ):
        """Test flow fails if JWT signature is invalid before userinfo call."""
        # --- Arrange ---
        # For this test, we need to simulate an IdP that *does* fetch user info.
        # We must explicitly reconstruct the MockDoc to ensure all attributes are present.
        mock_jwt_idp_with_userinfo = MockDoc(
            dict(
                doctype=self.mock_jwt_idp.doctype,
                authorization_type=self.mock_jwt_idp.authorization_type,
                jwks_endpoint=self.mock_jwt_idp.jwks_endpoint,
                fetch_user_info=True,
                profile_endpoint=self.mock_jwt_idp.profile_endpoint,
                audience_claim_key=self.mock_jwt_idp.audience_claim_key,
                allowed_audience=self.mock_jwt_idp.allowed_audience,
            )
        )
        auth.frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = mock_jwt_idp_with_userinfo

        # Mock the internal calls of validate_signature to simulate failure
        mock_requests.get.return_value.json.return_value = {
            "keys": [{"kid": "test-kid"}]
        }
        mock_jwt.get_unverified_header.return_value = {"kid": "test-kid"}
        mock_jwt.algorithms.RSAAlgorithm.from_jwk.return_value = MagicMock()
        mock_jwt.decode.side_effect = Exception("Invalid signature")

        # --- Act ---
        auth.validate()

        # --- Assert ---
        mock_jwt.decode.assert_called_once()
        mock_request_user_info.assert_not_called()
        auth.frappe.set_user.assert_not_called()
