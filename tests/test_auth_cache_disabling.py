import datetime
import json
import unittest
from unittest.mock import MagicMock, patch

from castlecraft import auth
from tests.conftest import MockDoc


class TestAuthCacheDisabling(unittest.TestCase):
    def setUp(self):
        self.test_user_email = "test@example.com"
        self.access_token = "valid-token-123"

    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.requests")
    def test_introspection_cache_disabled(self, mock_requests, mock_get_idp):
        """
        Verify that introspection bypasses cache and doesn't store in cache
        when is_cache_disabled is set.
        """
        # --- Arrange ---
        mock_idp = MockDoc(
            dict(
                doctype="CFE Identity Provider",
                idp_name="test-idp",
                enabled=1,
                is_cache_disabled=1,  # CACHE DISABLED
                authorization_type="Introspection",
                email_key="email",
                introspection_endpoint="https://idp.example.com/introspect",
                token_key="token",
                auth_header_enabled=1,
                client_id="test-client",
                client_secret="test-secret",
                create_user=False,
                fetch_user_info=False,
                user_roles=[],
            )
        )
        auth.frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = mock_idp
        auth.frappe.db.exists.return_value = True

        # Even if there is a cached token, it should be ignored
        auth.frappe.cache().get_value.return_value = json.dumps(
            {
                "active": True,
                "email": self.test_user_email,
                "exp": (
                    datetime.datetime.now() + datetime.timedelta(hours=1)
                ).timestamp(),
            }
        )

        mock_response = MagicMock()
        mock_response.status_code = 200
        introspection_payload = {
            "active": True,
            "email": self.test_user_email,
            "sub": "user-subject-123",
            "exp": (datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp(),
        }
        mock_response.json.return_value = introspection_payload
        mock_requests.post.return_value = mock_response

        # --- Act ---
        auth.validate()

        # --- Assert ---
        # 1. Ensure it still made a request (meaning it didn't use the cache)
        mock_requests.post.assert_called_once()

        # 2. Ensure it didn't call get_value on cache (though my implementation skips it)
        # Actually, if it skips it, get_value won't be called.
        auth.frappe.cache().get_value.assert_not_called()

        # 3. Ensure it didn't try to SAVE to cache
        auth.frappe.cache().set_value.assert_not_called()

        auth.frappe.set_user.assert_called_once_with(self.test_user_email)

    @patch("castlecraft.auth.requests")
    @patch("castlecraft.auth.frappe.get_value")
    @patch("castlecraft.auth.jwt")
    @patch("castlecraft.auth.get_idp")
    def test_jwt_cache_disabled(
        self, mock_get_idp, mock_jwt, mock_get_value, mock_requests
    ):
        """
        Verify that JWT verification bypasses cache and doesn't store in cache
        when is_cache_disabled is set.
        """
        # --- Arrange ---
        mock_jwt_idp = MockDoc(
            dict(
                doctype="CFE Identity Provider",
                authorization_type="JWT Verification",
                is_cache_disabled=1,  # CACHE DISABLED
                email_key="email",
                create_user=False,
                fetch_user_info=False,
                jwks_endpoint="https://idp.example.com/.well-known/jwks.json",
                audience_claim_key="aud",
                allowed_audience=[MockDoc(dict(aud="test-audience"))],
            )
        )
        auth.frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = mock_jwt_idp
        mock_get_value.return_value = self.test_user_email

        jwt_payload = {
            "sub": "user-sub-123",
            "exp": datetime.datetime.now().timestamp() + 3600,
            "aud": "test-audience",
            "email": self.test_user_email,
        }

        # Even if there is a cached payload, it should be ignored
        auth.frappe.cache().get_value.return_value = json.dumps(jwt_payload)

        # Mock the internal dependencies of validate_signature
        mock_requests.get.return_value.json.return_value = {
            "keys": [{"kid": "test-kid"}]
        }
        mock_jwt.get_unverified_header.return_value = {"kid": "test-kid"}
        mock_jwt.algorithms.RSAAlgorithm.from_jwk.return_value = MagicMock()
        mock_jwt.decode.return_value = jwt_payload

        # --- Act ---
        auth.validate()

        # --- Assert ---
        # 1. Ensure it still decoded the JWT (meaning it didn't use the cache)
        mock_jwt.decode.assert_called_once()

        # 2. Ensure it didn't call get_value on cache
        auth.frappe.cache().get_value.assert_not_called()

        # 3. Ensure it didn't try to SAVE to cache
        auth.frappe.cache().set_value.assert_not_called()

        auth.frappe.set_user.assert_called_once_with(self.test_user_email)
