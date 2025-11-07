import datetime
import json
import unittest
from unittest.mock import MagicMock, patch

from castlecraft import auth
from tests.conftest import MockDoc  # Import MockDoc from conftest


class TestAuthIntrospection(unittest.TestCase):
    def setUp(self):
        self.test_user_email = "test@example.com"
        self.access_token = "valid-token-123"

        self.mock_idp = MockDoc(
            dict(
                doctype="CFE Identity Provider",
                idp_name="test-idp",
                enabled=1,
                authorization_type="Introspection",
                email_key="email",
                introspection_endpoint="https://idp.example.com/introspect",
                token_key="token",
                auth_header_enabled=1,
                client_id="test-client",
                client_secret="test-secret",
                create_user=False,
                fetch_user_info=False,
                profile_endpoint="https://idp.example.com/userinfo",
                user_roles=[],
            )
        )

    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.requests")
    def test_introspection_valid_uncached_token_existing_user(
        self, mock_requests, mock_get_idp
    ):
        """
        Test `validate_bearer_with_introspection` with a valid,
        uncached token for an existing user.
        """
        # --- Arrange ---
        auth.frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp
        auth.frappe.db.exists.return_value = True

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
        mock_requests.post.assert_called_once_with(
            self.mock_idp.introspection_endpoint,
            data={"token": self.access_token},
            auth=unittest.mock.ANY,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        auth.frappe.set_user.assert_called_once_with(self.test_user_email)
        auth.frappe.cache().set_value.assert_called()

    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.requests")
    def test_introspection_valid_cached_token(self, mock_requests, mock_get_idp):
        """
        Test introspection with a valid,
        cached token to ensure it bypasses HTTP requests.
        """
        # --- Arrange ---
        auth.frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp

        cached_payload = {
            "active": True,
            "email": self.test_user_email,
            "sub": "user-subject-123",
            "exp": (datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp(),
        }
        auth.frappe.cache().get_value.return_value = json.dumps(cached_payload)
        auth.frappe.db.exists.return_value = True

        # --- Act ---
        auth.validate()

        # --- Assert ---
        mock_requests.post.assert_not_called()
        auth.frappe.set_user.assert_called_once_with(self.test_user_email)

    @patch("castlecraft.auth.create_and_save_user")
    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.requests")
    def test_introspection_new_user_creation(
        self, mock_requests, mock_get_idp, mock_create_user
    ):
        """
        Test introspection with a valid token for a
        non-existent user when `create_user` is enabled.
        """
        # --- Arrange ---
        self.mock_idp.create_user = True
        new_user_email = "new.user@example.com"

        auth.frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp
        auth.frappe.db.exists.return_value = False

        mock_response = MagicMock()
        introspection_payload = {
            "active": True,
            "email": new_user_email,
            "sub": "new-user-sub-456",
            "exp": (datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp(),
        }
        mock_response.json.return_value = introspection_payload
        mock_requests.post.return_value = mock_response

        mock_user = MockDoc(dict(email=new_user_email))
        mock_create_user.return_value = mock_user

        # --- Act ---
        auth.validate()

        # --- Assert ---
        mock_requests.post.assert_called_once()
        mock_create_user.assert_called_once_with(introspection_payload, self.mock_idp)
        auth.frappe.set_user.assert_called_once_with(new_user_email)

    @patch("castlecraft.auth.create_and_save_user")
    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.requests")
    def test_introspection_with_fetch_user_info(
        self, mock_requests, mock_get_idp, mock_create_user
    ):
        """Test introspection with `fetch_user_info` enabled for a new user."""
        # --- Arrange ---
        self.mock_idp.create_user = True
        self.mock_idp.fetch_user_info = True
        new_user_email = "another.new.user@example.com"

        auth.frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp
        auth.frappe.db.exists.return_value = False

        introspection_response = MagicMock()
        introspection_response.json.return_value = {
            "active": True,
            "sub": "another-sub-789",
            "exp": (datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp(),
        }

        userinfo_response = MagicMock()
        userinfo_payload = {
            "email": new_user_email,
            "given_name": "Another",
            "family_name": "User",
        }
        userinfo_response.json.return_value = userinfo_payload

        mock_requests.post.return_value = introspection_response
        mock_requests.get.return_value = userinfo_response

        mock_user = MockDoc(dict(email=new_user_email))
        mock_create_user.return_value = mock_user

        # --- Act ---
        auth.validate()

        # --- Assert ---
        mock_requests.post.assert_called_once_with(
            self.mock_idp.introspection_endpoint,
            data=unittest.mock.ANY,
            auth=unittest.mock.ANY,
            headers=unittest.mock.ANY,
        )
        mock_requests.get.assert_called_once_with(
            self.mock_idp.profile_endpoint,
            headers={"Authorization": f"Bearer {self.access_token}"},
        )
        mock_create_user.assert_called_once_with(userinfo_payload, self.mock_idp)
        auth.frappe.set_user.assert_called_once_with(new_user_email)

    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.requests")
    def test_introspection_inactive_token(self, mock_requests, mock_get_idp):
        """Test introspection with a token that is inactive."""
        # --- Arrange ---
        auth.frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp

        mock_response = MagicMock()
        introspection_payload = {"active": False}
        mock_response.json.return_value = introspection_payload
        mock_requests.post.return_value = mock_response

        # --- Act ---
        auth.validate()

        # --- Assert ---
        mock_requests.post.assert_called_once()
        auth.frappe.set_user.assert_not_called()

    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.requests")
    def test_introspection_new_user_creation_disabled(
        self, mock_requests, mock_get_idp
    ):
        """Test auth fails for a new user when `create_user` is disabled."""
        # --- Arrange ---
        self.mock_idp.create_user = False
        auth.frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp
        auth.frappe.db.exists.return_value = False

        mock_response = MagicMock()
        introspection_payload = {
            "active": True,
            "email": "new.user@example.com",
            "exp": (datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp(),
        }
        mock_response.json.return_value = introspection_payload
        mock_requests.post.return_value = mock_response

        # --- Act ---
        auth.validate()

        # --- Assert ---
        mock_requests.post.assert_called_once()
        auth.frappe.set_user.assert_not_called()
