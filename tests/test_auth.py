import datetime
import json
import time
import unittest
from unittest.mock import MagicMock, patch

from castlecraft import auth


class MockDoc(dict):
    """A mock object that simulates a Frappe DocType using a dictionary."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.__dict__ = self

    def get_password(self, key):
        return self.get(key)


class TestAuth(unittest.TestCase):
    def setUp(self):
        # This will hold mock objects for patching
        self.mocks = {}

        # Common test data
        self.test_user_email = "test@example.com"
        self.access_token = "valid-token-123"

        # Mock IDP configuration for Introspection
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

        # Mock IDP configuration for JWT Verification
        self.mock_jwt_idp = MockDoc(
            dict(
                doctype="CFE Identity Provider",
                idp_name="jwt-idp",
                enabled=1,
                authorization_type="JWT Verification",
                email_key="email",
                create_user=False,
                jwks_endpoint="https://idp.example.com/.well-known/jwks.json",
                allowed_audience=[MockDoc(dict(aud="test-audience"))],
            )
        )

    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.frappe")
    @patch("castlecraft.auth.requests")
    def test_introspection_valid_uncached_token_existing_user(
        self, mock_requests, mock_frappe, mock_get_idp
    ):
        """
        Test `validate_bearer_with_introspection` with a valid,
        uncached token for an existing user.
        """
        # --- Arrange ---

        # 1. Mock the main `validate` function's dependencies
        mock_frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp

        # 2. Mock introspection-specific dependencies
        # Simulate cache miss
        mock_frappe.cache().get_value.return_value = None
        # Simulate existing user using the correct method
        mock_frappe.db.exists.return_value = True

        # 3. Mock the external HTTP request to the introspection endpoint
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

        # Assert that an HTTP POST request was
        # made to the introspection endpoint
        mock_requests.post.assert_called_once_with(
            self.mock_idp.introspection_endpoint,
            data={"token": self.access_token},
            # HTTPBasicAuth is tricky to assert directly
            auth=unittest.mock.ANY,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )

        # Assert that the user session was set in Frappe
        mock_frappe.set_user.assert_called_once_with(self.test_user_email)

        # Assert that the token was cached after successful validation
        mock_frappe.cache().set_value.assert_called()

    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.frappe")
    @patch("castlecraft.auth.requests")
    def test_introspection_valid_cached_token(
        self, mock_requests, mock_frappe, mock_get_idp
    ):
        """
        Test introspection with a valid,
        cached token to ensure it bypasses HTTP requests.
        """
        # --- Arrange ---
        mock_frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp

        # Simulate cache hit with a valid, non-expired token payload
        cached_payload = {
            "active": True,
            "email": self.test_user_email,
            "sub": "user-subject-123",
            "exp": (datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp(),
        }
        mock_frappe.cache().get_value.return_value = json.dumps(cached_payload)
        # This test should also rely on db.exists for consistency
        mock_frappe.db.exists.return_value = True

        # --- Act ---
        auth.validate()

        # --- Assert ---
        # Assert that NO external HTTP request was made
        mock_requests.post.assert_not_called()

        # Assert that the user session was set
        mock_frappe.set_user.assert_called_once_with(self.test_user_email)

    @patch("castlecraft.auth.create_and_save_user")
    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.frappe")
    @patch("castlecraft.auth.requests")
    def test_introspection_new_user_creation(
        self, mock_requests, mock_frappe, mock_get_idp, mock_create_user
    ):
        """
        Test introspection with a valid token for a
        non-existent user when `create_user` is enabled.
        """
        # --- Arrange ---
        self.mock_idp.create_user = True
        new_user_email = "new.user@example.com"

        mock_frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp

        # Simulate cache miss and non-existent user
        mock_frappe.cache().get_value.return_value = None
        mock_frappe.db.exists.return_value = False

        # Mock introspection response
        mock_response = MagicMock()
        introspection_payload = {
            "active": True,
            "email": new_user_email,
            "sub": "new-user-sub-456",
            "exp": (datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp(),
        }
        mock_response.json.return_value = introspection_payload
        mock_requests.post.return_value = mock_response

        # Mock the user creation function to return a mock user
        mock_user = MockDoc(dict(email=new_user_email))
        mock_create_user.return_value = mock_user

        # --- Act ---
        auth.validate()

        # --- Assert ---
        mock_requests.post.assert_called_once()
        mock_create_user.assert_called_once_with(introspection_payload, self.mock_idp)
        mock_frappe.set_user.assert_called_once_with(new_user_email)

    @patch("castlecraft.auth.create_and_save_user")
    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.frappe")
    @patch("castlecraft.auth.requests")
    def test_introspection_with_fetch_user_info(
        self, mock_requests, mock_frappe, mock_get_idp, mock_create_user
    ):
        """Test introspection with `fetch_user_info` enabled for a new user."""
        # --- Arrange ---
        self.mock_idp.create_user = True
        self.mock_idp.fetch_user_info = True
        new_user_email = "another.new.user@example.com"

        mock_frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp
        mock_frappe.cache().get_value.return_value = None
        mock_frappe.db.exists.return_value = False

        # Mock introspection response (POST)
        introspection_response = MagicMock()
        introspection_response.json.return_value = {
            "active": True,
            "sub": "another-sub-789",
            "exp": (datetime.datetime.now() + datetime.timedelta(hours=1)).timestamp(),
        }

        # Mock userinfo response (GET)
        userinfo_response = MagicMock()
        userinfo_payload = {
            "email": new_user_email,
            "given_name": "Another",
            "family_name": "User",
        }
        userinfo_response.json.return_value = userinfo_payload

        # `requests` will be called twice: once for introspect (POST), once for userinfo (GET)
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
        # User creation should be called with the data from the userinfo endpoint
        mock_create_user.assert_called_once_with(userinfo_payload, self.mock_idp)
        mock_frappe.set_user.assert_called_once_with(new_user_email)

    @patch("castlecraft.auth.validate_signature")
    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.frappe")
    def test_jwt_verification_existing_user(
        self, mock_frappe, mock_get_idp, mock_validate_signature
    ):
        """Test JWT verification with a valid token for an existing user."""
        # --- Arrange ---
        jwt_token = "a.b.c"
        mock_frappe.get_request_header.return_value = f"Bearer {jwt_token}"
        mock_get_idp.return_value = self.mock_jwt_idp

        # Simulate cache miss and existing user
        mock_frappe.cache().get_value.return_value = None
        mock_frappe.get_value.return_value = self.test_user_email

        # Mock the b64decode and signature validation
        with patch("castlecraft.auth.get_b64_decoded_json") as mock_b64_decode:
            decoded_payload = {
                "email": self.test_user_email,
                "exp": time.time() + 3600,
                "aud": "test-audience",
                "sub": "jwt-user-sub",
            }
            mock_b64_decode.return_value = decoded_payload
            mock_validate_signature.return_value = decoded_payload

            # --- Act ---
            auth.validate()

        # --- Assert ---
        mock_validate_signature.assert_called_once_with(jwt_token, self.mock_jwt_idp)
        mock_frappe.set_user.assert_called_once_with(self.test_user_email)
        mock_frappe.cache().set_value.assert_called()

    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.frappe")
    @patch("castlecraft.auth.requests")
    def test_introspection_inactive_token(
        self, mock_requests, mock_frappe, mock_get_idp
    ):
        """Test introspection with a token that is inactive."""
        # --- Arrange ---
        mock_frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp
        mock_frappe.cache().get_value.return_value = None

        mock_response = MagicMock()
        introspection_payload = {"active": False}
        mock_response.json.return_value = introspection_payload
        mock_requests.post.return_value = mock_response

        # --- Act ---
        auth.validate()

        # --- Assert ---
        mock_requests.post.assert_called_once()
        mock_frappe.set_user.assert_not_called()

    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.frappe")
    @patch("castlecraft.auth.requests")
    def test_introspection_new_user_creation_disabled(
        self, mock_requests, mock_frappe, mock_get_idp
    ):
        """Test auth fails for a new user when `create_user` is disabled."""
        # --- Arrange ---
        self.mock_idp.create_user = False
        mock_frappe.get_request_header.return_value = f"Bearer {self.access_token}"
        mock_get_idp.return_value = self.mock_idp
        mock_frappe.cache().get_value.return_value = None
        mock_frappe.db.exists.return_value = False  # User does not exist

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
        mock_frappe.set_user.assert_not_called()

    @patch("castlecraft.auth.create_and_save_user")
    @patch("castlecraft.auth.validate_signature")
    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.frappe")
    def test_jwt_verification_new_user_creation(
        self, mock_frappe, mock_get_idp, mock_validate_signature, mock_create_user
    ):
        """Test JWT verification with user creation for a new user."""
        # --- Arrange ---
        self.mock_jwt_idp.create_user = True
        new_user_email = "new.jwt.user@example.com"
        jwt_token = "a.b.c"

        mock_frappe.get_request_header.return_value = f"Bearer {jwt_token}"
        mock_get_idp.return_value = self.mock_jwt_idp
        mock_frappe.cache().get_value.return_value = None
        mock_frappe.get_value.return_value = None  # User does not exist

        decoded_payload = {
            "email": new_user_email,
            "exp": time.time() + 3600,
            "aud": "test-audience",
        }

        with patch("castlecraft.auth.get_b64_decoded_json") as mock_b64_decode:
            mock_b64_decode.return_value = decoded_payload
            mock_validate_signature.return_value = decoded_payload
            mock_user = MockDoc(dict(email=new_user_email))
            mock_create_user.return_value = mock_user

            # --- Act ---
            auth.validate()

        # --- Assert ---
        mock_create_user.assert_called_once_with(decoded_payload, self.mock_jwt_idp)
        mock_frappe.set_user.assert_called_once_with(new_user_email)

    @patch("castlecraft.auth.validate_signature")
    @patch("castlecraft.auth.get_idp")
    @patch("castlecraft.auth.frappe")
    def test_jwt_verification_invalid_signature(
        self, mock_frappe, mock_get_idp, mock_validate_signature
    ):
        """Test JWT verification fails with an invalid signature."""
        # --- Arrange ---
        jwt_token = "a.b.c"
        mock_frappe.get_request_header.return_value = f"Bearer {jwt_token}"
        mock_get_idp.return_value = self.mock_jwt_idp
        mock_frappe.cache().get_value.return_value = None

        # Simulate signature validation failure
        mock_validate_signature.side_effect = Exception("Invalid signature")

        with patch("castlecraft.auth.get_b64_decoded_json"):
            # --- Act ---
            auth.validate()

        # --- Assert ---
        mock_frappe.set_user.assert_not_called()


class TestAuthHelpers(unittest.TestCase):
    @patch("castlecraft.auth.frappe")
    def test_get_idp_with_name(self, mock_frappe):
        """Test get_idp fetches a named IDP."""
        # --- Arrange ---
        idp_name = "specific-idp"

        # --- Act ---
        auth.get_idp(idp_name)

        # --- Assert ---
        mock_frappe.get_cached_doc.assert_called_once_with(
            "CFE Identity Provider", idp_name
        )
        mock_frappe.get_last_doc.assert_not_called()

    @patch("castlecraft.auth.frappe")
    def test_get_idp_default(self, mock_frappe):
        """Test get_idp fetches the default (last) IDP when no name is given."""
        # --- Arrange ---
        # --- Act ---
        auth.get_idp()

        # --- Assert ---
        mock_frappe.get_last_doc.assert_called_once_with(
            "CFE Identity Provider", filters={"enabled": 1}
        )
        mock_frappe.get_cached_doc.assert_not_called()

    @patch("castlecraft.auth.frappe")
    def test_create_and_save_user(self, mock_frappe):
        """Test create_and_save_user correctly maps claims and roles."""
        # --- Arrange ---
        idp_config = MockDoc(
            dict(
                email_key="email_address",
                first_name_key="given_name",
                full_name_key="name",
                user_roles=[
                    MockDoc(dict(role="Blogger")),
                    MockDoc(dict(role="Website Manager")),
                ],
                user_fields=[MockDoc(dict(claim="custom_claim"))],
            )
        )
        token_payload = {
            "email_address": "test.user@example.com",
            "given_name": "Test",
            "name": "Test User",
            "custom_claim": "custom_value",
        }

        mock_user_doc = MagicMock()
        mock_claims_doc = MagicMock()
        mock_frappe.new_doc.return_value = mock_user_doc
        mock_frappe.get_doc.return_value = mock_claims_doc
        # Simulate that the roles exist in the DB
        mock_frappe.db.get_value.return_value = True

        # --- Act ---
        created_user = auth.create_and_save_user(token_payload, idp_config)

        # --- Assert ---
        self.assertEqual(created_user, mock_user_doc)
        self.assertEqual(mock_user_doc.email, "test.user@example.com")
        self.assertEqual(mock_user_doc.first_name, "Test")
        self.assertEqual(mock_user_doc.full_name, "Test User")

        # Check that roles were appended
        self.assertEqual(mock_user_doc.append.call_count, 2)
        mock_user_doc.append.assert_any_call("roles", {"role": "Blogger"})
        mock_user_doc.append.assert_any_call("roles", {"role": "Website Manager"})

        # Check that custom claims were appended
        mock_claims_doc.append.assert_called_once_with(
            "claims", {"claim": "custom_claim", "value": "custom_value"}
        )
        mock_user_doc.save.assert_called_once()
        mock_claims_doc.save.assert_called_once()
        mock_frappe.db.commit.assert_called_once()
