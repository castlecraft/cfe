import unittest
from unittest.mock import MagicMock, patch

from castlecraft import auth
from tests.conftest import MockDoc


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
        mock_frappe.db.get_value.return_value = True

        # --- Act ---
        created_user = auth.create_and_save_user(token_payload, idp_config)

        # --- Assert ---
        self.assertEqual(created_user, mock_user_doc)
        self.assertEqual(mock_user_doc.email, "test.user@example.com")
        self.assertEqual(mock_user_doc.first_name, "Test")
        self.assertEqual(mock_user_doc.full_name, "Test User")

        self.assertEqual(mock_user_doc.append.call_count, 2)
        mock_user_doc.append.assert_any_call("roles", {"role": "Blogger"})
        mock_user_doc.append.assert_any_call("roles", {"role": "Website Manager"})

        mock_claims_doc.append.assert_called_once_with(
            "claims", {"claim": "custom_claim", "value": "custom_value"}
        )
        mock_user_doc.save.assert_called_once()
        mock_claims_doc.save.assert_called_once()
        mock_frappe.db.commit.assert_called_once()
