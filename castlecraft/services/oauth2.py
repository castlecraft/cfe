import frappe
from frappe.oauth import get_userinfo


@frappe.whitelist()
def openid_profile():
    """
    Overridden userinfo endpoint to validate only session user
    """
    user = frappe.get_doc("User", frappe.session.user)
    frappe.local.response = frappe._dict(get_userinfo(user))
