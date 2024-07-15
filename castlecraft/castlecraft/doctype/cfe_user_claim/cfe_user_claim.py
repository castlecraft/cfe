# Copyright (c) 2024, Castlecraft Ecommerce Pvt. Ltd. and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class CFEUserClaim(Document):
    pass


def has_permission(doc, user=None):
    user = user or frappe.session.user
    return doc.user == user or "System Manager" in frappe.get_roles()


def get_permission_query_conditions(user):
    if not user:
        user = frappe.session.user

    if "System Manager" in frappe.get_roles():
        return None

    return f"""(`tabCFE User Claim`.user = {frappe.db.escape(user)})"""
