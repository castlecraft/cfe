# Copyright (c) 2024, Castlecraft Ecommerce Pvt. Ltd. and contributors
# For license information, please see license.txt

import frappe
from frappe.model.document import Document


class CFEIdentityProvider(Document):
    def validate(self):
        self.validate_existing_idp()

    def validate_existing_idp(self):
        if self.enabled:
            enabled_idp = next(
                iter(
                    frappe.get_all(
                        self.doctype,
                        filters=[["enabled", "=", 1]],
                    )
                ),
                None,
            )
            if enabled_idp and enabled_idp.name != self.name:
                frappe.throw(
                    frappe._(
                        "{idp} already enabled".format(
                            idp=enabled_idp.get("name"),
                        ),
                    ),
                )

    def on_trash(self):
        if self.enabled:
            frappe.throw(frappe._("Cannot delete enabled Identity Provider"))
