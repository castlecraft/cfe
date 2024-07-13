from . import __version__

app_name = "castlecraft"
app_title = "Castlecraft"
app_publisher = "Castlecraft Ecommerce Pvt. Ltd."
app_description = "Castlecraft Frappe Extensions"
app_icon = "octicon octicon-file-directory"
app_color = "grey"
app_email = "support@castlecraft.in"
app_license = "MIT"
app_version = __version__

auth_hooks = ["castlecraft.auth.validate"]

has_permission = {
    "CFE User Claim": "castlecraft.castlecraft.doctype.cfe_user_claim.cfe_user_claim.has_permission",  # noqa: E501
}

override_whitelisted_methods = {
    "frappe.integrations.oauth2.openid_profile": "castlecraft.services.oauth2.openid_profile",  # noqa: E501
}

permission_query_conditions = {
    "CFE User Claim": "castlecraft.castlecraft.doctype.cfe_user_claim.cfe_user_claim.get_permission_query_conditions",  # noqa: E501
}
