import traceback

import frappe
from frappe.exceptions import DoesNotExistError
from frappe.oauth import get_userinfo

from castlecraft.auth import get_enabled_idp, get_userinfo_from_idp
from castlecraft.utils.format import respond_error

from castlecraft.auth import (  # isort: skip
    delete_cached_bearer_token,
    delete_cached_jwt,
    get_cached_user_from_sub,
    validate_signature,
)


@frappe.whitelist()
def openid_profile():
    """
    Overridden userinfo endpoint to validate only session user
    """
    user = frappe.get_doc("User", frappe.session.user)
    userinfo = frappe._dict(get_userinfo(user))
    user_claim = {}
    try:
        user_claim = frappe.get_cached_doc("CFE User Claim", user.name)
    except DoesNotExistError:
        pass

    for claim in user_claim.get("claims", []):
        userinfo[claim.claim] = claim.value
    frappe.local.response = userinfo


@frappe.whitelist(allow_guest=True)
def back_channel_logout(logout_token=None):
    """
    Back channel logout endpoint to logout sub
    """
    error_string = "castlecraft_backchannel_logout_failed"

    if not logout_token:
        respond_error(error_string, 400)

    try:
        verified_token = validate_signature(logout_token)
        if verified_token.get("sub"):
            payload = get_cached_user_from_sub(verified_token.get("sub"))
            email = payload.get("email")
            token = payload.get("token")
            if email:
                delete_cached_jwt(email)
            if token:
                delete_cached_bearer_token(token)
    except Exception:
        frappe.log_error(traceback.format_exc(), error_string)
        respond_error(error_string, 400)


@frappe.whitelist(methods=["POST"])
def sync_claims():
    """
    Sync user claims from Identity Provider

    Method: POST

    Parameters: None

    Path: /api/method/castlecraft.services.oauth2.sync_claims

    Error: 403 or 417

    Response: CFE User Claim

    """

    authorization_header = frappe.get_request_header(  # noqa: E501
        "Authorization", ""
    ).split(" ")

    if len(authorization_header) == 2:
        token = authorization_header[1]
        idp = get_enabled_idp()
        idp_user_claims = get_userinfo_from_idp(token, idp)
        idp_claim_map = [field.claim for field in idp.user_fields]
        claims = []
        for claim in idp_claim_map:
            claims.append(
                {
                    "claim": claim,
                    "value": idp_user_claims.get(claim),
                }
            )

        user = frappe.get_doc("User", frappe.session.user)
        user_claim = None
        try:
            user_claim = frappe.get_doc("CFE User Claim", user.name)
        except DoesNotExistError:
            user_claim = frappe.get_doc({"doctype": "CFE User Claim"})
        user_claim.set("claims", claims)
        user_claim.save(ignore_permissions=True)
        return user_claim.as_dict()
