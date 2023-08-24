import base64
import datetime
import json
import traceback

import frappe
import jwt
import requests
from requests.auth import HTTPBasicAuth


def validate():
    """
    Additional validation to execute along with frappe request
    """
    authorization_header = frappe.get_request_header(
        "Authorization", ""
    ).split(  # noqa: E501
        " "
    )  # noqa: E501
    if len(authorization_header) == 2:
        token = authorization_header[1]
        if frappe.get_conf().get("castlecraft_auth_introspect_bearer_enabled"):
            validate_bearer_with_introspection(token)
        elif frappe.get_conf().get(
            "castlecraft_auth_jwt_verify_bearer_enabled"
        ):  # noqa: E501
            validate_bearer_with_jwt_verification(token)


def validate_bearer_with_introspection(token):
    """
    Validates access_token by using introspection endpoint
    Caches the token up to expiry for reuse
    """
    is_valid = False
    email = None

    cached_token = get_cached_bearer_token(token)
    now = datetime.datetime.now()
    form_dict = frappe.local.form_dict
    token_response = {}

    try:
        if cached_token:
            token_json = json.loads(cached_token)
            exp = token_json.get("exp")
            email = frappe.get_value(
                "User",
                token_json.get(
                    frappe.get_conf().get(
                        "castlecraft_email_key",
                        "email",
                    ),
                ),
                "email",
            )
            if exp:
                exp = datetime.datetime.fromtimestamp(
                    int(
                        token_json.get("exp"),
                    ),
                )
            else:
                exp = now

            if now < exp and email:
                token_response = token_json
                is_valid = True
            else:
                delete_cached_bearer_token(token)

        else:
            client_id = frappe.get_conf().get("castlecraft_client_id")
            client_secret = frappe.get_conf().get("castlecraft_client_secret")
            introspect_url = frappe.get_conf().get(
                "castlecraft_introspect_url"
            )  # noqa: E501
            introspect_token_key = frappe.get_conf().get(
                "castlecraft_introspect_token_key", "token"
            )
            auth_header_enabled = frappe.get_conf().get(
                "castlecraft_auth_header_enabled"
            )
            auth = None
            if not introspect_url:
                return

            if auth_header_enabled and client_id and client_secret:
                auth = HTTPBasicAuth(client_id, client_secret)

            data = {}
            data[introspect_token_key] = token
            r = requests.post(
                introspect_url,
                data=data,
                auth=auth,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            token_response = r.json()
            exp = token_response.get("exp")

            if exp:
                exp = datetime.datetime.fromtimestamp(
                    int(
                        token_response.get("exp"),
                    )
                )
            else:
                exp = now + datetime.timedelta(
                    0, int(token_response.get("expires_in")) or 0
                )

            if now < exp:
                email = frappe.get_value(
                    "User",
                    token_response.get(
                        frappe.get_conf().get("castlecraft_email_key", "email")
                    ),
                    "email",
                )
                if email and token_response.get(
                    frappe.get_conf().get("castlecraft_email_key", "email")
                ):
                    cache_bearer_token(token, token_response, exp, now)
                    cache_user_from_sub(
                        token_response.get("sub"),
                        json.dumps({"email": email, "token": token}),
                    )
                    is_valid = True

        if frappe.get_conf().get(
            "castlecraft_create_user_on_auth_enabled"
        ) and not frappe.db.exists("User", email):
            user_data = token_response

            if frappe.get_conf().get(
                "castlecraft_fetch_userinfo"
            ) and not frappe.db.exists("User", email):
                userinfo_url = frappe.get_conf().get(
                    "castlecraft_userinfo_url",
                )
                if not userinfo_url:
                    return
                r = requests.get(
                    userinfo_url,
                    headers={"Authorization": f"Bearer {token}"},
                )
                user_data = r.json()

            user = create_and_save_user(user_data)
            email = user.email
            cache_bearer_token(token, token_response, exp, now)
            cache_user_from_sub(
                token_response.get("sub"),
                json.dumps({"email": email, "token": token}),
            )
            is_valid = True

        if is_valid:
            frappe.set_user(email)
            frappe.local.form_dict = form_dict

    except Exception:
        frappe.log_error(
            traceback.format_exc(),
            "castlecraft_bearer_auth_failed",
        )


def validate_bearer_with_jwt_verification(token):
    is_valid = False
    try:
        form_dict = frappe.local.form_dict
        now = datetime.datetime.now()
        b64_jwt_header, b64_jwt_body, b64_jwt_signature = token.split(".")
        body = get_b64_decoded_json(b64_jwt_body)
        email = frappe.get_value(
            "User",
            body.get(frappe.get_conf().get("castlecraft_email_key", "email")),
            "email",
        )
        cached_token = get_cached_jwt(email)

        if cached_token and cached_token == token:
            (
                cached_b64_jwt_header,
                cached_b64_jwt_body,
                cached_b64_jwt_signature,
            ) = cached_token.split(".")
            body = get_b64_decoded_json(cached_b64_jwt_body)
            exp = datetime.datetime.fromtimestamp(int(body.get("exp")))
            is_valid = True if now < exp else False

        if not is_valid:
            delete_cached_jwt(email)
            payload = validate_signature(token)

            if email:
                cache_jwt(
                    email,
                    token,
                    datetime.datetime.fromtimestamp(int(body.get("exp"))),
                    now,
                )
                cache_user_from_sub(
                    payload.get("sub"),
                    json.dumps({"email": email, "token": token}),
                )
                is_valid = True

            elif frappe.get_conf().get(
                "castlecraft_create_user_on_auth_enabled"
            ) and body.get(
                frappe.get_conf().get("castlecraft_email_key", "email")
            ):  # noqa: E501
                user = create_and_save_user(body)
                email = user.email
                cache_jwt(
                    email,
                    token,
                    datetime.datetime.fromtimestamp(int(payload.get("exp"))),
                    now,
                )
                cache_user_from_sub(
                    payload.get("sub"),
                    json.dumps({"email": email, "token": token}),
                )
                is_valid = True

        if is_valid:
            frappe.set_user(email)
            frappe.local.form_dict = form_dict

    except Exception:
        frappe.log_error(traceback.format_exc(), "castlecraft_jwt_auth_failed")


def create_and_save_user(body):
    """
    Create new User and save based on response
    """
    first_name_claim = frappe.get_conf().get(
        "castlecraft_first_name_key",
        "given_name",
    )
    full_name_claim = frappe.get_conf().get(
        "castlecraft_full_name_key",
        "name",
    )
    email = body.get(
        frappe.get_conf().get("castlecraft_email_key", "email")
    )  # noqa: E501
    user = frappe.new_doc("User")
    user.name = user.email = email
    user.first_name = body.get(
        first_name_claim,
        body.get(
            full_name_claim,
            email,
        ),
    )
    user.full_name = body.get(full_name_claim, email)
    if body.get("phone_number_verified"):
        user.phone = body.get("phone_number")

    for role in frappe.get_conf().get("castlecraft_default_roles", []):
        if frappe.db.get_value("Role", role, "name"):
            user.append("roles", {"role": role})

    user.flags.ignore_permissions = 1
    user.flags.no_welcome_mail = True
    user.save()
    frappe.db.commit()

    return user


def get_padded_b64str(b64string):
    return b64string + "=" * (-len(b64string) % 4)


def get_b64_decoded_json(b64str):
    return json.loads(
        base64.b64decode(get_padded_b64str(b64str)).decode("utf-8")
    )  # noqa: E501


def validate_signature(token):
    r = requests.get(frappe.get_conf().get("castlecraft_jwks_url"))  # noqa: E501
    jwks_keys = r.json()
    keys = jwks_keys.get("keys")
    public_keys = {}
    for jwk in keys:
        kid = jwk["kid"]
        public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(
            json.dumps(jwk)
        )  # noqa: E501

    kid = jwt.get_unverified_header(token)["kid"]
    key = public_keys[kid]

    return jwt.decode(
        get_padded_b64str(token),
        key=key,
        algorithms=["RS256"],
        audience=frappe.get_conf().get("castlecraft_allowed_aud", []),
    )


def get_cached_bearer_token(token: str):
    return frappe.cache().get_value(f"cc_bearer|{token}")


def get_cached_jwt(email: str):
    return frappe.cache().get_value(f"cc_jwt|{email}")


def get_cached_user_from_sub(sub):
    payload = None
    if sub:
        payload = frappe.cache().get_value(f"cc_sub|{sub}")
    return json.loads(payload) if payload else {}


def cache_user_from_sub(sub: str, payload: str):
    if sub and payload:
        frappe.cache().set_value(f"cc_sub|{sub}", payload)


def cache_bearer_token(
    token: str,
    token_response: dict,
    exp: datetime,
    now: datetime,
):
    frappe.cache().set_value(
        f"cc_bearer|{token}",
        json.dumps(token_response),
        expires_in_sec=exp - now,
    )


def cache_jwt(
    email: str,
    token: str,
    exp: datetime,
    now: datetime,
):
    frappe.cache().set_value(
        f"cc_jwt|{email}",
        token,
        expires_in_sec=exp - now,
    )


def delete_cached_bearer_token(token: str):
    frappe.cache().delete_key(f"cc_bearer|{token}")


def delete_cached_jwt(email: str):
    frappe.cache().delete_key(f"cc_jwt|{email}")
