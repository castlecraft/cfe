from urllib.parse import urlparse

import frappe
from frappe.installer import update_site_config

from castlecraft.utils.format import respond_error


@frappe.whitelist(methods=["GET"])
def get_allowed_cors_uris():
    """
    Returns list of allowed domains for System Manager Role

    Method: GET

    Parameters: None

    Path: /api/method/castlecraft.services.settings.get_allowed_cors_uris

    Error: 403

    Response:

    ```
    {
            "message": [
                    "https://app.example.com",
            ]
    }
    ```
    """

    if "System Manager" not in frappe.get_roles():
        return respond_error("Not Permitted", 403)

    return frappe.get_conf().get("allow_cors", [])


@frappe.whitelist(methods=["POST"])
def set_cors_uri(cors_uri=None):
    """
    Returns list of allowed domains for System Manager Role

    Method: POST

    Parameters: cors_uri [string] Valid URL. e.g. http://localhost:8000

    Path: /api/method/castlecraft.services.settings.set_cors_uri

    Error: 403

    Response:

    ```
    {
            "message": [
                    "https://app.example.com",
                    "http://localhost:8000"
            ]
    }
    ```
    """

    if "System Manager" not in frappe.get_roles():
        return respond_error("Not Permitted", 403)

    if not cors_uri:
        return respond_error("Invalid cors_uri", 400)

    if not frappe.utils.validate_url(cors_uri):
        return respond_error("Invalid cors_uri", 400)

    cors_uri = urlparse(cors_uri)
    cors_uri = f"{cors_uri.scheme}://{cors_uri.netloc}"
    allow_cors = frappe.get_conf().get("allow_cors", [])
    if cors_uri not in allow_cors:
        allow_cors.append(cors_uri)
        update_site_config("allow_cors", allow_cors)

    return allow_cors


@frappe.whitelist(methods=["POST"])
def unset_cors_uri(cors_uri=None):
    """
    Returns list of allowed domains for System Manager Role

    Method: POST

    Parameters: cors_uri [string] Valid URL. e.g. http://localhost:8000

    Path: /api/method/castlecraft.services.settings.unset_cors_uri

    Error: 403

    Response:

    ```
    {
            "message": [
                    "https://app.example.com"
            ]
    }
    ```
    """

    if "System Manager" not in frappe.get_roles():
        return respond_error("Not Permitted", 403)

    if not cors_uri:
        return respond_error("Invalid cors_uri", 400)

    allow_cors = frappe.get_conf().get("allow_cors", [])
    if cors_uri in allow_cors:
        allow_cors.remove(cors_uri)
        update_site_config("allow_cors", allow_cors)

    return allow_cors
