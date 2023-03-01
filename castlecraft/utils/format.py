import frappe


def respond_error(error_string=None, error_code=None):
    error_string = error_string or "Internal Server Error"
    error_code = error_code or 500

    frappe.local.response = frappe._dict(
        {
            "error": error_string,
            "description": frappe.scrub(error_string),
            "status_code": error_code,
        }
    )
    frappe.local.response["http_status_code"] = error_code

    return
