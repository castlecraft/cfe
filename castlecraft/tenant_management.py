import requests
import frappe
import json

from json import JSONDecodeError
from frappe import _

from castlecraft.exceptions import BadGatewayError, NotImplementedError

def create_tenant(
	firm_name,
	number_of_users = 5,
	storage_space_in_gb = 0,
	checklist_library_access = "Limited",
	audit_file_print_service = "Flexible",
	email_trail_and_trigger = "Exclude",
):
	return client_tenant_post_request("/api/client/tenant/v1/add", None, {
		"firm_name": firm_name,
		"number_of_users": number_of_users,
		"storage_space_in_gb": storage_space_in_gb,
		"checklist_library_access": checklist_library_access,
		"audit_file_print_service": audit_file_print_service,
		"email_trail_and_trigger": email_trail_and_trigger,
	})


def fetch_tenant(uuid):
	return client_tenant_get_request("/api/client/tenant/v1/fetch/"+uuid)


def remove_tenant(uuid):
	return client_tenant_post_request("/api/client/tenant/v1/remove/"+uuid)


def update_tenant(
	uuid,
	firm_name,
	number_of_users,
	storage_space_in_gb,
	checklist_library_access,
	audit_file_print_service,
	email_trail_and_trigger,
):
	data = {
		"uuid": uuid,
		"firm_name": firm_name,
		"number_of_users": number_of_users,
		"storage_space_in_gb": storage_space_in_gb,
		"checklist_library_access": checklist_library_access,
		"audit_file_print_service": audit_file_print_service,
		"email_trail_and_trigger": email_trail_and_trigger,
	}
	return client_tenant_post_request("/api/client/tenant/v1/update", None, data)


def list_tenants(
	uuid = None,
	firm_name = None,
	created_by_id = None,
	created_by_actor = None,
	sort = None,
	offset = 0,
	limit = 10,
):
	query = "&"

	if uuid:
		query += "uuid=" + uuid

	if firm_name:
		query += "firm_name=" + firm_name

	if created_by_id:
		query += "createdById=" + created_by_id

	if created_by_actor:
		query += "createdByActor=" + created_by_actor

	if sort:
		query += "sort=" + sort

	return client_tenant_get_request(
		"/api/client/tenant/v1/list?limit=" + str(limit) + "&offset=" + str(offset) + query,
	)


def client_tenant_post_request(endpoint, server_url=None, data=None):
	connected_app = get_connected_app()
	token = connected_app.get_client_token()
	if not server_url:
		server_url = get_admin_server_url()
	response = requests.post(
		server_url + endpoint,
		data=data,
		headers={"Authorization": "Bearer " + token.get_password("access_token")}
	)
	return process_response(response)


def client_tenant_get_request(endpoint, server_url = None):
	connected_app = get_connected_app()
	token = connected_app.get_client_token()
	if not server_url:
		server_url = get_admin_server_url()
	response = requests.get(
		server_url + endpoint,
		headers={"Authorization": "Bearer " + token.get_password("access_token")}
	)
	return process_response(response)


def get_connected_app():
	connected_app = frappe.get_conf().get("castlecraft_connected_app")

	if not connected_app:
		frappe.throw(_("Please set connected_app in site_config.json"))

	return frappe.get_doc("Connected App", connected_app)


def process_response(response):
	reason = response.reason
	try:
		if getattr(response, 'json', None):
			reason = response.json()
		if response.status_code < 300 and response.status_code > 199:
			return response.json()
	except JSONDecodeError:
		return {
			"status_code": response.status_code,
			"reason": reason,
		}

	frappe.throw("Bad Gateway Error: " + json.dumps(reason), BadGatewayError(reason))


def get_admin_server_url():
	admin_server_url = frappe.get_conf().get("castlecraft_admin_server_url")

	if not admin_server_url:
		raise NotImplementedError(_("castlecraft_admin_server_url not set in site_config.json"))

	return admin_server_url


def get_auth_server():
	auth_server_url = frappe.get_conf().get("castlecraft_auth_server_url")

	if not auth_server_url:
		raise NotImplementedError(_("castlecraft_auth_server_url not set in site_config.json"))

	return auth_server_url


def get_user_by_phone_or_email(email):
	return client_tenant_get_request("/user/v1/fetch_for_trusted_client/"+email, get_auth_server())


def add_tenant_user(email, tenant_id):
	user = get_user_by_phone_or_email(email)
	return client_tenant_post_request(
		"/api/client/tenant/user/v1/add",
		None,
		{ "user": user.get("uuid"), "tenant": tenant_id},
	)


def remove_tenant_user(email, tenant_id):
	user = get_user_by_phone_or_email(email)
	return client_tenant_post_request(
		"/api/client/tenant/user/v1/remove",
		None,
		{ "user": user.get("uuid"), "tenant": tenant_id},
	)
