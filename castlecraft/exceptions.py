class BadGatewayError(Exception):
	http_status_code = 502

class NotImplementedError(Exception):
	http_status_code = 501
