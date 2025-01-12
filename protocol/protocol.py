# protocol.py

from enum import Enum
import json


################################## Request parsing ##################################

class ClientRequestCodes(Enum):
    RegisterRequest = 1100
    VerifyCodeRequest = 1101
    LoginRequest = 1102
    SendMsgToUser = 1103
    GetUserPublicKey = 1104
    DisconnectRequest = 1105
    GetAllMessages = 1106
    GetMessagesFromUser = 1107


################################## Response builders ##################################

class ServerResponseCodes(Enum):
    RegistrationSuccess = 2100
    RegistrationFailed = 2101
    SendRegistrationCode = 2102
    VerificationFailed = 2103
    LoginSuccess = 2104
    LoginFailed = 2105
    UserOffline = 2106
    UserNotFound = 2107
    SendingMessageToUser = 2108
    UserAlreadyRegistered = 2109
    WrongUserData = 2110
    SendLoginCode = 2111
    ReadReceipt = 2112
    UpdatePendingMessages = 2113


################################## Protocol Helper Functions ##################################

def encode_client_request(payload):
    return json.dumps({
        "payload": payload
    }).encode("utf-8")


def decode_client_request(request: str):
    if not request:
        raise ValueError("not request ....... Invalid client request format: Request is empty or not a string.")
    elif not isinstance(request, str):
        raise ValueError("not isinstance .......... Invalid client request format: Request is empty or not a string.")
    try:
        data = json.loads(request)
        payload = data.get("payload", {})
        if not isinstance(payload, dict):
            raise ValueError("Invalid payload format.")
        return payload
    except (KeyError, ValueError, json.JSONDecodeError) as e:
        raise ValueError(f"Invalid client request format: {e}")


def encode_client_request_code(request_code):
    return json.dumps({
        "request_code": request_code.value
    }).encode("utf-8")


def decode_client_request_code(request: str) -> ClientRequestCodes:
    try:
        data = json.loads(request)
        request_code = data.get("request_code", {})
        return request_code
    except (KeyError, ValueError):
        raise ValueError("Invalid server response format.")


def encode_server_response(payload):
    if payload is None:
        payload = {}
    return json.dumps({
        "payload": payload
    }).encode("utf-8")


def decode_server_response(response: str) -> dict:
    try:
        data = json.loads(response)
        payload = data.get("payload", {})
        return payload
    except (KeyError, ValueError):
        raise ValueError("Invalid server response format.")


def encode_server_response_code(response_code):
    return json.dumps({
        "response_code": response_code.value
    }).encode("utf-8")


def decode_server_response_code(response: str) -> ServerResponseCodes:
    try:
        data = json.loads(response)
        response_code = data.get("response_code", {})
        return response_code
    except (KeyError, ValueError):
        raise ValueError("Invalid server response format.")
