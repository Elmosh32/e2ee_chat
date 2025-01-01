# protocol.py
import base64
import base64
import json
import random
import socket
from threading import Thread

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
# import json
# from enum import Enum
# from typing import Tuple
#
# # Global size constants
# USER_ID_LENGTH_BYTES = 16
# AES_KEY_SIZE_BYTES = 16
# MAX_USERNAME_SIZE = 255
# MAX_FILENAME_SIZE = 255
# PUBLIC_KEY_SIZE_BYTES = 160
# CHECKSUM_SIZE_BYTES = 16
# CURRENT_VERSION_NUMBER = 3
#
#
# ################################## Request parsing ##################################
#
# class ClientRequestCodes(Enum):
#     RegisterRequest = 1100
#     VerifyCodeRequest = 1101
#     LoginRequest = 1102
#     AesKeyExchange = 1103
#     SendAES = 1104
#     SendMsgToUser = 1105
#
#
# ################################## Response builders ##################################
#
# class ServerResponseCodes(Enum):
#     RegistrationSuccess = 2100
#     RegistrationFailed = 2101
#     SendRegistrationCode = 2102
#     VerificationSuccess = 2103
#     VerificationFailed = 2104
#     LoginSuccess = 2105
#     LoginFailed = 2106
#     SendAES = 2107
#     MessageOk = 2108
#     UserOnline = 2109
#     UserOffline = 2110
#
#
# def encode_request(request_code: Enum, payload: dict) -> str:
#     """
#     Encodes a request into a JSON string.
#     Works for both client requests and server responses.
#     """
#     return json.dumps({
#         "request_code": request_code.value,
#         "payload": payload
#     })
#
#
# def decode_request(request: str, request_enum: Enum) -> Tuple[Enum, dict]:
#     """
#     Decodes a request from a JSON string.
#     Works for both client requests and server responses.
#
#     :param request: JSON-encoded string
#     :param request_enum: The Enum class to use for decoding (either ClientRequestCodes or ServerResponseCodes)
#     :return: Tuple of request code and payload
#     """
#     try:
#         data = json.loads(request)
#         print("data:", data)
#         request_code = request_enum(data["request_code"])
#         payload = data.get("payload", {})
#         return request_code, payload
#     except (KeyError, ValueError):
#         raise ValueError("Invalid request format.")
#
#
# # Convenience functions for more specific use cases
# def encode_client_request(request_code: ClientRequestCodes, payload: dict) -> str:
#     return encode_request(request_code, payload)
#
#
# def encode_server_response(response_code: ServerResponseCodes, payload: dict = None) -> str:
#     return encode_request(response_code, payload or {})
#
#
# def decode_client_request(request: str) -> Tuple[ClientRequestCodes, dict]:
#     return decode_request(request, ClientRequestCodes)  # type: ignore
#
#
# def decode_server_response(response: str) -> Tuple[ServerResponseCodes, dict]:
#     return decode_request(response, ServerResponseCodes)  # type: ignore
#

from enum import Enum
from uuid import UUID
# from db import *
import json
from typing import Tuple

# Global size constants
USER_ID_LENGTH_BYTES = 16
AES_KEY_SIZE_BYTES = 16
MAX_USERNAME_SIZE = 255
MAX_FILENAME_SIZE = 255
PUBLIC_KEY_SIZE_BYTES = 160
CHECKSUM_SIZE_BYTES = 16
CURRENT_VERSION_NUMBER = 3


class File:
    def __init__(self, client_id, file_name, path, verified):
        self.verified = verified
        self.path = path
        self.file_name = file_name
        self.client_id = client_id


class Client:
    def __init__(self, client_id: UUID, name, public_key, last_seen, aes_key):
        self.client_id = client_id
        self.name = name
        self.public_key = public_key
        self.last_seen = last_seen
        self.aes_key = aes_key


################################## Request parsing ##################################

class ClientRequestCodes(Enum):
    RegisterRequest = 1100
    VerifyCodeRequest = 1101
    LoginRequest = 1102
    AesKeyExchange = 1103
    SendAES = 1104
    SendMsgToUser = 1105
    SendMsgToOfflineUser = 1106
    GetUserPublicKey = 1107


################################## Response builders ##################################

class ServerResponseCodes(Enum):
    RegistrationSuccess = 2100
    RegistrationFailed = 2101
    SendRegistrationCode = 2102
    VerificationSuccess = 2103
    VerificationFailed = 2104
    LoginSuccess = 2105
    LoginFailed = 2106
    SendAES = 2107
    MessageOk = 2108
    UserOnline = 2109
    UserOffline = 2110
    UserNotFound = 2111
    SendingUserPublicKey = 2112
    SendingMessageToUser = 2113
    UserSendsMessage = 2114


################################## Protocol Helper Functions ##################################

def encode_client_request(payload) -> str:
    return json.dumps({
        "payload": payload
    })


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
