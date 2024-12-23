# client.py
import json
from enum import Enum
from typing import Tuple

# Global size constants
USER_ID_LENGTH_BYTES = 16
AES_KEY_SIZE_BYTES = 16
MAX_USERNAME_SIZE = 255
MAX_FILENAME_SIZE = 255
PUBLIC_KEY_SIZE_BYTES = 160
CHECKSUM_SIZE_BYTES = 16
CURRENT_VERSION_NUMBER = 3


################################## Request parsing ##################################

class ClientRequestCodes(Enum):
    RegisterRequest = 1100
    VerifyCodeRequest = 1101
    LoginRequest = 1102
    AesKeyExchange = 1103
    SendAES = 1104
    SendMsgToOfflineUser = 1105


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


def encode_request(request_code: Enum, payload: dict) -> str:
    """
    Encodes a request into a JSON string.
    Works for both client requests and server responses.
    """
    return json.dumps({
        "request_code": request_code.value,
        "payload": payload
    })


def decode_request(request: str, request_enum: Enum) -> Tuple[Enum, dict]:
    """
    Decodes a request from a JSON string.
    Works for both client requests and server responses.

    :param request: JSON-encoded string
    :param request_enum: The Enum class to use for decoding (either ClientRequestCodes or ServerResponseCodes)
    :return: Tuple of request code and payload
    """
    try:
        data = json.loads(request)
        print("data:", data)
        request_code = request_enum(data["request_code"])
        payload = data.get("payload", {})
        return request_code, payload
    except (KeyError, ValueError):
        raise ValueError("Invalid request format.")


# Convenience functions for more specific use cases
def encode_client_request(request_code: ClientRequestCodes, payload: dict) -> str:
    return encode_request(request_code, payload)


def encode_server_response(response_code: ServerResponseCodes, payload: dict = None) -> str:
    return encode_request(response_code, payload or {})


def decode_client_request(request: str) -> Tuple[ClientRequestCodes, dict]:
    return decode_request(request, ClientRequestCodes)  # type: ignore


def decode_server_response(response: str) -> Tuple[ServerResponseCodes, dict]:
    return decode_request(response, ServerResponseCodes)  # type: ignore
