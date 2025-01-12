# constants.py

# Server configuration
HOST = "127.0.0.1"
PORT = 12345
MAX_CLIENTS = 10

SERVER_PUBLIC_KEY = b"""-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAoUibKE1c+9HkG8mSdAJ8
fRBhRsQtJIGtXrSFANN/bGcaLZbQIld3XfnSuD6AfaTTQMYo7cjJz+QbTBBWud3C
xsyr2XMOD4qZ5F6LdK8ydysMPNstGukA+xep3dMUHQiEl4xb6nL/yQ/E6Y16fQ+k
xZCGHTg15CGu6zly9A2DjQLMpB3PF4UYOg3mhtQyPIxiX4XtVQpxGXbqN75+KqUP
HlE/kbkvrMjzc0rS5k1FFvoGYv8DJMXPlFUYUtQv8uS6EMV6C24rjXMJlYh/R3YZ
5s+sGzHFIi7qE/tyXrLZn8o01cGmzP1FNJfWOOKBKePD/14kLJnvOEuzpv3goPvj
EwIDAQAB
-----END PUBLIC KEY-----"""

# Security
RSA_KEY_SIZE = 2048
RSA_CHUNK_SIZE = 190  # For 2048-bit RSA

# Global size constants
SERVER_RESPONSE_SIZE = 23
CLIENT_REQUEST_SIZE = 22

# UI
DEFAULT_PRINT = '\033[0m'
FAILURE_PRINT = '\033[31m'
SUCCESS_PRINT = '\033[32m'
INPUT_COLOR = '\033[36m'
INBOX_EMPTY_COLOR = '\033[37m'
INBOX_NOT_EMPTY_COLOR = '\033[92m'

ITALIC = '\033[3m'
BOLD = '\033[1m'
UNDERLINE = '\033[4m'
RESET_STYLE = '\033[0m'
COMMUNICATION_PRINT = '\033[36m'
