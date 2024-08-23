from enum import Enum

"""Misc stuff needed to construct packets"""

url_check_public_ip = "https://checkip.amazonaws.com"

chat_dest_command = "chat_dest_udp "

keepalive = b'keepalive'
header = b'\xFF' * 4
rcon_response = b"n"
ingame_chat = b""
getchallenge = b"getchallenge"
challenge = b"challenge"
secure_time = b"srcon HMAC-MD4 TIME "
secure_challenge = b"srcon HMAC-MD4 CHALLENGE "


class Security(Enum):
    RCON_INSECURE = 0
    RCON_TIME_SECURE = 1
    RCON_SECURE = 2
