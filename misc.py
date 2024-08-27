from enum import Enum

"""Misc stuff needed to construct packets"""

url_check_public_ip = "https://checkip.amazonaws.com"

chat_dest_command = "chat_dest_udp "

keepalive = b'keepalive'
header = b'\xFF' * 4

rcon_response = b"n"
ingame_chat = b""

getchallenge = b"getchallenge "
getstatus = b"getstatus "
getinfo = b"getinfo "

statusresponse = b"statusResponse\n"
inforesponse = b"infoResponse\n"

challenge = b"challenge"
insecure = b"rcon "
secure_time = b"srcon HMAC-MD4 TIME "
secure_challenge = b"srcon HMAC-MD4 CHALLENGE "

identifier = b"@Xon//"


class Security(Enum):
    RCON_INSECURE = 0
    RCON_SECURE_TIME = 1
    RCON_SECURE_CHALLENGE = 2
