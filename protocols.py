import asyncio
import logging
import re
import hmac
import time
from typing import Callable
import urllib.request

import misc

logger = logging.getLogger(__name__)  # for logging purposes
logging.basicConfig(level=logging.DEBUG)


class NoTransport(Exception):
    def __init__(self, msg="No transport has been initialized", *args):
        super().__init__(msg, *args)

    pass


class CustomProtocol(asyncio.DatagramProtocol):
    # bufsize = 1024

    def __init__(self,
                 parent: object,
                 ip: str, port: int, passw: str,
                 on_con_lost: asyncio.Future,
                 write_callback: Callable,
                 *args, **kwargs):
        """
        :param parent: Parent of this object. Use to call parent's methods where applicable
        :type parent: object
        :param ip: IPv4 address used to connect to a remote host.
        :type ip: str
        :param port: Port used by remote host.
        :type port: int
        :param passw: RCON password of the remote host.
        :type passw: str
        :param on_con_lost: asyncio Future object. Don't touch it I don't know what it does
        :type on_con_lost: asyncio.Future
        :param write_callback: An async callback function to schedule a task with.
                               Should take a chat message argument as a string.
        :type write_callback: typing.Callable
        :param args: Further args passed to parent of CustomProtocol inheritance-wise asyncio.DatagramProtocol
        :param kwargs: Further keyword args passed to parent of CustomProtocol inheritance-wise asyncio.DatagramProtocol

        """
        super().__init__(*args, **kwargs)
        self.parent = parent
        self.ip, self.port, self.passw = ip, port, passw
        self.on_con_lost = on_con_lost
        self.callback = write_callback

        self.transport = None

        self.challenge = {}
        self.encoding = 'utf-8'
        return

    def connection_made(self, transport):
        self.transport = transport
        logger.info("Successfully set up a datagram endpoint "
                    + str(self.transport.get_extra_info('sockname'))
                    + " to "
                    + str(self.transport.get_extra_info('peername')))

        port = self.transport.get_extra_info('sockname')[1]

        logger.info("Setting " + misc.chat_dest_command + "...")
        self.rcon(misc.chat_dest_command
                  + "{}:{}".format(
                    str(urllib.request.urlopen(misc.url_check_public_ip).read().decode().strip()),
                    int(port)))
        return

    def connection_lost(self, exc: Exception):
        if exc:
            logger.error(exc)
        else:
            logger.info("Closed an endpoint "
                        + str(self.transport.get_extra_info('sockname'))
                        + " to "
                        + str(self.transport.get_extra_info('peername')))
            return

    def error_received(self, exc: Exception):
        if exc:
            logger.error(exc)
        else:
            return

    def datagram_received(self, data: bytes, addr):
        if re.match(rb"^" + misc.header, data):
            data = re.sub(rb"^" + misc.header, b'', data)

            if re.match(rb"^" + misc.rcon_response, data):
                data = re.sub(rb"^" + misc.rcon_response, b'', data)
                logger.debug("Received rcon response " + data.decode().strip())  # comment our or set debug lvl higher to avoid spam

            elif re.match(rb"^" + misc.ingame_chat, data):
                data = re.sub(rb"^" + misc.ingame_chat, b'', data)
                logger.debug("Received in-game chat message " + data.decode().strip())  # like above
                asyncio.create_task(self.callback(data.decode()))

            elif re.match(rb"^" + misc.challenge, data):
                logger.info("Received challenge " + data.decode())
                self.challenge = data

            else:
                logger.warning("Incoming datagram hasn't matched any patterns")
                print(data)
        else:
            logger.warning("Encountered a packet with a non-Quake header")
            return

    def construct_getchallenge(self) -> bytes:
        return misc.header + misc.getchallenge

    def send_getchallenge(self) -> None:
        if self.transport:
            getchallenge = self.construct_getchallenge()
            self.transport.sendto(getchallenge)
        else:
            logger.error(NoTransport)
            return

    def parse_challenge(self, challenge: bytes) -> bytes:
        return challenge[len(misc.header + misc.challenge):len(misc.header + misc.challenge) + 11]

    def construct_secure_time(self, command: str) -> bytes:
        """
        Constructs a secure time-based rcon packet to send to a remote host.
        :param command: A command to send to the remote host.
        :type command: str
        :return: Body of secure time-based packet for the rcon protocol.
        """
        tm = time.time()
        cmdplustime = "{:6f} {}".format(tm, command)

        hm = hmac.new(bytes(self.passw, self.encoding), bytes(cmdplustime, self.encoding), 'md4').digest()

        return misc.header + misc.secure_time + hm + b' ' + bytes(cmdplustime, self.encoding)

    def construct_secure_challenge(self, command: str) -> None:
        """
        Constructs a secure challenge-based RCON packet to send to a remote host.
        :param command: A command to send to the remote host.
        :type command: str
        :return: Body of secure challenge-based packet for the rcon protocol.
        """
        raise NotImplementedError  # todo

    def rcon(self, command: str) -> bool:
        """
        Sends an RCON command to a remote host.
        :param command: A command to send to the remote host.
        :type command: str
        :return: True or false based on success.
        """
        if self.transport:
            self.transport.sendto(self.construct_secure_time(command))  # asynchronous
        else:
            logger.error(NoTransport)
            return False
        return True
