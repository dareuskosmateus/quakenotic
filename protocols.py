import asyncio
import logging
import re
import hmac
import time
from functools import wraps
from typing import Callable
import urllib.request

import misc

logger = logging.getLogger(__name__)  # for logging purposes
logging.basicConfig(level=logging.DEBUG)


class NoTransport(Exception):
    def __init__(self, identifier="", msg="No transport has been initialized", *args):
        super().__init__(identifier + msg, *args)

    pass


class Conn(object):
    instances = []
    """Wrapper class for transport/protocol of async."""
    def __init__(self, parent: object, transport: asyncio.Transport, protocol: asyncio.Protocol):
        Conn.instances.append(self)

        self.parent = parent
        self.transport, self.protocol = transport, protocol

    def __del__(self):
        Conn.instances.remove(self)

class Query(object):
    def __init__(self, identifier, event, data, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.identifier, self.event, self.data = identifier, event, data


class XonoticProtocol(asyncio.DatagramProtocol):
    # bufsize = 1024

    def __init__(self,
                 parent: object,
                 ip: str, port: int, passw: str,
                 on_con_lost: asyncio.Future,
                 write_callback: Callable,
                 *args, security=misc.Security.RCON_SECURE_TIME, **kwargs):
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

        self.challenge = None
        self.encoding = 'utf-8'

        self.security = security

        self.queries = []
        return

    @property
    def identifier(self):
        """Identifier to help keep track which object issued a log message."""
        return "<{}>:{} ".format(str(hex(id(self))), str(self.transport.get_extra_info('sockname')))

    @staticmethod
    def if_transport(func):
        @wraps(func)
        def wrap(self, *args, **kwargs):
            if self.transport is None:
                raise NoTransport(self.identifier)
            return func(self, *args, **kwargs)

        return wrap

    @staticmethod
    def querying(func):
        @wraps(func)
        async def wrap(self, challenge, *args, **kwargs):
            query = Query(challenge, asyncio.Event(), bytearray())
            self.queries.append(query)
            await func(self, challenge, *args, **kwargs)
            await query.event.wait()
            self.queries.remove(query)
            return query.data
        return wrap

    def connection_made(self, transport):
        self.transport = transport

        logger.info(self.identifier + "Successfully set up a datagram endpoint to "
                    + str(self.transport.get_extra_info('peername')))

        port = self.transport.get_extra_info('sockname')[1]

        logger.info(self.identifier + "Setting " + misc.chat_dest_command + "...")
        self.rcon(misc.chat_dest_command
                  + "{}:{}".format(
            str(urllib.request.urlopen(misc.url_check_public_ip).read().decode().strip()),
            int(port)))
        return

    def connection_lost(self, exc: Exception):
        if exc:
            logger.error(self.identifier + exc)
        else:
            logger.info(self.identifier + "Closed an endpoint to "
                        + str(self.transport.get_extra_info('peername')))
            return

    def error_received(self, exc: Exception):
        if exc:
            logger.error(self.identifier + exc)
        else:
            return

    def datagram_received(self, data: bytes, addr):
        if re.match(rb"^" + misc.header, data):
            data = re.sub(rb"^" + misc.header, b'', data)

            if re.match(rb"^" + misc.rcon_response, data):
                data = re.sub(rb"^" + misc.rcon_response, b'', data)
                logger.debug(self.identifier
                             + "Received rcon response "
                             + data.decode().strip())  # comment our or set debug lvl higher to avoid spam


            elif re.match(rb"^" + misc.challenge, data):
                logger.info(self.identifier + "Received challenge " + data.decode())
                self.challenge = data

            elif re.match(rb"^" + misc.statusresponse, data):
                logger.info(self.identifier + "Received status response " + data.decode())
                data = re.sub(rb"^" + misc.statusresponse, b'', data)
                self.handle_query_response(data)
                pass
                # print to interested parties

            elif re.match(rb"^" + misc.inforesponse, data):
                logger.info(self.identifier + "Received info response " + data.decode())
                data = re.sub(rb"^"+ misc.inforesponse, b'', data)
                self.handle_query_response(data)
                # whatever

            elif re.match(rb"^" + misc.ingame_chat, data):
                data = re.sub(rb"^" + misc.ingame_chat, b'', data)
                logger.debug(self.identifier + "Received in-game chat message " + data.decode().strip())  # like above
                asyncio.create_task(self.callback(self.parent, data.decode()))

            else:
                logger.warning(self.identifier + "Incoming datagram hasn't matched any patterns")
                print(data)
        else:
            logger.warning(self.identifier + "Encountered a packet with a non-Quake header")
            return

    def construct_getchallenge(self) -> bytes:
        return misc.header + misc.getchallenge

    @if_transport
    @querying
    def send_getchallenge(self, challenge="") -> None:
        """Sends a challenge issue request to remote host."""
        getchallenge = self.construct_getchallenge()
        self.transport.sendto(getchallenge)
        return

    def parse_challenge(self, challenge: bytes) -> bytes:
        return challenge[len(misc.header + misc.challenge):len(misc.header + misc.challenge) + 11]  # don't touch the 11

    def construct(self, command: str) -> bytes:
        """
        Constructs a ready to use rcon packet.
        :param command: Command to be sent to remote host.
        :type command: str
        :return: bytes packet ready to send.
        """
        match self.security:
            case misc.Security.RCON_SECURE_TIME:
                return self.construct_secure_time(command)
            case misc.Security.RCON_SECURE_CHALLENGE:
                return self.construct_secure_challenge(command)
            case misc.Security.RCON_INSECURE:
                return self.construct_insecure(command)
            case _:
                logger.error(self.identifier + "Construct called but no security has been set")
                return

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

    def construct_insecure(self, command: str):
        """
        Returns insecure barebytes rcon packet. Server doesn't respond unless it has set `rcon_secure 0`.
        :param command: A command to send to the remote host.
        :type command: str
        :return: Body of unsecure rcon protocoled packet.
        """
        return misc.header + misc.insecure + self.passw + command

    @if_transport
    def rcon(self, command: str):
        """
        Sends an RCON command to a remote host.
        :param command: A command to send to the remote host.
        :type command: str
        :return: True or false based on success.
        """
        logger.debug(self.identifier + "Sent rcon command " + command)
        self.transport.sendto(self.construct(command))  # asynchronous
        # return await response

    @if_transport
    async def keepalive(self):
        """Keeps the system from closing this socket"""
        logger.debug(self.identifier + "Keepalive sent")
        self.transport.sendto(misc.keepalive)
        # return await response?

    @if_transport
    @querying
    async def request_status(self, challenge: bytes):
        """
        Requests status from remote host.
        :param challenge: identifier to identify response packet with. Doesn't have to be server issued challenge,
        can be anything.
        :type challenge: bytes
        :return: None. Decorator creates a query object.
        """
        logger.debug(self.identifier + "Requested status")
        self.transport.sendto(misc.header + misc.getstatus + challenge)
        return

    @if_transport
    @querying
    async def request_info(self, challenge: bytes):
        """
        Requests info according to https://discourse.ioquake.org/t/how-to-get-server-status-with-python/1135
        Doesn't seem to be doing anything different than getstatus. I left it in
        :param challenge: identifier to identify response packet with. Doesn't have to be server issued challenge,
        can be anything.
        :type challenge: bytes
        :return: None. Decorator creates a query object.
        """
        logger.debug(self.identifier + "Requested info")
        self.transport.sendto(misc.header + misc.getinfo + challenge)
        return

    @if_transport
    def handle_query_response(self, data: bytes): # this is a bit slow
        """
        Parses raw bytes response into a dictionary

        :param data: bytes data from remote host.
        :return: None
        """
        challenge = re.findall(b'\\\challenge\\\([a-zA-Z]+)', data)
        for query in self.queries:
            if challenge[0] == query.identifier:

                parsed = re.findall(b'(\\\+[A-Za-z0-9_ :.!]+\\\+[A-Za-z0-9_ :.!]+)', data) # change it so it doesnt pick up the challenge
                keyvalues = {}

                for pair in parsed:
                    split = pair.split(b"\\")
                    keyvalues.update({split[1]:split[2]})

                players = re.findall(rb'([^\n]+[A-Za-z0-9" -]+[^\n])', re.sub(b'(\\\+[A-Za-z0-9_ :.!/-@+\-\"\^]+\\\+[A-Za-z0-9_ :.!/-@+\-\"\^]+)', b'', data))
                keyvalues.update({b'players' : players})

                query.data = keyvalues
                query.event.set()
                return
