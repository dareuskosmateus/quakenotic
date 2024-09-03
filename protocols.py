import asyncio
import re
import hmac
import time
import socket
from functools import wraps
from typing import Callable
import urllib.request

import logsetup
import misc

logger = logsetup.setup_log(__name__)  # for logging purposes


class NoTransport(Exception):
    def __init__(self, identifier="", msg="No transport has been initialized", *args):
        super().__init__(identifier + msg, *args)

    pass


class Conn(object):
    instances = []
    """Wrapper class for transport/protocol of async."""

    def __init__(self, parent: object, transport: asyncio.Transport = None, protocol: asyncio.Protocol = None):
        Conn.instances.append(self)

        self.parent = parent
        self.transport, self.protocol = transport, protocol

    def __del__(self):
        Conn.instances.remove(self)


class Query(object):
    def __init__(self, identifier, event, data):
        super().__init__()
        self.identifier, self.event, self.data = identifier, event, data


class Player(object):
    def __init__(self, name: str, *args):
        super().__init__()
        self.name, self.score, self.ping = name, args[0], args[1]
        self.team = Player.match_team(args[2]) if args[2] else ""

    @staticmethod
    def match_team(team: int):
        match int(team):
            case 0:
                return "Spec"
            case 1:
                return "Red"
            case 2:
                return "Blue"
        return


class GameProtocol(asyncio.DatagramProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    @staticmethod
    def if_transport(func):
        @wraps(func)  # allows access to args of func, and a bunch of other quality of life features
        def wrap(self, *args, **kwargs):
            if self.transport is None:
                raise NoTransport(self.identifier)
            return func(self, *args, **kwargs)

        return wrap

    @staticmethod
    def querying(default_challenge=None):  # decorator factory, returns decorator according to arguments
        def decorator(func):
            @wraps(func)  # allows access to args of func, and a bunch of other quality of life features
            async def wrap(self, challenge, *args, **kwargs):
                query = Query(challenge, asyncio.Event(), bytearray())
                self.queries.append(query)
                await func(self, challenge, *args, **kwargs)
                await query.event.wait()
                self.queries.remove(query)
                return query.data

            @wraps(func)
            async def default_wrap(self, *args, **kwargs):
                query = Query(default_challenge, asyncio.Event(), bytearray())
                self.queries.append(query)
                await func(self, *args, **kwargs)
                await query.event.wait()
                self.queries.remove(query)
                return query.data

            match default_challenge:
                case None:
                    return wrap
                case _:
                    return default_wrap

        return decorator

    def rcon(self):
        raise NotImplementedError("Implement this abstract method before usage")


class XonoticProtocol(GameProtocol):
    encoding = 'utf-8'

    def __init__(self,
                 parent: object,
                 ip: str, port: int, passw: str,
                 on_con_lost: asyncio.Future,
                 write_callback: Callable,
                 *args, security=misc.Security.RCON_INSECURE, **kwargs):
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

        self.security = security

        self.queries = []  # think of converting this into a quasi queue
        return

    @property
    def identifier(self):
        """Identifier to help keep track which object issued a log message."""
        return f"<{str(hex(id(self)))}>:{str(self.transport.get_extra_info('sockname'))}:{str(self.transport.get_extra_info('peername'))}"

    def connection_made(self, transport):
        self.transport = transport

        logger.info(self.identifier + "Successfully set up a datagram endpoint to "
                    + str(self.transport.get_extra_info('peername')))

        logger.info(self.identifier + "Creating set_chat_dest task...")
        asyncio.create_task(self.set_chat_dest())
        return

    async def set_chat_dest(self):
        if not self.challenge:
            logger.info(self.identifier + "Awaiting for challenge...")
            await self.send_getchallenge()
            logger.info(self.identifier + "Awaited getchallenge")

        logger.info(self.identifier + "Setting " + misc.chat_dest_command + "...")

        port = self.transport.get_extra_info('sockname')[1]

        match self.ip:
            case 'localhost' | 'loopback' | '127.0.0.1':
                self.rcon(misc.chat_dest_command
                          + "{}:{}".format(
                    '127.0.0.1', #socket.gethostbyname(socket.gethostname())
                    int(port)))

            case _:
                self.rcon(misc.chat_dest_command
                          + "{}:{}".format(
                    str(urllib.request.urlopen(misc.url_check_public_ip).read().decode().strip()),
                    int(port)))
        return

    def connection_lost(self, exc: Exception):
        if exc:
            logger.error(self.identifier + repr(exc))
        else:
            logger.info(self.identifier + "Closed an endpoint to "
                        + str(self.transport.get_extra_info('peername')))
            return

    def error_received(self, exc: Exception):
        if exc:
            logger.error(self.identifier + repr(exc))
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
                self.handle_query_response('challenge', data)

            elif re.match(rb"^" + misc.statusresponse, data):
                logger.info(self.identifier + "Received status response " + data.decode())
                data = re.sub(rb"^" + misc.statusresponse, b'', data)
                self.handle_query_response('status', data)

            elif re.match(rb"^" + misc.inforesponse, data):
                logger.info(self.identifier + "Received info response " + data.decode())
                data = re.sub(rb"^" + misc.inforesponse, b'', data)
                self.handle_query_response('info', data)

            elif re.match(rb"^" + misc.ingame_chat, data):
                data = re.sub(rb"^" + misc.ingame_chat, b'', data)
                logger.debug(self.identifier + "Received in-game chat message " + data.decode().strip())  # like above
                asyncio.create_task(self.callback(self.parent, data.decode()))

            elif re.match(rb"^" + misc.ingame_spec, data):
                data = re.sub(rb"^" + misc.ingame_chat, b'', data)
                logger.debug(self.identifier + "Received in-game change-to-spec signal " + data.decode())
                asyncio.create_task(self.callback(self.parent, data.decode()))

            elif re.match(rb"^" + misc.ingame_death, data):
                data = re.sub(rb"^" + misc.ingame_death, b'', data)
                logger.debug(self.identifier + "Received in-game player death signal " + data.decode())
                asyncio.create_task(self.callback(self.parent, data.decode()))

            elif re.match(rb"^" + misc.ingame_teamchange, data):
                data = re.sub(rb"^" + misc.ingame_teamchange, b'', data)
                logger.debug(self.identifier + "Received in-game team change signal " + data.decode())
                asyncio.create_task(self.callback(self.parent, data.decode()))

            else:
                logger.warning(self.identifier + "Incoming datagram hasn't matched any patterns " + data.decode())
        else:
            logger.warning(self.identifier + "Encountered a packet with a non-Quake header" + data.decode())
            return

    def construct_getchallenge(self) -> bytes:
        return misc.header + misc.getchallenge

    @GameProtocol.if_transport
    @GameProtocol.querying(default_challenge="getchallenge")
    async def send_getchallenge(self) -> None:
        """Sends a challenge issue request to remote host."""
        logger.info(self.identifier + "Retrieving challenge...")
        self.transport.sendto(self.construct_getchallenge())
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

    def construct_secure_challenge(self, command: str) -> bytes:
        """
        Constructs a secure challenge-based RCON packet to send to a remote host.
        :param command: A command to send to the remote host.
        :type command: str
        :return: Body of secure challenge-based packet for the rcon protocol.
        """
        if self.challenge:
            cmdpluschallenge = "{} {}".format(self.challenge, command)
            hm = hmac.new(bytes(self.passw, self.encoding), bytes(cmdpluschallenge, self.encoding), 'md4').digest()

            return misc.header + misc.secure_challenge + hm + b' ' + bytes(cmdpluschallenge, self.encoding)  # fix
        else:
            logger.error(self.identifier + "Construct with challenge called but no challenge is set")
            return b''

    def construct_insecure(self, command: str) -> bytes:
        """
        Returns insecure barebytes rcon packet. Server doesn't respond unless it has set `rcon_secure 0`.
        :param command: A command to send to the remote host.
        :type command: str
        :return: Body of unsecure rcon protocoled packet.
        """
        #print(misc.header + misc.insecure + bytes(self.passw, self.encoding) + bytes(command, self.encoding))
        return misc.header + misc.insecure + bytes(self.passw, self.encoding) + b" " +  bytes(command, self.encoding)

    @GameProtocol.if_transport
    # querying?
    def rcon(self, command: str) -> None:
        """
        Sends an RCON command to a remote host.
        :param command: A command to send to the remote host.
        :type command: str
        :return: None
        """
        logger.debug(self.identifier + "Sent rcon command " + command)
        self.transport.sendto(self.construct(command))  # asynchronous
        return  # do we care about return value of an rcon?

    @GameProtocol.if_transport
    async def keepalive(self) -> None:
        """Keeps the system from closing this socket"""
        logger.debug(self.identifier + "Keepalive sent")
        self.transport.sendto(misc.keepalive)
        return  # don't care about the return of this

    @GameProtocol.if_transport
    @GameProtocol.querying()
    async def request_status(self, challenge: bytes) -> None:
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

    @GameProtocol.if_transport
    @GameProtocol.querying()
    async def request_info(self, challenge: bytes) -> None:
        """
        Requests info according to https://discourse.ioquake.org/t/how-to-get-server-status-with-python/1135
        Doesn't seem to be doing anything different from getstatus. I left it in
        :param challenge: identifier to identify response packet with. Doesn't have to be server issued challenge,
        can be anything.
        :type challenge: bytes
        :return: None. Decorator creates a query object.
        """
        logger.debug(self.identifier + "Requested info")
        self.transport.sendto(misc.header + misc.getinfo + challenge)
        return

    @GameProtocol.if_transport
    def handle_query_response(self, type, data: bytes) -> None:  # this is a bit slow
        """
        Parses raw bytes response into a dictionary

        :param data: bytes data from remote host.
        :return: None
        """
        match type:
            case 'info' | 'status':
                challenge = re.findall(b'(?<=\\\\challenge\\\\)(.*?)(?=\\\\)', data)
                for query in self.queries:

                    if challenge[0] == query.identifier:

                        parsed = re.findall(b'(\\\\([ -[\]-~]+)\\\\([ -[\]-~]+))',
                                            data)  # change it so it doesn't pick up the ?challenge? do we care?
                        keyvalues = {}

                        for pair in parsed:
                            keyvalues.update({pair[1].decode(): pair[2].decode()})

                        players = re.findall(b'(?<=\\n).+?(?=\\n)', data)

                        for iterator in range(0, len(players)):
                            coloredname = re.search(b'\"(.*)\"', players[iterator]).group().decode().strip("\"")
                            name = re.sub("(?:\^x(?:[0-9]|[A-F])(?:[0-9]|[A-F])(?:[0-9]|[A-F])|\^[0-9])", "", coloredname, flags=re.IGNORECASE)
                            numbers = players[iterator].split(b"\"")[0].decode().split(' ')
                            players[iterator] = Player(name, *numbers)

                        keyvalues.update({'players': players,
                                          'ip': "{}:{}".format(self.ip, self.port)})

                        query.data = keyvalues
                        query.event.set()
                        return

            case 'challenge':
                for query in self.queries:
                    if 'getchallenge' == query.identifier:
                        query.data = data
                        query.event.set()
                        return
