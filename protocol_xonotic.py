import logsetup
import asyncio
import re
import time
import hmac
import urllib
import socket
from enum import Enum
from typing import Callable

from protocols import Decorators, GameProtocolUDP
import misc

logger = logsetup.setup_log(__name__)


class Security(Enum):
    RCON_INSECURE = 0
    RCON_SECURE_TIME = 1
    RCON_SECURE_CHALLENGE = 2


class Client(object):
    def __init__(self, ip: str, port: int, passw: str, security=Security.RCON_SECURE_TIME):
        super().__init__()
        self.ip, self.port, self.passw = ip, port, passw
        self.security = security
        self.challenge = None
        self.queries = []

    @property
    def identifier(self):
        return f"{str(__class__.__name__)} - {self.ip}:{self.port}"

    def __str__(self):
        return self.identifier


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


class XonoticProtocol(GameProtocolUDP):
    encoding = 'utf-8'

    chat_dest_command = "chat_dest_udp "

    keepalive = b'keepalive'
    header = b'\xFF' * 4

    rcon_response = b"n"
    ingame_chat = b""  # b"chat"
    ingame_spec = b"spec"
    ingame_death = b"died"
    ingame_teamchange = b"team"

    getchallenge = b"getchallenge "
    getstatus = b"getstatus "
    getinfo = b"getinfo "

    challenge = b"challenge "
    statusresponse = b"statusResponse\n"
    inforesponse = b"infoResponse\n"

    insecure = b"rcon "
    secure_time = b"srcon HMAC-MD4 TIME "
    secure_challenge = b"srcon HMAC-MD4 CHALLENGE "

    discordsay = "discordsay "

    def __init__(self,
                 clients: list,
                 *args,
                 write_callback: Callable = None,
                 on_con_lost: asyncio.Future = None,
                 **kwargs):
        """
        :param parent: Parent of this object. Use to call parent's methods where applicable
        :type parent: object
        :param clients: Clients of this protocol.
        :type clients: list
        :param on_con_lost: asyncio Future object. Don't touch it I don't know what it does
        :type on_con_lost: asyncio.Future
        :param write_callback: An async callback function to schedule a task with.
                               Should take a chat message argument as a string.
        :type write_callback: typing.Callable
        :param args: Further args passed to parent of CustomProtocol inheritance-wise asyncio.DatagramProtocol
        :param kwargs: Further keyword args passed to parent of CustomProtocol inheritance-wise asyncio.DatagramProtocol
        """
        super().__init__(*args, **kwargs)
        self.clients = [self.create_client(args['addr'], args['port'], args['passw']) for args in clients]
        self.on_con_lost = on_con_lost
        self.callback = write_callback

        self.transport = None

        asyncio.create_task(self.keep_alive())

        return

    @property
    def identifier(self):
        """Identifier to help keep track which object issued a log message."""
        return f"<{str(__class__.__name__)}> - " \
               f"{str(self.transport.get_extra_info('sockname'))}:"

    def get_client(self, addr: tuple):
        for each in self.clients:
            if tuple([each.ip, each.port]) == addr:
                return each
        return False

    def create_client(self, ip, port, passw):
        return Client(ip, port, passw)

    def connection_made(self, transport):
        self.transport = transport

        logger.info(self.identifier + "Successfully set up a datagram endpoint")

        for each in self.clients:
            logger.info(self.identifier + "Creating set_chat_dest tasks...")
            asyncio.create_task(self.set_chat_dest(each))
        return

    async def set_chat_dest(self, client: Client):
        if not client.challenge:
            logger.info(self.identifier + "Awaiting for challenge for client " + client.identifier + "...")
            await self.send_getchallenge(client)
            logger.info(self.identifier + "Awaited getchallenge for " + client.identifier)

        logger.info(self.identifier + "Setting " + self.chat_dest_command + " for " + client.identifier + "...")

        port = self.transport.get_extra_info('sockname')[1]

        match client.ip:
            case 'localhost' | 'loopback':
                self.rcon(client, self.chat_dest_command
                          + "{}:{}".format(
                    socket.gethostbyname(socket.gethostname()),
                    int(port)))

            case _:
                self.rcon(client, self.chat_dest_command
                          + "{}:{}".format(
                    str(urllib.request.urlopen(misc.url_check_public_ip).read().decode().strip()),
                    int(port)))
        return

    def connection_lost(self, exc: Exception):
        if exc:
            logger.error(self.identifier + repr(exc))
        else:
            logger.info(self.identifier + "Closed the endpoint")
            return

    def error_received(self, exc: Exception):
        if exc:
            logger.error(self.identifier + repr(exc))
        else:
            return

    def datagram_received(self, data: bytes, addr):
        if re.match(rb"^" + self.header, data):
            client = self.get_client(addr)

            data = re.sub(rb"^" + self.header, b'', data)

            if re.match(rb"^" + self.rcon_response, data):
                data = re.sub(rb"^" + self.rcon_response, b'', data)
                logger.debug(self.identifier
                             + "Received rcon response from " + client.identifier
                             + data.decode().strip())  # comment our or set debug lvl higher to avoid spam

            elif re.match(rb"^" + self.challenge, data):
                logger.info(self.identifier + "Received challenge from " + client.identifier
                            + data.decode())
                client.challenge = data
                self.handle_query_response('challenge', client, data)

            elif re.match(rb"^" + self.statusresponse, data):
                logger.info(self.identifier + "Received status response from " + client.identifier
                            + data.decode())
                data = re.sub(rb"^" + self.statusresponse, b'', data)
                self.handle_query_response('status', client, data)

            elif re.match(rb"^" + self.inforesponse, data):
                logger.info(self.identifier + "Received info response from " + client.identifier +
                            data.decode())
                data = re.sub(rb"^" + self.inforesponse, b'', data)
                self.handle_query_response('info', client, data)

            elif re.match(rb"^" + self.ingame_chat, data):
                data = re.sub(rb"^" + self.ingame_chat, b'', data)
                logger.debug(self.identifier + "Received in-game chat message from " + client.identifier +
                             data.decode().strip())  # like above
                self.callback([tuple([client.ip, client.port]), data.decode()])

            elif re.match(rb"^" + self.ingame_spec, data):
                data = re.sub(rb"^" + self.ingame_chat, b'', data)
                logger.debug(self.identifier + "Received in-game change-to-spec signal from " + client.identifier
                             + data.decode())
                self.callback(client, data.decode())

            elif re.match(rb"^" + self.ingame_death, data):
                data = re.sub(rb"^" + self.ingame_death, b'', data)
                logger.debug(self.identifier + "Received in-game player death signal from " + client.identifier
                             + data.decode())
                self.callback(client, data.decode())

            elif re.match(rb"^" + self.ingame_teamchange, data):
                data = re.sub(rb"^" + self.ingame_teamchange, b'', data)
                logger.debug(self.identifier + "Received in-game team change signal from " + client.identifier +
                             data.decode())
                self.callback(client, data.decode())

            else:
                logger.warning(self.identifier + "Incoming datagram from " + client.identifier
                               + " hasn't matched any patterns " + data.decode())
        else:
            logger.warning(self.identifier + "Encountered a packet with a non-Quake header from " + str(addr)
                           + data.decode())
            return

    def construct_getchallenge(self) -> bytes:
        return self.header + self.getchallenge

    @Decorators.if_transport
    @Decorators.querying(default_challenge="getchallenge")
    async def send_getchallenge(self, client: Client) -> None:
        """Sends a challenge issue request to remote host."""
        logger.info(self.identifier + "Retrieving challenge for " + client.identifier)
        self.transport.sendto(self.construct_getchallenge(), (client.ip, client.port))
        return

    def parse_challenge(self, challenge: bytes) -> bytes:
        return challenge[len(self.header + self.challenge):len(self.header + self.challenge) + 11]  # don't touch the 11

    def construct(self, client: Client, command: str) -> bytes:
        """
        Constructs a ready to use rcon packet.
        :param client: client struct containing address and port.
        :param command: Command to be sent to remote host.
        :type command: str
        :return: bytes packet ready to send.
        """
        match client.security:
            case Security.RCON_SECURE_TIME:
                return self.construct_secure_time(client, command)
            case Security.RCON_SECURE_CHALLENGE:
                return self.construct_secure_challenge(client, command)
            case Security.RCON_INSECURE:
                return self.construct_insecure(client, command)
            case _:
                logger.error(self.identifier + "Construct called but no security has been set for " + client.identifier)

    def construct_secure_time(self, client: Client, command: str) -> bytes:
        """
        Constructs a secure time-based rcon packet to send to a remote host.
        :param client: client struct containing address and port.
        :param command: A command to send to the remote host.
        :type command: str
        :return: Body of secure time-based packet for the rcon protocol.
        """
        tm = time.time()
        cmdplustime = "{:6f} {}".format(tm, command)

        hm = hmac.new(bytes(client.passw, self.encoding), bytes(cmdplustime, self.encoding), 'md4').digest()

        return self.header + self.secure_time + hm + b' ' + bytes(cmdplustime, self.encoding)

    def construct_secure_challenge(self, client: Client, command: str) -> bytes:
        """
        Constructs a secure challenge-based RCON packet to send to a remote host.
        :param client: client struct containing address and port.
        :param command: A command to send to the remote host.
        :type command: str
        :return: Body of secure challenge-based packet for the rcon protocol.
        """
        if client.challenge:
            cmdpluschallenge = "{} {}".format(client.challenge, command)
            hm = hmac.new(bytes(client.passw, self.encoding), bytes(cmdpluschallenge, self.encoding), 'md4').digest()

            return self.header + self.secure_challenge + hm + b' ' + bytes(cmdpluschallenge, self.encoding)  # fix
        else:
            logger.error(self.identifier + "Construct with challenge called but no challenge is set")
            return b''

    def construct_insecure(self, client: Client, command: str) -> bytes:
        """
        Returns insecure barebytes rcon packet. Server doesn't respond unless it has set `rcon_secure 0`.
        :param client: client struct containing address and port.
        :param command: A command to send to the remote host.
        :type command: str
        :return: Body of unsecure rcon protocoled packet.
        """
        return self.header + self.insecure + client.passw + command

    @Decorators.if_transport
    # querying?
    def rcon(self, client: Client, command: str) -> None:
        """
        Sends an RCON command to a remote host.
        :param client: client struct containing address and port.
        :param command: A command to send to the remote host.
        :type command: str
        :return: None
        """
        logger.debug(self.identifier + "Sent rcon command " + command + " to " + client.identifier)
        self.transport.sendto(self.construct(client, command), (client.ip, client.port))  # asynchronous
        return  # do we care about return value of an rcon?

    @Decorators.if_transport
    async def keepalive(self, client: Client = None) -> None:
        """Keeps the system from closing this socket"""
        if client is not None:
            logger.debug(self.identifier + "Keepalive sent to " + client.identifier)
            self.transport.sendto(self.keepalive, (client.ip, client.port))
        else:
            for each in self.clients:
                logger.debug(self.identifier + "Keepalive sent to " + each.identifier)
                self.transport.sendto(self.keepalive, (each.ip, each.port))
        return  # don't care about the return of this

    @Decorators.if_transport
    @Decorators.querying()
    async def request_status(self, client: Client, challenge: bytes) -> None:
        """
        Requests status from remote host.
        :param client: client struct containing address and port.
        :param challenge: identifier to identify response packet with. Doesn't have to be server issued challenge,
        can be anything.
        :type challenge: bytes
        :return: None. Decorator creates a query object.
        """
        logger.debug(self.identifier + "Requested status from " + client.identifier)
        self.transport.sendto(self.header + self.getstatus + challenge, (client.ip, client.port))
        return

    @Decorators.if_transport
    @Decorators.querying()
    async def request_info(self, client: Client, challenge: bytes) -> None:
        """
        Requests info according to https://discourse.ioquake.org/t/how-to-get-server-status-with-python/1135
        Doesn't seem to be doing anything different from getstatus. I left it in
        :param client: client struct containing address and port.
        :param challenge: identifier to identify response packet with. Doesn't have to be server issued challenge,
        can be anything.
        :type challenge: bytes
        :return: None. Decorator creates a query object.
        """
        logger.debug(self.identifier + "Requested info")
        self.transport.sendto(self.header + self.getinfo + challenge, (client.ip, client.port))
        return

    @Decorators.if_transport
    def handle_query_response(self, type: str, client: Client, data: bytes) -> None:  # this is a bit slow
        """
        Parses raw bytes response into a dictionary
        :param client: client struct containing address and port.
        :param data: bytes data from remote host.
        :return: None
        """
        match type:
            case 'info' | 'status':
                challenge = re.findall(b'(?<=\\\\challenge\\\\)(.*?)(?=\\\\)', data)
                for query in client.queries:

                    if challenge[0] == query.identifier:

                        parsed = re.findall(b'(\\\\([ -[\]-~]+)\\\\([ -[\]-~]+))',
                                            data)  # change it so it doesn't pick up the ?challenge? do we care?
                        keyvalues = {}

                        for pair in parsed:
                            keyvalues.update({pair[1].decode(): pair[2].decode()})

                        players = re.findall(b'(?<=\\n).+?(?=\\n)', data)

                        for iterator in range(0, len(players)):
                            coloredname = re.search(b'\"(.*)\"', players[iterator]).group().decode().strip("\"")
                            name = re.sub("(?:\^x(?:[0-9]|[A-F])(?:[0-9]|[A-F])(?:[0-9]|[A-F])|\^[0-9])", "",
                                          coloredname, flags=re.IGNORECASE)
                            numbers = players[iterator].split(b"\"")[0].decode().split(' ')
                            players[iterator] = Player(name, *numbers)

                        keyvalues.update({'players': players,
                                          'ip': "{}:{}".format(client.ip, client.port)})

                        query.data = keyvalues
                        query.event.set()
                        return

            case 'challenge':
                for query in client.queries:
                    if 'getchallenge' == query.identifier:
                        query.data = data
                        query.event.set()
                        return

    def send(self, addr, msg):
        self.rcon(self.get_client(addr), "say " + msg)

    async def keep_alive(self):
        while True:
            for client in self.clients:
                self.transport.sendto(self.keepalive, (client.ip, client.port))
            await asyncio.sleep(20)
