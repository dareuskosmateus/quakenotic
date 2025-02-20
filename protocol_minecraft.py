import asyncio
from typing import Self

from protocols import GameProtocolTCP
import logsetup

logger = logsetup.setup_log(__name__)


class Packet(object):
    def __init__(self, id: int, type: int, contents: bytes):
        self.id, self.type, self.contents = id, type, contents
        return

    @classmethod
    def from_bytes(cls, data: bytes) -> Self:
        """
        A classmethod custom constructor to construct an object of this type from pure bytes.
        :param data: bytes to slice to construct this object off of.
        :return: Self
        """
        self = cls(int(data[4:8]), int(data[8:12]), bytes(data[12:-1]))
        return self

    @property
    def length(self):
        """Returns length of the actual contents of this packet. Does not reflect the total length in bytes."""
        return len(self.contents)

    @property
    def pad(self):
        return bytes(1)

    def to_bytes(self):
        return b"".join(tuple[(
                               bytes(self.length),
                               bytes(self.id),
                               bytes(self.type),
                               bytes(self.contents),
                               bytes(self.pad)
                             )]
                        )


class Client(object):
    def __init__(self, ip: str, port: int, transport: asyncio.Transport = None):
        self.ip, self.port = ip, port
        self.transport = transport
        return


class MinecraftProtocol(GameProtocolTCP):
    def __init__(self, clients, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.clients = {client: self.create_client(client) for client in clients}
        self.transport = None

        return

    @property
    def identifier(self):
        return

    def create_client(self, addr: tuple[str, int]):
        return Client(addr[0], addr[1])

    def get_client(self):
        return

    def connection_made(self, transport):
        logger.info("Successfully established a connection to " + str(transport.get_extra_info('peername')))
        self.clients[transport.get_extra_info('peername')].transport = transport

        return

    def connection_lost(self, exc):
        if exc:
            logger.exception(exc)
        else:
            logger.info("Closed the connection to " + str())

        return

    def data_received(self, data):
        logger.debug("Received a packet " + str(data.decode()))
        return

    def eof_received(self):
        return
