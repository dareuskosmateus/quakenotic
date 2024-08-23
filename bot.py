import discord
import logging
from discord.ext import commands, tasks
import asyncio
import os
import sys

import protocols

logger = logging.getLogger(__name__)  # for logging purposes
logging.basicConfig(level=logging.DEBUG)


class Bot(discord.ext.commands.Bot):
    max_message_length = 127
    to_xonotic_format = "<{}>:[{}]: {}"
    from_xonotic_format = "`{}`"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.connections = {}

        self.setup_commands()

        return

    async def setup_connections(self):
        with open(os.path.dirname(os.path.realpath(sys.argv[0])) + "/sockets.csv") as sockets:
            for line in sockets:
                address, passw, channels = line.split(";")
                ip, port = address.split(":")
                channels = channels.split(",")
                conn = await self.create_connection(ip, port, passw)
                self.connections.update({conn: [self.get_channel(int(channel.strip())) for channel in channels]})

            pass
        return

    async def create_connection(self, ip: str, port: int, passw: str):
        """
        Creates a UDP datagram endpoint for rcon purposes.
        :param ip: IPv4 address of remote host.
        :type ip: str
        :param port: Port used by remote host.
        :type port: int
        :param passw: RCON password of remote host.
        :type passw: str
        :return:
        """
        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()
        conn = protocols.Conn(self, None, None)
        conn.transport, conn.protocol = await loop.create_datagram_endpoint(
            lambda: protocols.XonoticProtocol(conn, ip, port, passw, on_con_lost, self.write_to_chats),
            remote_addr=(ip, port))

        return conn

    @classmethod
    async def new(cls, *args, **kwargs) -> object:
        """
        Classmethod constructor. Add async attributes here that cannot be set in __init__,
        Remember to set an "update" function if dealing with inheritance,
        To be used in async functions.
        :return: Instance of this class
        """

        self = cls(*args, **kwargs)
        return self

    def setup_commands(self) -> None:
        """
        Sets up commands of this bot. Needs to be invoked within __init__. Put your commands with decorators
        here (outside it doesn't work).
        :return: None
        """

        @self.command(name="status", description="Queries game server for current status: players, map, ping.")
        async def game_status(ctx):
            # todo
            return

        @self.command(name="ping", description="Pong.")
        async def check_if_dead(ctx) -> None:
            await ctx.channel.send("Pong")
            return

        # add further decorators and associated functions for more commands
        return

    async def on_ready(self):
        """Stock discord coroutine."""

        await self.setup_connections()
        self.refresh_datagrams.start()
        return

    async def on_message(self, message: discord.Message, /):
        """Stock discord coroutine."""
        if not message.author.bot:
            await self.process_commands(message)
            for conn in self.connections:
                if message.channel in self.connections[conn]:
                    if len(message.content) <= Bot.max_message_length:
                        conn.protocol.rcon("discordsay \"" + Bot.to_xonotic_format.format(
                            message.author.id, message.author.name, message.content) + "\"")
            pass
        return

    async def write_to_chats(self, conn: object, msg: str) -> None:
        for channel in self.connections[conn]:
            await channel.send(Bot.from_xonotic_format.format(msg))
        return

    @tasks.loop(seconds=20)
    async def refresh_datagrams(self):
        logger.debug("Refreshing datagrams...")
        for conn in self.connections:
            conn.protocol.keepalive()
        return
