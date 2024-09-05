import discord

from discord.ext import commands, tasks
import asyncio
import os
import sys

import logsetup
import protocols

logger = logsetup.setup_log(__name__)  # for logging purposes


class Bot(discord.ext.commands.Bot):
    max_message_length = 255
    to_xonotic_format = "<^xC00DISCORD^7>:[{}]: {}"
    from_xonotic_format = "{}"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.connections = {}

        self.setup_commands()

        return

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

    def setup_commands(self) -> None:
        """
        Sets up commands of this bot. Needs to be invoked within __init__. Put your commands with decorators
        here (outside it doesn't work).
        :return: None
        """

        @self.command(name="status",
                      description="Queries game server for current status: players, map, hostname.")
        async def game_status(ctx):
            for conn in self.connections:
                if ctx.channel in self.connections[conn]:
                    data = await conn.protocol.request_status(ctx.author.name.encode())
                    await ctx.channel.send(embed=self.format_status(data, ctx.author.name))
            return

        @self.command(name="info",
                      description="Queries game server for current info. Doesn't seem to be different from status")
        async def game_info(ctx):
            for conn in self.connections:
                if ctx.channel in self.connections[conn]:
                    data = await conn.protocol.request_info(ctx.author.name.encode())
                    await ctx.channel.send(embed=self.format_status(data))
            return

        @self.command(name="ping", description="Pong.")
        async def check_if_dead(ctx) -> None:
            await ctx.channel.send("Pong")
            return

        @self.command(name="goatstatus", description="Bah.")
        async def goat_status(ctx) -> None:
            await ctx.channel.send(":goat:")
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

        logger.debug("Message caught in " + str(message.channel.id) + ", contents " + str(message.content))
        if not message.author.bot:
            await self.process_commands(message)
            for conn in self.connections:
                if message.channel in self.connections[conn] and len(message.content) <= Bot.max_message_length:
                    logger.debug("Sending from discord " + str(message.content))
                    if message.reference:
                        referred = await message.channel.fetch_message(message.reference.message_id)
                        conn.protocol.rcon("say \"" + Bot.to_xonotic_format.format(
                            message.author.display_name,
                            "(to {}) {}".format(referred.author.display_name, message.content)) + "\"")
                    else:
                        conn.protocol.rcon("say \"" + Bot.to_xonotic_format.format(
                            message.author.display_name,
                            message.content + "\""))
            pass
        return

    async def write_to_chats(self, conn: object, msg: str) -> None:
        for channel in self.connections[conn]:
            # indexname, content = msg.split(":", 1)
            # hook = await channel.create_webhook(name=indexname, reason="Incoming chat message")
            # await hook.send(content)
            # await hook.delete(reason="Expired (chat message already sent)")
            await channel.send(Bot.from_xonotic_format.format(msg.replace('`','')))
        return

    @tasks.loop(seconds=20)
    async def refresh_datagrams(self):
        logger.debug("Refreshing datagrams...")
        for conn in self.connections:
            await conn.protocol.keepalive()
        return

    def format_status(self, status: dict, requester: str = None) -> discord.Embed:
        embed = discord.Embed(title="Server status",
                              description="",
                              )

        embed.add_field(name="Server name: ", value=status['hostname'], inline=True)
        embed.add_field(name="Address: ", value=status['ip'], inline=True)
        embed.add_field(name="Map: ", value=status['mapname'], inline=True)
        embed.add_field(name="Clients: ", value="{}/{} ({} bots)".format(
            status['clients'], status['sv_maxclients'], status['bots']), inline=True)

        if bool(status['players']):
            formatted = "`{:<30} {:>5} {:4} {:2}`\n".format("Nickname", "Score", "Ping", "Team")
            for player in status['players']:

                formatted += "`{:<30} {:>5} {:4} {:4}`\n".format(
                    player.name, player.score, player.ping, player.team if bool(player.team) else "")
            embed.add_field(name="Player list: ", value=formatted, inline=False)

        if requester:
            embed.set_footer(text="Copyup 2069 LOLOLOL, requested by {}".format(requester))

        return embed
