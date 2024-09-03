import discord
from discord.ext import commands, tasks

import logsetup
import protocols

logger = logsetup.setup_log(__name__)  # for logging purposes


class Bot(discord.ext.commands.Bot):
    max_message_length = 127
    to_xonotic_format = "^xC00<DISCORD>^7:[{}]: {}"
    from_xonotic_format = "`{}`"

    def __init__(self, *args, **kwargs):
        self.token = kwargs['token']
        intents = kwargs['intents']
        kwargs.pop('intents')
        super().__init__(*args, intents=discord.Intents(**intents), **kwargs)

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

    def run(self, *args, **kwargs):
        if self.token:
            super().run(self.token, *args, **kwargs)
        else:
            super().run(*args, **kwargs)

        return

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
                for client in conn.protocol.clients:
                    if ctx.channel in client.channels:
                        data = await conn.protocol.request_status(client, ctx.author.name.encode())
                        await ctx.channel.send(embed=self.format_status(data, ctx.author.name))
            return

        @self.command(name="info",
                      description="Queries game server for current info. Doesn't seem to be different from status")
        async def game_info(ctx):
            for conn in self.connections:
                for client in conn.protocol.clients:
                    if ctx.channel in client.channels:
                        data = await conn.protocol.request_info(client, ctx.author.name.encode())
                        await ctx.channel.send(embed=self.format_status(data, ctx.author.name))
            return

        @self.command(name="ping", description="Pong.")
        async def check_if_dead(ctx) -> None:
            await ctx.channel.send("Pong")
            return

        # add further decorators and associated functions for more commands
        logger.info("Finished setting up commands")
        return

    async def on_ready(self):
        """Stock discord coroutine."""
        logger.info("Ready")

        return

    async def on_message(self, message: discord.Message, /):
        """Stock discord coroutine."""

        if not message.author.bot:
            await self.process_commands(message)

        return

    async def send_to_channel(self, msg: str, channelid: int):
        await self.get_channel(channelid).send(msg)
        return
