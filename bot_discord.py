import asyncio

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
        self.token = kwargs['token'] if kwargs['token'] else None
        super().__init__(*args, intents=discord.Intents(**kwargs.pop('intents')), **kwargs)
        self.channels = kwargs['channels']
        self.callback = kwargs['callback']

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

    async def start(self, token=None, *args, **kwargs):
        if self.token:
            await super().start(self.token, *args, **kwargs)
        else:
            await super().start(token, *args, **kwargs)

    def setup_commands(self) -> None:
        """
        Sets up commands of this bot. Needs to be invoked within __init__. Put your commands with decorators
        here (outside it doesn't work).
        :return: None
        """

        @self.command(name="status",
                      description="Queries game server for current status: players, map, hostname.")
        async def game_status(ctx):

            return

        @self.command(name="info",
                      description="Queries game server for current info. Doesn't seem to be different from status")
        async def game_info(ctx):

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

        if message.author.bot:
            return

        await self.process_commands(message)
        if message.channel.id in self.channels:
            logger.debug("Caught a message")
            self.callback([tuple([self, message.channel.id]), message.content])
            pass

        return

    async def send(self, channelid: list[int], msg: str):
        for each in channelid:
            channel = self.get_channel(each)
            await channel.send(msg)
        return
