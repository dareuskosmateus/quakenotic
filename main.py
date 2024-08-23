import discord
import logging
import os
import sys
from dotenv import load_dotenv
import bot

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG)


if __name__ == "__main__":
    logger.info("Main executed")
    load_dotenv(os.path.dirname(os.path.realpath(sys.argv[0])) + "/env_vars.env")
    token = os.getenv("TOKEN")
    client = bot.Bot(intents=discord.Intents.all(), command_prefix="$") #change to appropriate intents
    client.run(token, log_handler=None)
    pass
else:
    raise ImportError("This file is not supposed to be imported as a module")
