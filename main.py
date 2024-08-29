import logging
import discord
import os
import sys
from dotenv import load_dotenv

import bot
import logsetup


def main():
    logger.info("Main executed")
    load_dotenv(os.path.dirname(os.path.realpath(sys.argv[0])) + "/env_vars.env")
    token = os.getenv("TOKEN")
    client = bot.Bot(intents=discord.Intents.all(), command_prefix="$")  # change to appropriate intents
    client.run(token)
    return


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG, handlers=[])
    logger = logsetup.setup_log(__name__)
    main()
else:
    raise ImportError("This file is not supposed to be imported as a module")
