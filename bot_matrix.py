import asyncio

import logsetup
import bot_base

logger = logsetup.setup_log(__name__)


class MatrixBot(bot_base.BotBase):
    def __init__(self):
        super().__init__()

    def __del__(self):
        return
