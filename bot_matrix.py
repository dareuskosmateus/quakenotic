import asyncio

import logsetup
from bot_base import BotBase

logger = logsetup.setup_log(__name__)


class MatrixBot(BotBase):
    def __init__(self):
        super().__init__()

    def __del__(self):
        return
