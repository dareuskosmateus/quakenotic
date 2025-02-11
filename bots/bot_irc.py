import logsetup
from bots.bot_base import BotBase

logger = logsetup.setup_log(__name__)


class IRCBot(BotBase):
    def __init__(self):
        super().__init__()

    def __del__(self):
        return

