import asyncio

import logsetup

logger = logsetup.setup_log(__name__)


class BotBase(object):
    def __init__(self, *args, **kwargs):
        super().__init__()
        return

    def __del__(self):
        return

    def run(self):
        try:
            asyncio.run(self.start())
        except Exception as exc:
            logger.exception(exc)

    async def start(self):
        raise NotImplementedError("Define this abstract method first")
