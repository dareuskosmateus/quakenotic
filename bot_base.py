import asyncio

import logsetup

logger = logsetup.setup_log(__name__)

class BotBase(object):
    def __init__(self):
        super().__init__()

    def __del__(self):
        return

    def run(self):
        async def runner():
            async with self:
                await self.start()

        try:
            asyncio.run(runner())
        except Exception as exc:
            logger.exception(exc)

    async def start(self):
        raise NotImplementedError("Define this abstract method first")