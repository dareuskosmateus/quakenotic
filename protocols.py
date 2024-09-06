import asyncio
from functools import wraps

import logsetup

logger = logsetup.setup_log(__name__)  # for logging purposes


class NoTransport(Exception):
    def __init__(self, identifier="", msg="No transport has been initialized", *args):
        super().__init__(identifier + msg, *args)

    pass


class Query(object):
    def __init__(self, identifier, event, data):
        self.identifier, self.event, self.data = identifier, event, data


class Decorators:
    @staticmethod
    def if_transport(func):
        @wraps(func)  # allows access to args of func, and a bunch of other quality of life features
        def wrap(self, *args, **kwargs):
            if self.transport is None:
                raise NoTransport(self.identifier)
            return func(self, *args, **kwargs)

        return wrap

    @staticmethod
    def querying(default_challenge=None):  # decorator factory, returns decorator according to arguments
        def decorator(func):
            @wraps(func)  # allows access to args of func, and a bunch of other quality of life features
            async def wrap(self, client, challenge, *args, **kwargs):
                query = Query(challenge, asyncio.Event(), bytearray())
                client.queries.append(query)
                await func(self, client, challenge, *args, **kwargs)
                await query.event.wait()
                client.queries.remove(query)
                return query.data

            @wraps(func)
            async def default_wrap(self, client, *args, **kwargs):
                query = Query(default_challenge, asyncio.Event(), bytearray())
                client.queries.append(query)
                await func(self, client, *args, **kwargs)
                await query.event.wait()
                client.queries.remove(query)
                return query.data

            match default_challenge:
                case None:
                    return wrap
                case _:
                    return default_wrap

        return decorator


class GameProtocol(object):
    def __init__(self):
        return


class GameProtocolTCP(asyncio.Protocol, GameProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        return


class GameProtocolUnix(asyncio.Protocol, GameProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        return


class GameProtocolUDP(asyncio.DatagramProtocol, GameProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        return
