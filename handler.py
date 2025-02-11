import os, sys
import asyncio
import queue
import yaml
import threading
import importlib
import platform

from typing import Callable, Self
import logsetup

logger = logsetup.setup_log(__name__)

def formatsyspath(filename: str) -> str:
    """Helper function to parse stupid filepaths on different systems."""
    match platform.system():
        case "Windows":
            return "\\" + filename
        case "Linux" | "Darwin":
            return "/" + filename
        case _:
            raise NotImplementedError("Unsupported system")


class CallbackObject(object):
    """
    A callable callback object for chatbots to pass messages through.
    Since threading is terrible in python this object also passes along the asyncio event loop for the bot thread to use.
    No real multithreading actually takes place.
    """
    def __init__(self, callback: Callable, loop: asyncio.AbstractEventLoop = None):
        self.callback = callback
        self.loop = loop if loop else asyncio.get_running_loop()
        return

    def __call__(self, *args, **kwargs):
        self.loop.call_soon_threadsafe(self.callback(*args, **kwargs))
        return

class ThreadLoop(threading.Thread):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.loop = asyncio.new_event_loop()
        self.loop.create_task(self._target(*self._args, **self._kwargs))
        self._target = self.loop.run_forever

    def run(self, *args, **kwargs):
        super().run()
        pass


class SafeLoaderPlusTuples(yaml.SafeLoader):
    """
    A class for yaml custom types support.
    More information can be found in https://pyyaml.org/wiki/PyYAMLDocumentation#yaml-tags-and-python-types
    """
    def construct_tuple(self, node):
        return tuple(self.construct_sequence(node))


class Relay(object):  # struct
    """
    A struct like class for encapsulation purposes.
    Contains references to various objects related to the notion of a relay within this script.
    """
    def __init__(self, queue, bot, args, kwargs, runargs, runkwargs):
        super().__init__()
        self.queue, self.bot, self.args, self.kwargs, self.runargs, self.runkwargs = (
            queue, bot, args, kwargs, runargs, runkwargs)


class SharedChat(object):  # struct
    """
    A struct like class for encapsulation purposes.
    Contains references to various objects related to the notion of a shared chat within this script.
    """
    def __init__(self, servers, bots):
        super().__init__()
        self.servers, self.bots = servers, bots


class CustomQueue(queue.Queue):
    def __init__(self, event, *args, **kwargs):
        queue.Queue.__init__(self, *args, **kwargs)
        self.event = event

    def put_notify(self, item):
        self.put(item)
        self.event.set()

    async def async_get(self, *args, **kwargs):
        flag = 0
        result = []
        while not flag:
            try:
                result = tuple([self.get_nowait() for _ in range(self.qsize())])
                flag = 1
            except queue.Empty:
                await asyncio.sleep(1)

        return result


class BijectiveDict(dict):
    """
    Two-way dict
    https://en.wikipedia.org/wiki/Bidirectional_map
    https://en.wikipedia.org/wiki/Bijection
    """

    def __init__(self, mydict=dict()):
        dict.__init__(self, mydict)
        self.rev_dict = dict(map(reversed, mydict.items()))

    def __setitem__(self, key, value):
        dict.__setitem__(self, key, value)
        self.rev_dict.__setitem__(value, key)

    def pop(self, key):
        self.rev_dict.pop(self[key])
        dict.pop(self, key)

    def update(self, __m, **kwargs):
        dict.update(self, __m, **kwargs)
        self.rev_dict.update(dict(map(reversed, __m.items())))


class Connection(object):  # struct
    """
    A struct like class for encapsulation purposes.
    Contains references to various objects related to the notion of a connection to a game/whatever server within this script.
    """
    def __init__(self, queue, transport: asyncio.Transport, protocol: asyncio.Protocol, clients: list):
        self.queue, self.transport, self.protocol, self.clients = queue, transport, protocol, clients

    @classmethod
    def from_await(cls, queue, async_wrap: tuple[asyncio.Transport, asyncio.Protocol], clients: list) -> Self:
        """
        Custom constructor.
        :param queue:
        :param async_wrap:
        :param clients:
        :return:
        """
        return cls(queue, async_wrap[0], async_wrap[1], clients)


class Handler(object):
    """
    A class representing the notion of a message handler. A glorified but bastardized form of the adapter pattern.
    Within this script can only run one thread for memory sanity reasons, so only one handler is needed like the singleton pattern
    (don't really need two separate handlers if one does the trick),
    however it is possible to run multiple scripts with a handler each to simulate multithreading with a bunch of independent processes.
    For this, user supplied config paths are to be added.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.event_stop = asyncio.Event()
        self.stuff_to_read = asyncio.Event()

        self.queue = CustomQueue(self.stuff_to_read)
        self.relays = BijectiveDict()
        self.connections = BijectiveDict()
        self.servers = BijectiveDict()
        self.threads = BijectiveDict()
        self.sharedpool = BijectiveDict()

    @classmethod
    async def new(cls) -> Self:
        self = cls()
        return self

    def __del__(self):
        return

    @property
    def identifier(self):
        return f"{self.__class__.__name__} "

    def run(self):
        try:
            asyncio.run(self.start())
        except Exception as exc:
            logger.exception(exc)
        return

    async def start(self):
        await self.setup()

        while not self.event_stop.is_set():
            await self.queue.event.wait()
            msg = await self.queue.async_get()
            if msg:
                await asyncio.create_task(self.handle_messages(*msg))
                self.stuff_to_read.clear()

        return

    async def stop(self):
        self.event_stop.set()
        return

    async def setup(self):
        """
        Sets connections, relays, and shared chats before asyncio loop begins running.
        Additionally adds a constructor to yaml's custom types.
        :return: None
        """

        SafeLoaderPlusTuples.add_constructor(u'tag:yaml.org,2002:python/tuple',
                                             SafeLoaderPlusTuples.construct_tuple)

        await self.setup_connections()
        await self.setup_relays()
        await self.setup_shared_chats()
        await self.setup_threads()

        logger.info(self.identifier + "Finished setting up")

        return

    async def setup_connections(self):
        logger.info(self.identifier + "Setting up connections...")
        with open(os.path.dirname(os.path.realpath(sys.argv[0])) + formatsyspath("config/sockets.yaml")) as file:
            sockets = yaml.load(file, Loader=SafeLoaderPlusTuples)

            for game in sockets:
                package = importlib.import_module(sockets[game]['protocol']['path'])
                protocol = getattr(package, sockets[game]['protocol']['name'])

                clients = []
                for server in sockets[game]['protocol']['servers']:
                    if sockets[game]['protocol']['servers'][server]['active'] is not True:
                        self.servers.update({server: None})
                        continue

                    clients.append(sockets[game]['protocol']['servers'][server])
                    self.servers.update({server: tuple([
                                                    sockets[game]['protocol']['servers'][server]['addr'],
                                                    sockets[game]['protocol']['servers'][server]['port']
                                                    ])
                    })

                sockets[game]['protocol']['args'].append(clients)
                sockets[game]['protocol']['kwargs'].update({"write_callback": CallbackObject(self.queue.put_notify)})

                self.connections.update({game: Connection.from_await(
                    self.queue,
                    await self.create_connection(
                        sockets[game]['protocol']['type'],
                        protocol,
                        sockets[game]['protocol']['args'],
                        sockets[game]['protocol']['kwargs'],
                        sockets[game]['protocol']['conn']['args'],
                        sockets[game]['protocol']['conn']['kwargs'],
                    ),
                    tuple(list(
                        tuple([clients[client]['addr'],
                               clients[client]['port']]) for client in range(len(clients))))
                )
                })

        return

    async def setup_relays(self):
        logger.info(self.identifier + "Setting up relays...")
        with open(os.path.dirname(os.path.realpath(sys.argv[0])) + formatsyspath("config/relays.yaml")) as file:
            relays = yaml.load(file, Loader=SafeLoaderPlusTuples)

            for bot in relays:
                if relays[bot]['active'] is not True:
                    self.relays.update({bot: None})
                    continue

                package = importlib.import_module(relays[bot]['path'])
                classname = getattr(package, relays[bot]['classname'])
                relay = classname(*relays[bot]['args'], callback=CallbackObject(self.queue.put_notify), **relays[bot]['kwargs'])

                self.relays.update({bot: Relay(
                    self.queue,
                    relay,
                    relays[bot]['args'],
                    relays[bot]['kwargs'],
                    relays[bot]['run']['args'],
                    relays[bot]['run']['kwargs']
                )
                })

        return

    async def setup_shared_chats(self):
        logger.info(self.identifier + "Setting up shared chat pools...")
        if not self.connections or not self.relays:
            logger.warning(
                self.identifier
                + "Called setup_shared_chats but connections or relays are empty")
            # only run if these are already set up due to dependency on previous setups

        with open(os.path.dirname(os.path.realpath(sys.argv[0])) + formatsyspath("config/sharedchats.yaml")) as file:
            shared = yaml.load(file, Loader=SafeLoaderPlusTuples)

            for chat in shared:
                relays, servers = shared[chat]['relays'], shared[chat]['servers']
                self.sharedpool.update({chat: SharedChat(
                    {self.servers[server]: self.get_conn(self.servers[server])
                     for server in servers},
                    {self.relays[relay].bot: relays[relay] for relay in relays}
                )
                })
                pass

        return

    def get_conn(self, server: tuple[str, int]):
        """
        Getter function to return a connection object of a given tuple of IP address and port.
        Get a better search algorithm. Maybe add in some kind of partial or lexicographic order.
        :param server: a tuple of IP address and port.
        :return: Connection
        """

        for conn in self.connections:
            if server in self.connections[conn].clients:
                return self.connections[conn]

    async def setup_threads(self):
        logger.info(self.identifier + "Setting up threads...")
        if not self.relays:
            logger.warning(self.identifier + "Called setup_threads but relays are empty")

        #for relay in self.relays:
        #    await asyncio.create_task(self.relays[relay].bot.start())

        self.threads.update({self.relays[relay].bot: ThreadLoop(target=self.relays[relay].bot.start,
                                                            args=self.relays[relay].runargs,
                                                            kwargs=self.relays[relay].runkwargs) for relay in
                             self.relays})

        for each in self.threads:
            self.threads[each].start()

        return

    async def create_connection(self, socket_type: str, protocol: asyncio.Protocol,
                                protargs: list, protkwargs: dict, connargs: list, connkwargs: dict,
                                ) -> tuple[asyncio.Transport, asyncio.Protocol] | asyncio.Server | None:
        """
        Creates an asyncio.Transport and asyncio.Protocol pair according to specified.
        Note this pair of objects is not thread safe.
        :param socket_type: socket type as defined in. Is a string to make it easier on the matching (not like we are going to get another socket type within this century)
        :param protocol: protocol as defined in https://docs.python.org/3/library/asyncio-protocol.html#protocols
        :param protargs: args to protocol constructor.
        :param protkwargs: kwargs to protocol constructor.
        :param connargs: args to transport constructor.
        :param connkwargs: kwargs to transport construtor.
        :return: a tuple of transport, protocol of asyncio module. Possibly asyncio.Server for some reason i can't remember as well. None on failure.
        """

        loop = asyncio.get_running_loop()

        try:
            match socket_type:
                case 'udp':
                    func = loop.create_datagram_endpoint

                case 'tcp':
                    func = loop.create_server

                case 'unix':
                    func = loop.create_unix_server

                case _:
                    raise NotImplementedError("This socket type is unsupported")

        except Exception as exc:
            logger.exception(exc)
            return None

        return await func(lambda: protocol(*protargs, **protkwargs), *connargs, **connkwargs)

    async def handle_messages(self, *args):
        logger.debug("Handling messages " + str(args))
        for each in args:
            await self.handle_message(each[0], *each[1:])
        return

    async def handle_message(self, _from: tuple[str, int] | tuple[object, int], *msg: str):
        for shared in self.sharedpool:
            if _from not in self.sharedpool[shared].servers and _from[0] not in self.sharedpool[shared].bots:
                continue

            for server in self.sharedpool[shared].servers:
                # send to all the other servers in shared pool
                if _from == server:
                    continue

                self.sharedpool[shared].servers[server].protocol.send(server, "".join(msg))

            for bot in self.sharedpool[shared].bots:
                # send to all bots in shared pool
                if _from[0] == bot:
                    continue

                asyncio.run_coroutine_threadsafe(bot.send(self.sharedpool[shared].bots[bot], "".join(msg)),
                                                 loop=self.threads[bot].loop)
        return
