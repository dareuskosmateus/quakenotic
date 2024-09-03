import os, sys
import asyncio
import queue
import tomllib
import threading
import importlib
import platform

import logsetup

logger = logsetup.setup_log(__name__)


def formatsyspath(filename: str) -> str:
    match platform.system():
        case "Windows":
            return "\\" + filename
        case "Linux" | "Darwin":
            return "/" + filename
        case _:
            raise NotImplementedError("Unsupported system")


class Relay(object):  # struct
    def __init__(self, queue, bot, args, kwargs, runargs, runkwargs):
        super().__init__()
        self.queue, self.bot, self.args, self.kwargs, self.runargs, self.runkwargs = (
            queue, bot, args, kwargs, runargs, runkwargs)


class SharedChat(object):  # struct
    def __init__(self, servers, relays):
        super().__init__()
        self.servers, self.relays = servers, relays


class CustomQueue(queue.Queue):
    def __init__(self, event, *args, **kwargs):
        queue.Queue.__init__(self, *args, **kwargs)
        self.event = event
        self.async_lock = asyncio.Lock()
        self.sync_lock = threading.Lock()

    def put_notify(self, item):
        self.put(item)
        self.event.set()

    async def async_get(self, *args, **kwargs):
        flag = 0
        result = []
        while not flag:
            try:
                result = [self.get_nowait() for _ in range(self.qsize())]
                flag = 1
            except queue.Empty:
                await asyncio.sleep(1)

        return result


class Connection(object):
    def __init__(self, queue, transport, protocol):
        self.queue, self.transport, self.protocol = queue, transport, protocol

    @classmethod
    def from_await(cls, queue, async_wrap: tuple[asyncio.Transport, asyncio.Protocol]):
        return cls(queue, async_wrap[0], async_wrap[1])


class Handler(object):
    def __init__(self):
        super().__init__()
        self.event_stop = asyncio.Event()
        self.stuff_to_read = asyncio.Event()

        self.queue = CustomQueue(self.stuff_to_read)
        self.relays = {}
        self.connections = {}
        self.servers = {}
        self.threads = {}
        self.sharedpool = {}

    @classmethod
    async def new(cls):
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
            await self.stuff_to_read.wait()
            msg = await self.queue.async_get()
            await asyncio.create_task(self.handle_message(msg))
            self.stuff_to_read.clear()

        return

    async def stop(self):
        self.event_stop.set()
        return

    async def setup(self):
        await self.setup_connections()
        await self.setup_relays()
        await self.setup_shared_chats()
        await self.setup_threads()

        logger.info(self.identifier + "Finished setting up")

        return

    async def setup_connections(self):
        logger.info(self.identifier + "Setting up connections...")
        with open(os.path.dirname(os.path.realpath(sys.argv[0])) + formatsyspath("sockets.toml"), "rb") as file:
            connections = tomllib.load(file)

            for game in connections:
                clients = []

                for server in connections[game]['servers']:
                    addr, port, passw = str(connections[game]['servers'][server]['addr']), \
                        int(connections[game]['servers'][server]['port']), \
                        str(connections[game]['servers'][server]['passw'])

                    clients.append(tuple([addr, port, passw]))
                    self.servers.update({server: tuple([addr, port, passw])})

                connections[game]['protocol']['args'].append(clients)

                source = importlib.import_module(connections[game]['protocol']['path'])
                protocolname = getattr(source, connections[game]['protocol']['protocolname'])

                try:
                    connections[game]['protocol']['connkwargs']['local_addr'] = tuple(
                        connections[game]['protocol']['connkwargs']['local_addr'])
                except Exception as exc:
                    logger.exception(exc)
                    continue

                connections[game]['protocol']['kwargs'].update({"write_callback": self.queue.put_notify})

                self.connections.update({game: Connection.from_await(self.queue, await self.create_connection(
                    connections[game]['protocol']['type'],
                    protocolname,
                    connections[game]['protocol']['args'],
                    connections[game]['protocol']['kwargs'],
                    connections[game]['protocol']['connargs'],
                    connections[game]['protocol']['connkwargs']
                ))})

        return

    async def setup_relays(self):
        logger.info(self.identifier + "Setting up relays...")
        with open(os.path.dirname(os.path.realpath(sys.argv[0])) + formatsyspath("relays.toml"), "rb") as file:
            relays = tomllib.load(file)

            for bot in relays['bots']:
                if relays['bots'][bot]['active'] is True:
                    source = importlib.import_module(relays['bots'][bot]['path'])
                    classname = getattr(source, relays['bots'][bot]['classname'])
                    client = classname(*relays['bots'][bot]['args'], **relays['bots'][bot]['kwargs'])

                    self.relays.update({bot: Relay(self.queue,
                                                   client,
                                                   relays['bots'][bot]['args'],
                                                   relays['bots'][bot]['kwargs'],
                                                   relays['bots'][bot]['run']['args'],
                                                   relays['bots'][bot]['run']['kwargs'])})

        return

    async def setup_shared_chats(self):
        logger.info(self.identifier + "Setting up shared chat pools...")
        if not self.connections or not self.relays:
            logger.warning(
                self.identifier
                + "Called setup_shared_chats but connections or relays are empty")  # only run if these are already set up

        with open(os.path.dirname(os.path.realpath(sys.argv[0])) + formatsyspath("sharedchats.toml"), "rb") as file:
            shared = tomllib.load(file)

            for chat in shared:
                self.sharedpool.update({chat: SharedChat(shared[chat]['servers'], shared[chat]['relays'])})
                pass

        return

    async def setup_threads(self):
        logger.info(self.identifier + "Setting up threads...")
        if not self.relays:
            logger.warning(self.identifier + "Called setup_threads but relays are empty")

        self.threads.update({relay: threading.Thread(target=self.relays[relay].bot.run,
                                                     args=self.relays[relay].runargs,
                                                     kwargs=self.relays[relay].runkwargs) for relay in self.relays})

        for each in self.threads:
            self.threads[each].start()

        return

    async def create_connection(self, socket_type: str, protocol: asyncio.Protocol,
                                protargs: list, protkwargs: dict, connargs: list, connkwargs: dict,
                                ) -> tuple[asyncio.Transport, asyncio.Protocol] | None:
        loop = asyncio.get_running_loop()
        func = None

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

    async def handle_message(self, *args):
        logger.debug("Handling a message " + str(args))
        return
