import asyncio
import logging
from typing import List

from autobahn.asyncio.websocket import WebSocketServerFactory, WebSocketServerProtocol


class LSDBStreamProtocol(WebSocketServerProtocol):
    active_sessions: List["LSDBStreamProtocol"] = []

    def onConnect(self, request):
        logging.info("Client connecting: {0}".format(request.peer))

    def onOpen(self):
        logging.info("WebSocket connection open.")
        self.active_sessions.append(self)

    def onClose(self, wasClean, code, reason):
        logging.info("WebSocket connection closed: {0}".format(reason))
        self.active_sessions.remove(self)

    @classmethod
    def broadcast(cls, message: str):
        for session in cls.active_sessions:
            if session.is_open:
                session.sendMessage(message.encode("UTF8"), isBinary=False)


async def run_websocket_server():
    factory = WebSocketServerFactory()
    factory.protocol = LSDBStreamProtocol

    loop = asyncio.get_event_loop()
    coro = loop.create_server(factory, "0.0.0.0", 9000)
    await coro
