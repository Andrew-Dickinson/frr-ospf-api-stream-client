#!/usr/bin/env python3
# -*- coding: utf-8 eval: (blacken-mode 1) -*-
# SPDX-License-Identifier: GPL-2.0-or-later
#
# December 22 2021, Christian Hopps <chopps@labn.net>
#
# Copyright 2021-2022, LabN Consulting, L.L.C.
#

import argparse
import asyncio
import errno
import json
import logging
import socket
import struct
import sys
from asyncio import Lock
from functools import partial
from ipaddress import ip_address as ip
from typing import Dict

from apscheduler.schedulers.asyncio import AsyncIOScheduler

from archival import archive_event_message, archive_db_snapshot
from lsdb import LSDB
from websockets_server import LSDBStreamProtocol, run_websocket_server

FMT_APIMSGHDR = ">BBHL"
FMT_APIMSGHDR_SIZE = struct.calcsize(FMT_APIMSGHDR)

FMT_LSA_FILTER = ">HBB"  # + plus x"I" areas
LSAF_ORIGIN_NON_SELF = 0
LSAF_ORIGIN_SELF = 1
LSAF_ORIGIN_ANY = 2

FMT_LSA_HEADER = ">HBBIIlHH"
FMT_LSA_HEADER_SIZE = struct.calcsize(FMT_LSA_HEADER)

# ------------------------
# Messages to OSPF daemon.
# ------------------------

MSG_REGISTER_OPAQUETYPE = 1
MSG_UNREGISTER_OPAQUETYPE = 2
MSG_REGISTER_EVENT = 3
MSG_SYNC_LSDB = 4
MSG_ORIGINATE_REQUEST = 5
MSG_DELETE_REQUEST = 6
MSG_SYNC_REACHABLE = 7
MSG_SYNC_ISM = 8
MSG_SYNC_NSM = 9
MSG_SYNC_ROUTER_ID = 19

smsg_info = {
    MSG_REGISTER_OPAQUETYPE: ("REGISTER_OPAQUETYPE", "BBxx"),
    MSG_UNREGISTER_OPAQUETYPE: ("UNREGISTER_OPAQUETYPE", "BBxx"),
    MSG_REGISTER_EVENT: ("REGISTER_EVENT", FMT_LSA_FILTER),
    MSG_SYNC_LSDB: ("SYNC_LSDB", FMT_LSA_FILTER),
    MSG_ORIGINATE_REQUEST: ("ORIGINATE_REQUEST", ">II" + FMT_LSA_HEADER[1:]),
    MSG_DELETE_REQUEST: ("DELETE_REQUEST", ">IBBxBL"),
    MSG_SYNC_REACHABLE: ("MSG_SYNC_REACHABLE", ""),
    MSG_SYNC_ISM: ("MSG_SYNC_ISM", ""),
    MSG_SYNC_NSM: ("MSG_SYNC_NSM", ""),
    MSG_SYNC_ROUTER_ID: ("MSG_SYNC_ROUTER_ID", ""),
}

# OSPF API MSG Delete Flag.
OSPF_API_DEL_ZERO_LEN_LSA = 0x01  # send withdrawal with no LSA data

# --------------------------
# Messages from OSPF daemon.
# --------------------------

MSG_REPLY = 10
MSG_READY_NOTIFY = 11
MSG_LSA_UPDATE_NOTIFY = 12
MSG_LSA_DELETE_NOTIFY = 13
MSG_NEW_IF = 14
MSG_DEL_IF = 15
MSG_ISM_CHANGE = 16
MSG_NSM_CHANGE = 17
MSG_REACHABLE_CHANGE = 18
MSG_ROUTER_ID_CHANGE = 20

amsg_info = {
    MSG_REPLY: ("REPLY", "bxxx"),
    MSG_READY_NOTIFY: ("READY_NOTIFY", ">BBxxI"),
    MSG_LSA_UPDATE_NOTIFY: ("LSA_UPDATE_NOTIFY", ">IIBxxx" + FMT_LSA_HEADER[1:]),
    MSG_LSA_DELETE_NOTIFY: ("LSA_DELETE_NOTIFY", ">IIBxxx" + FMT_LSA_HEADER[1:]),
    MSG_NEW_IF: ("NEW_IF", ">II"),
    MSG_DEL_IF: ("DEL_IF", ">I"),
    MSG_ISM_CHANGE: ("ISM_CHANGE", ">IIBxxx"),
    MSG_NSM_CHANGE: ("NSM_CHANGE", ">IIIBxxx"),
    MSG_REACHABLE_CHANGE: ("REACHABLE_CHANGE", ">HH"),
    MSG_ROUTER_ID_CHANGE: ("ROUTER_ID_CHANGE", ">I"),
}

OSPF_API_OK = 0
OSPF_API_NOSUCHINTERFACE = -1
OSPF_API_NOSUCHAREA = -2
OSPF_API_NOSUCHLSA = -3
OSPF_API_ILLEGALLSATYPE = -4
OSPF_API_OPAQUETYPEINUSE = -5
OSPF_API_OPAQUETYPENOTREGISTERED = -6
OSPF_API_NOTREADY = -7
OSPF_API_NOMEMORY = -8
OSPF_API_ERROR = -9
OSPF_API_UNDEF = -10

msg_errname = {
    OSPF_API_OK: "OSPF_API_OK",
    OSPF_API_NOSUCHINTERFACE: "OSPF_API_NOSUCHINTERFACE",
    OSPF_API_NOSUCHAREA: "OSPF_API_NOSUCHAREA",
    OSPF_API_NOSUCHLSA: "OSPF_API_NOSUCHLSA",
    OSPF_API_ILLEGALLSATYPE: "OSPF_API_ILLEGALLSATYPE",
    OSPF_API_OPAQUETYPEINUSE: "OSPF_API_OPAQUETYPEINUSE",
    OSPF_API_OPAQUETYPENOTREGISTERED: "OSPF_API_OPAQUETYPENOTREGISTERED",
    OSPF_API_NOTREADY: "OSPF_API_NOTREADY",
    OSPF_API_NOMEMORY: "OSPF_API_NOMEMORY",
    OSPF_API_ERROR: "OSPF_API_ERROR",
    OSPF_API_UNDEF: "OSPF_API_UNDEF",
}

# msg_info = {**smsg_info, **amsg_info}
msg_info = {}
msg_info.update(smsg_info)
msg_info.update(amsg_info)
msg_name = {k: v[0] for k, v in msg_info.items()}
msg_fmt = {k: v[1] for k, v in msg_info.items()}
msg_size = {k: struct.calcsize(v) for k, v in msg_fmt.items()}


def api_msgname(mt):
    return msg_name.get(mt, str(mt))


def api_errname(ecode):
    return msg_errname.get(ecode, str(ecode))


# -------------------
# API Semantic Errors
# -------------------


class APIError(Exception):
    pass


class MsgTypeError(Exception):
    pass


class SeqNumError(Exception):
    pass


# --------------
# Client Classes
# --------------


class OspfApiClient:
    def __str__(self):
        return "OspfApiClient({})".format(self.server)

    @staticmethod
    def _get_bound_sockets(port):
        s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
        try:
            s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # s1.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            s1.bind(("", port))
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            try:
                s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                # s2.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                s2.bind(("", port + 1))
                return s1, s2
            except Exception:
                s2.close()
                raise
        except Exception:
            s1.close()
            raise

    def __init__(self, server="localhost", handlers=None):
        """A client connection to OSPF Daemon using the OSPF API

        The client object is not created in a connected state.  To connect to the server
        the `connect` method should be called.  If an error is encountered when sending
        messages to the server an exception will be raised and the connection will be
        closed.  When this happens `connect` may be called again to restore the
        connection.

        Args:
            server: hostname or IP address of server default is "localhost"
            handlers: dict of message handlers, the key is the API message
                type, the value is a function. The functions signature is:
                `handler(msg_type, msg, msg_extra, *params)`, where `msg` is the
                message data after the API header, `*params` will be the
                unpacked message values, and msg_extra are any bytes beyond the
                fixed parameters of the message.
        Raises:
            Will raise exceptions for failures with various `socket` modules
            functions such as `socket.socket`, `socket.setsockopt`, `socket.bind`.
        """
        self._seq = 0
        self._s = None
        self._as = None
        self._ls = None
        self._ar = self._r = self._aw = self._w = None
        self.server = server
        self.handlers = handlers if handlers is not None else dict()
        self.write_lock = Lock()

        # try and get consecutive 2 ports
        PORTSTART = 49152
        PORTEND = 65534
        for port in range(PORTSTART, PORTEND + 2, 2):
            try:
                logging.debug("%s: binding to ports %s, %s", self, port, port + 1)
                self._s, self._ls = self._get_bound_sockets(port)
                break
            except OSError as error:
                if error.errno != errno.EADDRINUSE or port == PORTEND:
                    logging.warning("%s: binding port %s error %s", self, port, error)
                    raise
                logging.debug("%s: ports %s, %s in use.", self, port, port + 1)
        else:
            assert False, "Should not reach this code execution point"

    async def _connect_locked(self):
        logging.debug("%s: connect to OSPF API", self)

        loop = asyncio.get_event_loop()

        self._ls.listen()
        try:
            logging.debug("%s: connecting sync socket to server", self)
            await loop.sock_connect(self._s, (self.server, 2607))

            logging.debug("%s: accepting connect from server", self)
            self._as, _ = await loop.sock_accept(self._ls)
        except Exception:
            await self._close_locked()
            raise

        logging.debug("%s: success", self)
        self._r, self._w = await asyncio.open_connection(sock=self._s)
        self._ar, self._aw = await asyncio.open_connection(sock=self._as)
        self._seq = 1

    async def connect(self):
        async with self.write_lock:
            await self._connect_locked()

    @property
    def closed(self):
        "True if the connection is closed."
        return self._seq == 0

    async def _close_locked(self):
        logging.debug("%s: closing", self)
        if self._s:
            if self._w:
                self._w.close()
                await self._w.wait_closed()
                self._w = None
            else:
                self._s.close()
            self._s = None
            self._r = None
        assert self._w is None
        if self._as:
            self._as.close()
            self._as = None
            self._ar = None
        if self._ls:
            self._ls.close()
            self._ls = None
        self._seq = 0

    async def close(self):
        async with self.write_lock:
            await self._close_locked()

    @staticmethod
    async def _msg_read(r, expseq=-1):
        """Read an OSPF API message from the socket `r`

        Args:
            r: socket to read msg from
            expseq: sequence number to expect or -1 for any.
        Raises:
            Will raise exceptions for failures with various `socket` modules,
            Additionally may raise SeqNumError if unexpected seqnum is received.
        """
        try:
            mh = await r.readexactly(FMT_APIMSGHDR_SIZE)
            v, mt, l, seq = struct.unpack(FMT_APIMSGHDR, mh)
            if v != 1:
                raise Exception("received unexpected OSPF API version {}".format(v))
            if expseq == -1:
                logging.debug("_msg_read: got seq: 0x%x on async read", seq)
            elif seq != expseq:
                raise SeqNumError("rx {} != {}".format(seq, expseq))
            msg = await r.readexactly(l) if l else b""
            return mt, msg
        except asyncio.IncompleteReadError:
            raise EOFError

    async def msg_read(self):
        """Read a message from the async notify channel.

        Raises:
            May raise exceptions for failures with various `socket` modules.
        """
        return await OspfApiClient._msg_read(self._ar, -1)

    async def msg_send(self, mt, mp):
        """Send a message to OSPF API and wait for error code reply.

        Args:
            mt: the messaage type
            mp: the message payload
        Returns:
            error: an OSPF_API_XXX error code, 0 for OK.
        Raises:
            Raises SeqNumError if the synchronous reply is the wrong sequence number;
            MsgTypeError if the synchronous reply is not MSG_REPLY. Also,
            may raise exceptions for failures with various `socket` modules,

            The connection will be closed.
        """
        logging.debug("SEND: %s: sending %s seq 0x%x", self, api_msgname(mt), self._seq)
        mh = struct.pack(FMT_APIMSGHDR, 1, mt, len(mp), self._seq)

        seq = self._seq
        self._seq = seq + 1

        try:
            async with self.write_lock:
                self._w.write(mh + mp)
                await self._w.drain()
                mt, mp = await OspfApiClient._msg_read(self._r, seq)

            if mt != MSG_REPLY:
                raise MsgTypeError(
                    "rx {} != {}".format(api_msgname(mt), api_msgname(MSG_REPLY))
                )

            return struct.unpack(msg_fmt[MSG_REPLY], mp)[0]
        except Exception:
            # We've written data with a sequence number
            await self.close()
            raise

    async def msg_send_raises(self, mt, mp=b"\x00" * 4):
        """Send a message to OSPF API and wait for error code reply.

        Args:
            mt: the messaage type
            mp: the message payload
        Raises:
            APIError if the server replies with an error.

            Also may raise exceptions for failures with various `socket` modules,
            as well as MsgTypeError if the synchronous reply is incorrect.
            The connection will be closed for these non-API error exceptions.
        """
        ecode = await self.msg_send(mt, mp)
        if ecode:
            raise APIError("{} error {}".format(api_msgname(mt), api_errname(ecode)))

    async def handle_async_msg(self, mt, msg):
        if mt not in msg_fmt:
            logging.debug("RECV: %s: unknown async msg type %s", self, mt)
            return

        fmt = msg_fmt[mt]
        sz = msg_size[mt]
        tup = struct.unpack(fmt, msg[:sz])
        extra = msg[sz:]

        if mt not in self.handlers:
            logging.debug(
                "RECV: %s: no handlers for msg type %s", self, api_msgname(mt)
            )
            return

        logging.debug("RECV: %s: calling handler for %s", self, api_msgname(mt))
        await self.handlers[mt](mt, msg, extra, *tup)

    #
    # Client to Server Messaging
    #
    @staticmethod
    def lsa_type_mask(*lsa_types):
        "Return a 16 bit mask for each LSA type passed."
        if not lsa_types:
            return 0xFFFF
        mask = 0
        for t in lsa_types:
            assert 0 < t < 16, "LSA type {} out of range [1, 15]".format(t)
            mask |= 1 << t
        return mask

    @staticmethod
    def lsa_filter(origin, areas, lsa_types):
        """Return an LSA filter.

        Return the filter message bytes based on `origin` the `areas` list and the LSAs
        types in the `lsa_types` list.
        """
        mask = OspfApiClient.lsa_type_mask(*lsa_types)
        narea = len(areas)
        fmt = FMT_LSA_FILTER + ("{}I".format(narea) if narea else "")
        # lsa type mask, origin, number of areas, each area
        return struct.pack(fmt, mask, origin, narea, *areas)

    async def req_lsdb_sync(self):
        "Register for all LSA notifications and request an LSDB synchronoization."
        logging.debug("SEND: %s: request LSDB events", self)
        mp = OspfApiClient.lsa_filter(LSAF_ORIGIN_ANY, [], [])
        await self.msg_send_raises(MSG_REGISTER_EVENT, mp)

        logging.debug("SEND: %s: request LSDB sync", self)
        await self.msg_send_raises(MSG_SYNC_LSDB, mp)

    async def req_router_id_sync(self):
        "Request a dump of the current NSM states of all neighbors."
        logging.debug("SEND: %s: request router ID sync", self)
        await self.msg_send_raises(MSG_SYNC_ROUTER_ID)


class OspfLSDBClient(OspfApiClient):
    """A client connection to OSPF Daemon for manipulating Opaque LSA data.

    The client object is not created in a connected state.  To connect to the server
    the `connect` method should be called.  If an error is encountered when sending
    messages to the server an exception will be raised and the connection will be
    closed.  When this happens `connect` may be called again to restore the
    connection.

    Args:
        server: hostname or IP address of server default is "localhost"
        wait_ready: if True then wait for OSPF to signal ready, in newer versions
            FRR ospfd is always ready so this overhead can be skipped.
            default is False.

    Raises:
        Will raise exceptions for failures with various `socket` modules
        functions such as `socket.socket`, `socket.setsockopt`, `socket.bind`.
    """

    def __init__(self, server="localhost"):
        handlers = {
            MSG_LSA_UPDATE_NOTIFY: self._lsa_change_msg,
            MSG_LSA_DELETE_NOTIFY: self._lsa_change_msg,
            MSG_ROUTER_ID_CHANGE: self._router_id_msg,
        }

        super().__init__(server, handlers)

        self.router_id = ip(0)
        self.router_id_change_cb = None

        self.lsid_seq_num = {}
        self.lsa_change_cb = None

    async def _handle_msg_loop(self):
        try:
            logging.debug("entering async msg handling loop")
            while True:
                mt, msg = await self.msg_read()
                if mt in amsg_info:
                    await self.handle_async_msg(mt, msg)
                else:
                    mts = api_msgname(mt)
                    logging.warning(
                        "ignoring unexpected msg: %s len: %s", mts, len(msg)
                    )
        except EOFError:
            logging.info("Got EOF from OSPF API server on async notify socket")
            return 2
        except Exception:
            logging.exception("Exception while handling async msg")
            return 99

    async def _lsa_change_msg(self, mt, msg, extra, ifaddr, aid, is_self, *ls_header):
        (
            lsa_age,  # ls_age,
            _,  # ls_options,
            lsa_type,
            ls_id,
            _,  # ls_adv_router,
            ls_seq,
            _,  # ls_cksum,
            ls_len,
        ) = ls_header

        if mt == MSG_LSA_UPDATE_NOTIFY:
            ts = "update"
        else:
            assert mt == MSG_LSA_DELETE_NOTIFY
            ts = "delete"

        logging.info(
            "RECV: LSA %s msg for LSA %s in area %s seq 0x%x len %s age %s",
            ts,
            ip(ls_id),
            ip(aid),
            ls_seq,
            ls_len,
            lsa_age,
        )

        pre_lsa_size = msg_size[mt] - FMT_LSA_HEADER_SIZE
        lsa = msg[pre_lsa_size:]

        if self.lsa_change_cb:
            self.lsa_change_cb(mt, ifaddr, aid, ls_header, extra, lsa)

    async def _router_id_msg(self, mt, msg, extra, router_id):
        router_id = ip(router_id)
        logging.info("RECV: %s router ID %s", api_msgname(mt), router_id)
        old_router_id = self.router_id
        if old_router_id == router_id:
            return

        self.router_id = router_id
        logging.info(
            "RECV: %s new router ID %s older router ID %s",
            api_msgname(mt),
            router_id,
            old_router_id,
        )

        if self.router_id_change_cb:
            logging.info("RECV: %s calling callback", api_msgname(mt))
            await self.router_id_change_cb(router_id, old_router_id)

    async def monitor_lsa(self, callback=None):
        """Monitor changes to LSAs.

        Args:
            callback: if given, callback will be called when changes are received for
                any LSA. The callback signature is:

                `callback(msg_type, ifaddr, area_id, lsa_header, extra, lsa)`

                Args:
                    msg_type: MSG_LSA_UPDATE_NOTIFY or MSG_LSA_DELETE_NOTIFY
                    ifaddr: integer identifying an interface (by IP address)
                    area_id: integer identifying an area
                    lsa_header: the LSA header as an unpacked tuple (fmt: ">HBBIILHH")
                    extra: the octets that follow the LSA header
                    lsa: the octets of the full lsa
        """
        self.lsa_change_cb = callback
        await self.req_lsdb_sync()

    async def monitor_router_id(self, callback=None):
        """Monitor the OSPF router ID.

        The property `router_id` contains the OSPF urouter ID.
        This value is updated prior to calling the `callback`

        Args:
            callback: callback will be called when the router ID changes.
                The callback signature is:

                `callback(new_router_id, old_router_id)`

                Args:
                    new_router_id: the new router ID
                    old_router_id: the old router ID
        """
        self.router_id_change_cb = callback
        await self.req_router_id_sync()


def write_db_snapshot_loop(lsdb: LSDB, path_prefix: str):
    db_snapshot = lsdb.to_api_dict()
    archive_db_snapshot(db_snapshot, path_prefix)
    logging.info("Wrote DB snapshot due to heartbeat")


def initialize_scheduler():
    scheduler = AsyncIOScheduler()
    scheduler.start()
    return scheduler


async def async_main(args):
    c = OspfLSDBClient(args.server)
    await c.connect()

    lsdb = LSDB()

    def print_event(event: Dict):
        print(json.dumps(event))

    def ws_broadcast_event(event: Dict):
        LSDBStreamProtocol.broadcast(json.dumps(event))

    if not args.mute_stdout_stream:
        lsdb.add_event_listener(print_event)

    if args.events_path_prefix:
        lsdb.add_event_listener(
            partial(archive_event_message, path_prefix=args.events_path_prefix)
        )

    try:
        asyncio.create_task(c._handle_msg_loop())

        async def trigger_and_unhook(*args):
            logging.warning("LSDB loaded!")
            c.router_id_change_cb = None
            lsdb.initial_load_active = False

        logging.warning("Waiting for initial load to complete...")
        await c.monitor_lsa(lsdb.recv_lsa_callback)

        # We don't actually care about the router ID callback, but we use this to queue up an event
        # in the sync queue so that we know when the initial load has completed, and we can start
        # streaming the diff to our consumers
        await c.monitor_router_id(trigger_and_unhook)

        async def wait_for_lsdb_load():
            while lsdb.initial_load_active:
                await asyncio.sleep(0.2)

        await wait_for_lsdb_load()

        # Once the LSDB is loaded, Initiate the async websockets server in the background
        if args.ws_listen:
            asyncio.create_task(run_websocket_server(args.ws_listen))
            lsdb.add_event_listener(ws_broadcast_event)

        # Also start up an async task to write out api.andrew.mesh API payloads
        if args.snapshots_path_prefix:
            scheduler = initialize_scheduler()
            scheduler.add_job(
                partial(write_db_snapshot_loop, lsdb, args.snapshots_path_prefix),
                "cron",
                minute="*",
            )
    except Exception as error:
        logging.error("async_main: unexpected error: %s", error, exc_info=True)
        return 2

    try:
        logging.info("Sleeping forever")
        while True:
            await asyncio.sleep(120)
    except EOFError:
        logging.info("Got EOF from OSPF API server on async notify socket")
        return 2


def main(*args):
    ap = argparse.ArgumentParser(args)
    ap.add_argument("--server", default="localhost", help="OSPF API server")
    ap.add_argument(
        "--ws-listen", help="Interface and port to listen for websockets sessions on"
    )
    ap.add_argument(
        "--events-path-prefix", help="File path prefix for events JSONL output files"
    )
    ap.add_argument(
        "--snapshots-path-prefix",
        help="File path prefix for LSDB snapshot JSON output files",
    )
    ap.add_argument(
        "--mute-stdout-stream",
        action="store_true",
        help="Pass to disable the event stream in stdout",
    )
    ap.add_argument("-v", "--verbose", action="store_true", help="be verbose")
    args = ap.parse_args()

    level = logging.DEBUG if args.verbose else logging.WARNING
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s: %(name)s %(message)s",
    )

    logging.info("ospfclient: starting")

    status = 3
    try:
        status = asyncio.run(async_main(args))
    except KeyboardInterrupt:
        logging.info("Exiting, received KeyboardInterrupt in main")
    except Exception as error:
        logging.info("Exiting, unexpected exception %s", error, exc_info=True)
    else:
        logging.info("ospfclient: clean exit")

    return status


if __name__ == "__main__":
    exit_status = main()
    sys.exit(exit_status)
