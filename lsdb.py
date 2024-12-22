import abc
import asyncio
import datetime
import ipaddress
import json
import logging
import math
import struct
import sys
from collections import defaultdict
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal, Tuple, Dict, Any, Callable, Optional, List, Union

from frozendict import frozendict
import jsondiff as jd
from jsondiff import diff

import netaddr

MSG_TYPE = Literal["MSG_LSA_UPDATE_NOTIFY", "MSG_LSA_DELETE_NOTIFY"]

ROUTER_LSA_HEADER_EXT = ">BxH"
ROUTER_LINK_FORMAT = ">IIBBH"

NETWORK_HEADER_EXT = ">L"

AS_EXTERNAL_HEADER_EXT = ">IIII"

LSA_TYPE_ROUTER = 1
LSA_TYPE_NETWORK = 2
LSA_TYPE_AS_EXTERNAL = 5

LSA_TYPE_NAMES = {
    LSA_TYPE_ROUTER: "Router",
    LSA_TYPE_NETWORK: "Network",
    LSA_TYPE_AS_EXTERNAL: "AS External",
}

LSA_MAX_AGE = datetime.timedelta(hours=1).total_seconds()
LSA_MAX_AGE_DIFF = datetime.timedelta(minutes=15).total_seconds()
MIN_LS_ARRIVAL = datetime.timedelta(seconds=1)

LSA_HEADER_FIELD_MAPPINGS: Dict[str, Tuple[int, Optional[int], Optional[int]]] = {
    "ls_age": (0, None, None),
    "ls_options": (1, None, None),
    "ls_options_e": (1, 0x02, 1),
    "ls_options_mc": (1, 0x04, 2),
    "ls_options_np": (1, 0x08, 3),
    "ls_options_ea": (1, 0x10, 4),
    "ls_options_dc": (1, 0x20, 5),
    "ls_type": (2, None, None),
    "ls_id": (3, None, None),
    "ls_advertising_router": (4, None, None),
    "ls_seq": (5, None, None),
    "ls_checksum": (6, None, None),
    "ls_len": (7, None, None),
}

LSA_HEADER_EXT_FIELD_MAPPINGS: Dict[
    Literal[LSA_TYPE_ROUTER, LSA_TYPE_NETWORK, LSA_TYPE_AS_EXTERNAL],
    Dict[
        str,
        Tuple[
            int,
            Optional[int],
            Optional[int],
        ],
    ],
] = {
    LSA_TYPE_ROUTER: {
        "router_lsa_options": (0, None, None),
        "router_lsa_options_b": (0, 0x01, 0),
        "router_lsa_options_e": (0, 0x02, 1),
        "router_lsa_options_v": (0, 0x04, 2),
        "link_count": (1, None, None),
    },
    LSA_TYPE_NETWORK: {
        "network_mask": (0, None, None),
    },
    LSA_TYPE_AS_EXTERNAL: {
        "network_mask": (0, None, None),
        "is_type_2": (1, 0x80000000, 31),
        "metric": (1, 0x00FFFFFF, 0),
        "forwarding_address": (2, None, None),
        "external_route_tag": (3, None, None),
    },
}

LSA_FIELD_MAPPING_MODIFIER_FUNCS: Dict[str, Callable[[int], Any]] = {
    None: lambda x: x,
    "as_ip": lambda x: str(netaddr.IPAddress(x)),
    # "as_bitflags": lambda x: [(x >> i) & 1 == 1 for i in range(7, -1, -1)],
}

JSONDIFF_TO_HUMAN = {
    jd.discard: "remove",
    jd.add: "add",
}

POST_DELETE_LSA_TTL = datetime.timedelta(seconds=10)


def addr_and_mask_to_cidr(addr: int, mask: int) -> str:
    if mask == 0:
        prefix_len = 0
    else:
        mask_binary_string = bin(mask)
        assert "b0" not in mask_binary_string
        assert "01" not in mask_binary_string
        assert len(mask_binary_string[2:]) == 32
        prefix_len = mask_binary_string[2:].count("1")

    assert prefix_len <= 32
    assert prefix_len >= 0
    network_addr_int = addr & mask
    # network_addr_int = (addr >> prefix_len) << prefix_len
    network_addr = ipaddress.ip_address(network_addr_int)
    return f"{str(network_addr)}/{prefix_len}"


class LSAException(Exception):
    pass


class LSAChecksumValidationException(LSAException):
    pass


class LSA(abc.ABC):
    def __getattr__(self, attr: str) -> Any:
        def mask_and_shift(val: int, mask: int, shift: int) -> int:
            if mask is not None:
                masked = val & mask
            else:
                masked = val

            if shift is not None:
                return masked >> shift

            return masked

        modifier_func_name = None
        if "__" in attr:
            attr, modifier_func_name = attr.split("__")

        try:
            modifier_func = LSA_FIELD_MAPPING_MODIFIER_FUNCS[modifier_func_name]
        except KeyError:
            raise AttributeError(f"{attr} is not a valid attribute")

        try:
            idx, mask, shift = LSA_HEADER_FIELD_MAPPINGS[attr]
            container = self.header
        except KeyError:
            try:
                idx, mask, shift = LSA_HEADER_EXT_FIELD_MAPPINGS[self.ls_type][attr]
                container = self.header_ext
            except KeyError:
                raise AttributeError(f"{attr} is not a valid attribute")

        return modifier_func(mask_and_shift(container[idx], mask, shift))

    def __init__(
        self,
        lsa_header: Tuple[int, int, int, int, int, int, int, int],
        lsa_data: bytes,
    ):
        self.header = lsa_header
        self.body = lsa_data
        self.lsdb = None

    def __repr__(self):
        return f"Type {self.ls_type} ({LSA_TYPE_NAMES[self.ls_type]}) LSA: ID {self.ls_id__as_ip} with seq num {self.ls_seq} from {self.ls_advertising_router__as_ip}"

    def __lt__(self, other):
        # RFC 2328 Section 13.1
        if self.ls_seq != other.ls_seq:
            return self.ls_seq < other.ls_seq

        if self.ls_checksum != other.ls_checksum:
            return self.ls_seq < other.ls_seq

        if self.ls_age == LSA_MAX_AGE and other.ls_age != LSA_MAX_AGE:
            return False

        if other.ls_age == LSA_MAX_AGE and self.ls_age != LSA_MAX_AGE:
            return True

        if abs(other.ls_age - self.ls_age) > LSA_MAX_AGE_DIFF:
            return self.ls_age < other.ls_age

        return False

    def attach_to_lsdb(self, lsdb: "LSDB") -> None:
        self.lsdb = lsdb

    @property
    def identifier_tuple(self):
        return self.ls_type, self.ls_id, self.ls_advertising_router

    @property
    def internal_entity_id(self):
        if self.ls_type == LSA_TYPE_NETWORK:
            return self.network_cidr
        else:
            return self.ls_advertising_router__as_ip

    @property
    def header_ext(self) -> Tuple:
        raise NotImplementedError("Subclasses must implement this function")

    def header_dict(self) -> Dict[str, Union[int, str]]:
        return {
            # "ls_age": self.ls_age,
            # "ls_options_e": bool(self.ls_options_e),
            # "ls_options_mc": bool(self.ls_options_mc),
            # "ls_options_np": bool(self.ls_options_np),
            # "ls_options_ea": bool(self.ls_options_ea),
            # "ls_options_dc": bool(self.ls_options_dc),
            "ls_type": self.ls_type,
            "ls_id": self.ls_id__as_ip,
            "ls_advertising_router": self.ls_advertising_router__as_ip,
            # "ls_seq": self.ls_seq,
            # "ls_checksum": self.ls_checksum,
            # "ls_len": self.ls_len,
        }

    def diff_list(
        self, old: Optional["LSA"], new: Optional["LSA"]
    ) -> List[Dict[str, Any]]:
        if new and old and new.ls_type != new.ls_type:
            raise ValueError(
                f"Cannot check diff between {new} and {old} as they are different LSA types"
            )

        return self._diff_list(old, new)

    @staticmethod
    def _diff_list(old: Optional["LSA"], new: Optional["LSA"]) -> List[Dict[str, Any]]:
        raise NotImplementedError("Subclasses must implement this function")

    def to_dict(self) -> Dict[str, Any]:
        raise NotImplementedError("Subclasses must implement this function")

    @classmethod
    def construct_lsa(
        cls,
        lsa_header: Tuple[int, int, int, int, int, int, int, int],
        lsa_body: bytes,
    ) -> "LSA":
        dummy_lsa = cls(lsa_header, lsa_body)
        if dummy_lsa.ls_type == 1:
            return RouterLSA(lsa_header, lsa_body)
        elif dummy_lsa.ls_type == 2:
            return NetworkLSA(lsa_header, lsa_body)
        elif dummy_lsa.ls_type == 5:
            return ASExternalLSA(lsa_header, lsa_body)
        else:
            raise NotImplementedError(
                f"LSA type {dummy_lsa.ls_type} is not implemented"
            )


class RouterLSA(LSA):
    @dataclass
    class RouterLink:
        id: int
        data: int
        type: int
        tos_count: int
        metric: int

        @property
        def id__as_ip(self) -> str:
            return str(netaddr.IPAddress(self.id))

        @property
        def data__as_ip(self) -> str:
            return str(netaddr.IPAddress(self.data))

    def __init__(
        self, lsa_header: Tuple[int, int, int, int, int, int, int, int], lsa_data: bytes
    ):
        super().__init__(lsa_header, lsa_data)
        if self.ls_type != LSA_TYPE_ROUTER:
            raise ValueError(f"Invalid type {self.ls_type}, expected {LSA_TYPE_ROUTER}")

    @property
    def header_ext(self) -> Tuple:
        return struct.unpack(ROUTER_LSA_HEADER_EXT, self.body[:4])

    @property
    def links(self) -> List[RouterLink]:
        links_data = self.body[4:]
        assert (
            len(links_data) == self.link_count * 12
        )  # Invariant for TOS-free LSA updates

        links = []
        for i in range(self.link_count):
            link_data = struct.unpack(
                ROUTER_LINK_FORMAT, links_data[i * 12 : (i + 1) * 12]
            )
            link = RouterLSA.RouterLink(*link_data)
            assert link.tos_count == 0
            links.append(link)

        return links

    def to_dict(self) -> Dict[str, Any]:
        links_json = defaultdict(set)
        for link in self.links:
            if link.type == 1:
                links_json["router"].add(
                    frozendict({"id": link.id__as_ip, "metric": link.metric})
                )
            elif link.type == 2:
                if not self.lsdb:
                    raise RuntimeError(
                        "You must attach an LSDB instance to this LSA to serialize network links"
                    )

                network_lsa = self.lsdb.dr_map.get(link.id__as_ip)

                if not network_lsa:
                    raise ValueError(
                        f"Could not find network LSA for DR address {link.id__as_ip} in LSDB {self.lsdb}"
                    )

                network_cidr = addr_and_mask_to_cidr(
                    network_lsa.ls_id, network_lsa.network_mask
                )
                links_json["network"].add(
                    frozendict(
                        {
                            "id": network_cidr,
                            # "id": link.id__as_ip,  ### WRONG
                            "metric": link.metric,
                        }
                    )
                )
            elif link.type == 3:
                links_json["stubnet"].add(
                    frozendict(
                        {
                            "id": addr_and_mask_to_cidr(link.id, link.data),
                            "metric": link.metric,
                        }
                    )
                )
            else:
                raise ValueError(
                    f"Unsupported link type: {link.type} in {link} on {self}"
                )

        return links_json

    @staticmethod
    def _diff_list(
        old: Optional["RouterLSA"], new: Optional["RouterLSA"]
    ) -> List[Dict[str, Any]]:
        try:
            old_routes: Dict[str, set] = old.to_dict() if old else {}
            new_routes: Dict[str, set] = new.to_dict() if new else {}
        except ValueError:
            # LSDB not yet filled case for network links
            return []

        output = []

        route_types = set(old_routes.keys()) | set(new_routes.keys())
        for route_type in route_types:
            if route_type not in old_routes:
                old_routes[route_type] = set()
            if route_type not in new_routes:
                new_routes[route_type] = set()

        lsa = new if new else old

        for route_type in route_types:
            old_links = old_routes[route_type]
            new_links = new_routes[route_type]

            removed_links = old_links - new_links
            added_links = new_links - old_links

            changes = {("removed", link) for link in removed_links} | {
                ("added", link) for link in added_links
            }

            for change_verb, content in changes:
                output.append(
                    {
                        "entity": {
                            "type": "router",
                            "id": lsa.internal_entity_id,
                        },
                        change_verb: ({"link": {route_type: content}}),
                    }
                )

        return output


class NetworkLSA(LSA):
    @dataclass
    class RouterID:
        id: int

        @property
        def id__as_ip(self) -> str:
            return str(netaddr.IPAddress(self.id))

    def __init__(
        self, lsa_header: Tuple[int, int, int, int, int, int, int, int], lsa_data: bytes
    ):
        super().__init__(lsa_header, lsa_data)
        if self.ls_type != LSA_TYPE_NETWORK:
            raise ValueError(
                f"Invalid type {self.ls_type}, expected {LSA_TYPE_NETWORK}"
            )

    @property
    def header_ext(self) -> Tuple:
        return struct.unpack(NETWORK_HEADER_EXT, self.body[:4])

    @property
    def routers(self) -> List[RouterID]:
        router_ids_bytes = self.body[4:]
        assert len(router_ids_bytes) % 4 == 0
        router_count = len(router_ids_bytes) // 4

        routers = []
        for i in range(router_count):
            router_id_as_bytes = router_ids_bytes[i * 4 : (i + 1) * 4]
            router_id_as_int = struct.unpack(">I", router_id_as_bytes)[0]
            routers.append(self.RouterID(router_id_as_int))

        return routers

    @property
    def network_cidr(self):
        return addr_and_mask_to_cidr(self.ls_id, self.network_mask)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dr": self.ls_advertising_router__as_ip,
            "routers": {router.id__as_ip for router in self.routers},
        }

    @staticmethod
    def _diff_list(
        old: Optional["NetworkLSA"], new: Optional["NetworkLSA"]
    ) -> List[Dict[str, Any]]:
        old_routers: set = old.to_dict()["routers"] if old else set()
        new_routers: set = new.to_dict()["routers"] if new else set()

        output = []

        removed_routers = old_routers - new_routers
        added_routers = new_routers - old_routers

        changes = {("removed", router) for router in removed_routers} | {
            ("added", router) for router in added_routers
        }

        lsa = new if new else old
        for change_verb, content in changes:
            output.append(
                {
                    "entity": {
                        "type": "network",
                        "id": lsa.network_cidr,
                    },
                    change_verb: ({"router": content}),
                }
            )

        return output


class ASExternalLSA(LSA):

    def __init__(
        self, lsa_header: Tuple[int, int, int, int, int, int, int, int], lsa_data: bytes
    ):
        super().__init__(lsa_header, lsa_data)
        if self.ls_type != LSA_TYPE_AS_EXTERNAL:
            raise ValueError(
                f"Invalid type {self.ls_type}, expected {LSA_TYPE_AS_EXTERNAL}"
            )

    @property
    def header_ext(self) -> Tuple:
        return struct.unpack(AS_EXTERNAL_HEADER_EXT, self.body[:16])

    def to_dict(self) -> Dict[str, Any]:
        route = {
            "id": addr_and_mask_to_cidr(self.ls_id, self.network_mask),
        }
        if self.is_type_2:
            route["metric2"] = self.metric
        else:
            route["metric"] = self.metric

        if self.forwarding_address:
            route["via"] = self.forwarding_address__as_ip

        return route

    @staticmethod
    def _diff_list(
        old: Optional["ASExternalLSA"], new: Optional["ASExternalLSA"]
    ) -> List[Dict[str, Any]]:
        if new and old:
            return []

        lsa = new if new else old
        verb = "added" if new else "removed"

        return [
            {
                "entity": {
                    "type": "router",
                    "id": lsa.internal_entity_id,
                },
                verb: {"link": {"external": lsa.to_dict()}},
            }
        ]


def hexdump(data: bytes):
    def to_printable_ascii(byte):
        return chr(byte) if 32 <= byte <= 126 else "."

    offset = 0
    while offset < len(data):
        chunk = data[offset : offset + 4]
        hex_values = " ".join(f"{byte:02x}" for byte in chunk)
        ascii_values = "".join(to_printable_ascii(byte) for byte in chunk)
        print(f"{offset:08x}  {hex_values:<48}  |{ascii_values}|")
        offset += 4


class LSDB:
    def __init__(self):
        self.lsa_dict: Dict[
            Tuple[int, int, int], Tuple[LSA, datetime.datetime, bool]
        ] = {}
        self.expiring_queue = []

        asyncio.create_task(self._clear_expired_items())

    async def _clear_expired_items(self):
        try:
            while True:
                while len(self.expiring_queue):
                    expiry_time, lsa = self.expiring_queue[0]
                    if expiry_time < datetime.datetime.now(tz=datetime.timezone.utc):
                        self.expiring_queue.pop(0)
                        if (
                            lsa.identifier_tuple in self.lsa_dict
                            and self.lsa_dict[lsa.identifier_tuple][2]
                        ):
                            del self.lsa_dict[lsa.identifier_tuple]
                            # Print delete message
                            diff_list = lsa.diff_list(lsa, None)
                            for item in diff_list:
                                print(json.dumps(item))
                    else:
                        # The list is guaranteed to be ordered, no need to scan
                        # through all the items that aren't ready yet
                        break

                await asyncio.sleep(1)
        except Exception:
            logging.exception("Exception while clearing expired items")
            return 98

    def get_lsa(self, lsa: LSA) -> Tuple[LSA, datetime.datetime, bool]:
        result = self.lsa_dict.get(lsa.identifier_tuple)
        return result if result else (None, None, None)

    def delete_lsa(self, lsa: LSA) -> None:
        if lsa.identifier_tuple in self.lsa_dict:
            if self.lsa_dict[lsa.identifier_tuple][2]:
                delete_recv_time = self.lsa_dict[lsa.identifier_tuple][1]
            else:
                delete_recv_time = datetime.datetime.now(tz=datetime.timezone.utc)

            self.lsa_dict[lsa.identifier_tuple] = (
                self.lsa_dict[lsa.identifier_tuple][0],
                delete_recv_time,
                True,
            )

            self.expiring_queue.append((delete_recv_time + POST_DELETE_LSA_TTL, lsa))

    def put_lsa(self, lsa: LSA) -> None:
        self.lsa_dict[lsa.identifier_tuple] = (
            lsa,
            datetime.datetime.now(tz=datetime.timezone.utc),
            False,
        )
        lsa.attach_to_lsdb(self)

    @property
    def lsas_by_entity(self):
        entity_mapping: Dict[str, LSA] = {}
        for lsa, _ in self.lsa_dict.values():
            entity_mapping[lsa.internal_entity_id] = lsa

        return entity_mapping

    @property
    def dr_map(self):
        dr_to_lsa_map: Dict[str, LSA] = {}
        for lsa, _ in self.lsa_dict.values():
            if lsa.ls_type == LSA_TYPE_NETWORK:
                # network_cidr = addr_and_mask_to_cidr(lsa.ls_id, lsa.network_mask)
                # networks[network_cidr] = {
                #     "dr": lsa.ls_advertising_router__as_ip,
                #     "routers": [router.id__as_ip for router in lsa.routers],
                # }
                dr_to_lsa_map[lsa.ls_id__as_ip] = lsa

        return dr_to_lsa_map

    def to_api_dict(self) -> Dict[str, Any]:
        dr_to_lsa_map = self.dr_map

        networks = {}
        routers = defaultdict(lambda: {"links": defaultdict(set)})

        for lsa, _ in self.lsa_dict.values():
            if lsa.ls_type == LSA_TYPE_NETWORK:
                networks[lsa.internal_entity_id] = lsa.to_dict()

        for lsa, _ in self.lsa_dict.values():
            if lsa.ls_type == LSA_TYPE_ROUTER:
                routers[lsa.internal_entity_id]["links"] |= lsa.to_dict()
            elif lsa.ls_type == LSA_TYPE_AS_EXTERNAL:
                routers[lsa.internal_entity_id]["links"]["external"].add(
                    frozendict(lsa.to_dict())
                )

        return {
            "areas": {"0.0.0.0": {"networks": networks, "routers": routers}},
            "updated": int(datetime.datetime.now(tz=datetime.timezone.utc).timestamp()),
        }


global_ls_db: Optional[LSDB] = None


def recv_lsa_callback(
    msg_type: int,
    ifaddr: int,
    area_id: int,
    lsa_header: Tuple[int, int, int, int, int, int, int, int],
    lsa_data: bytes,
    full_lsa_message: bytes,
):
    global global_ls_db
    if not global_ls_db:
        global_ls_db = LSDB()

    assert area_id == 0

    lsa = LSA.construct_lsa(lsa_header, lsa_data)

    existing_db_copy, last_write, delete_bit = global_ls_db.get_lsa(lsa)
    # ttl_expired = (
    #     delete_bit
    #     and (datetime.datetime.now(tz=datetime.timezone.utc) - last_write)
    #     > POST_DELETE_LSA_TTL
    # )

    if msg_type == MSG_LSA_DELETE_NOTIFY and existing_db_copy:
        global_ls_db.delete_lsa(lsa)

        # # Disabled for router and network LSAs to allow diffs
        # if lsa.ls_type == LSA_TYPE_AS_EXTERNAL:
        #     global_ls_db.delete_lsa(lsa)
        #     print(
        #         json.dumps(
        #             {
        #                 "entity": {
        #                     "type": "router",
        #                     "id": lsa.internal_entity_id,
        #                 },
        #                 "remove": {"link": {"external": lsa.to_dict()}},
        #             }
        #         )
        #     )
        return

    if lsa.ls_age == LSA_MAX_AGE and (not existing_db_copy or delete_bit):
        return  # Drop per RFC 2328 Section 13.0 (4)

    if delete_bit or not existing_db_copy or existing_db_copy < lsa:
        if (
            existing_db_copy
            and not delete_bit
            and (datetime.datetime.now(tz=datetime.timezone.utc) - last_write)
            < MIN_LS_ARRIVAL
        ):
            return  # Drop per RFC 2328 Section 13.0 (5)(a)

        global_ls_db.put_lsa(lsa)

        # if existing_db_copy and not ttl_expired:
        if existing_db_copy:
            output = existing_db_copy.diff_list(existing_db_copy, lsa)
            for line in output:
                print(json.dumps(line))
        else:
            output = lsa.diff_list(None, lsa)
            for line in output:
                print(json.dumps(line))


from ospfclient import MSG_LSA_DELETE_NOTIFY
