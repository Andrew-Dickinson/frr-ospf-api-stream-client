import abc
import datetime
import math
import struct
from dataclasses import dataclass
from datetime import timedelta
from typing import Literal, Tuple, Dict, Any, Callable, Optional, List, Union

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

    def to_dict(self) -> Dict[str, Any]:
        return {**self.header_dict(), **self._to_dict()}

    def _to_dict(self) -> Dict[str, Any]:
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

    def _to_dict(self) -> Dict[str, Any]:
        return {
            "router_lsa_options_b": bool(self.router_lsa_options_b),
            "router_lsa_options_e": bool(self.router_lsa_options_e),
            "router_lsa_options_v": bool(self.router_lsa_options_v),
            "link_count": self.link_count,
            "links": [
                {
                    "id": link.id__as_ip,
                    "data": link.data__as_ip,
                    "type": link.type,
                    "tos_count": link.tos_count,
                    "metric": link.metric,
                }
                for link in self.links
            ],
        }


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

    def _to_dict(self) -> Dict[str, Any]:
        return {
            "network_mask": self.network_mask,
            "routers": [
                {
                    "id": router.id__as_ip,
                }
                for router in self.routers
            ],
        }


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

    def _to_dict(self) -> Dict[str, Any]:
        return {
            "network_mask": self.network_mask,
            "is_type_2": bool(self.is_type_2),
            "metric": self.metric,
            "forwarding_address": self.forwarding_address__as_ip,
            "external_route_tag": self.external_route_tag,
        }


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


global_ls_db: Dict[Tuple[int, int, int], Tuple[LSA, datetime.datetime]] = {}


def recv_lsa_callback(
    msg_type: int,
    ifaddr: int,
    area_id: int,
    lsa_header: Tuple[int, int, int, int, int, int, int, int],
    lsa_data: bytes,
    full_lsa_message: bytes,
):
    assert area_id == 0

    lsa = LSA.construct_lsa(lsa_header, lsa_data)
    lsa_identifier_tuple = (lsa.ls_type, lsa.ls_id, lsa.ls_advertising_router)

    existing_db_copy = global_ls_db.get(lsa_identifier_tuple)

    if msg_type == MSG_LSA_DELETE_NOTIFY and existing_db_copy:
        # Disabled to allow diffs
        # del global_ls_db[lsa_identifier_tuple]
        return
    else:
        pass

    if lsa.ls_age == LSA_MAX_AGE and not existing_db_copy:
        return  # Drop per RFC 2328 Section 13.0 (4)

    if not existing_db_copy or existing_db_copy[0] < lsa:
        if (
            existing_db_copy
            and (datetime.datetime.now(tz=datetime.timezone.utc) - existing_db_copy[1])
            < MIN_LS_ARRIVAL
        ):
            return  # Drop per RFC 2328 Section 13.0 (5)(a)

        if existing_db_copy:
            old_dict = existing_db_copy[0].to_dict()
            new_dict = lsa.to_dict()
            pass

        global_ls_db[lsa_identifier_tuple] = (
            lsa,
            datetime.datetime.now(tz=datetime.timezone.utc),
        )


from ospfclient import MSG_LSA_DELETE_NOTIFY