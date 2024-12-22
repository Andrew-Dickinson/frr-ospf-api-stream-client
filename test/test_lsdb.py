import unittest

import pytest

from lsdb import LSA, RouterLSA, NetworkLSA, ASExternalLSA


class TestLSA(unittest.TestCase):
    def test_header(self):
        lsa = LSA(
            (13, 2, 1, 168430090, 168430090, -2147454788, 30016, 36),
            b"\x02\x00\x00\x01\nFL\x14\nFLc\x02\x00\x00\n",
        )

        self.assertEqual(lsa.ls_age, 13)
        self.assertEqual(lsa.ls_options, 0x02)
        self.assertEqual(lsa.ls_options_e, 1)
        self.assertEqual(lsa.ls_options_mc, 0)
        self.assertEqual(lsa.ls_options_np, 0)
        self.assertEqual(lsa.ls_options_ea, 0)
        self.assertEqual(lsa.ls_options_dc, 0)

        self.assertEqual(lsa.ls_type, 1)
        self.assertEqual(lsa.ls_id, 168430090)
        self.assertEqual(lsa.ls_id__as_ip, "10.10.10.10")
        self.assertEqual(lsa.ls_advertising_router, 168430090)
        self.assertEqual(lsa.ls_advertising_router__as_ip, "10.10.10.10")
        self.assertEqual(lsa.ls_seq, -2147454788)
        self.assertEqual(lsa.ls_checksum, 30016)
        self.assertEqual(lsa.ls_len, 36)

    def test_router_lsa(self):
        lsa = RouterLSA(
            (13, 2, 1, 168430090, 168430090, -2147454788, 30016, 36),
            b"\x02\x00\x00\x01\nFL\x14\nFLc\x02\x00\x00\n",
        )

        with pytest.raises(ValueError):
            NetworkLSA(
                (13, 2, 1, 168430090, 168430090, -2147454788, 30016, 36),
                b"\x02\x00\x00\x01\nFL\x14\nFLc\x02\x00\x00\n",
            )

        with pytest.raises(ValueError):
            ASExternalLSA(
                (13, 2, 1, 168430090, 168430090, -2147454788, 30016, 36),
                b"\x02\x00\x00\x01\nFL\x14\nFLc\x02\x00\x00\n",
            )

        self.assertEqual(
            str(lsa),
            "Type 1 (Router) LSA: ID 10.10.10.10 with seq num -2147454788 from 10.10.10.10",
        )

        self.assertEqual(lsa.router_lsa_options, 0x02)
        self.assertEqual(lsa.router_lsa_options_b, 0)
        self.assertEqual(lsa.router_lsa_options_e, 1)
        self.assertEqual(lsa.router_lsa_options_v, 0)
        self.assertEqual(lsa.link_count, 1)

        self.assertEqual(len(lsa.links), 1)

        self.assertEqual(lsa.links[0].id, 172379156)
        self.assertEqual(lsa.links[0].id__as_ip, "10.70.76.20")
        self.assertEqual(lsa.links[0].data, 172379235)
        self.assertEqual(lsa.links[0].data__as_ip, "10.70.76.99")
        self.assertEqual(lsa.links[0].type, 2)
        self.assertEqual(lsa.links[0].metric, 10)
        self.assertEqual(lsa.links[0].tos_count, 0)

    def test_network_lsa(self):
        lsa = NetworkLSA(
            (8, 2, 2, 172379156, 172377993, -2147460016, 33695, 36),
            b"\xff\xff\xff\x00\nFG\x89\n\n\n\n\nE\x02\x1b",
        )

        with pytest.raises(ValueError):
            RouterLSA(
                (8, 2, 2, 172379156, 172377993, -2147460016, 33695, 36),
                b"\xff\xff\xff\x00\nFG\x89\n\n\n\n\nE\x02\x1b",
            )

        with pytest.raises(ValueError):
            ASExternalLSA(
                (8, 2, 2, 172379156, 172377993, -2147460016, 33695, 36),
                b"\xff\xff\xff\x00\nFG\x89\n\n\n\n\nE\x02\x1b",
            )

        self.assertEqual(
            str(lsa),
            "Type 2 (Network) LSA: ID 10.70.76.20 with seq num -2147460016 from 10.70.71.137",
        )

        self.assertEqual(lsa.network_mask, 0xFFFFFF00)

        self.assertEqual(len(lsa.routers), 3)

        self.assertEqual(lsa.routers[0].id, 172377993)
        self.assertEqual(lsa.routers[0].id__as_ip, "10.70.71.137")

        self.assertEqual(lsa.routers[1].id, 168430090)
        self.assertEqual(lsa.routers[1].id__as_ip, "10.10.10.10")

        self.assertEqual(lsa.routers[2].id, 172294683)
        self.assertEqual(lsa.routers[2].id__as_ip, "10.69.2.27")

    def test_as_external_lsa(self):
        lsa = ASExternalLSA(
            (9, 34, 5, 0, 172294155, -2147482663, 64257, 36),
            b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        )

        with pytest.raises(ValueError):
            RouterLSA(
                (9, 34, 5, 0, 172294155, -2147482663, 64257, 36),
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )

        with pytest.raises(ValueError):
            NetworkLSA(
                (9, 34, 5, 0, 172294155, -2147482663, 64257, 36),
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
            )

        self.assertEqual(
            str(lsa),
            "Type 5 (AS External) LSA: ID 0.0.0.0 with seq num -2147482663 from 10.69.0.11",
        )

        self.assertEqual(lsa.network_mask, 0x00000000)
        self.assertEqual(lsa.is_type_2, 0)
        self.assertEqual(lsa.metric, 0)
        self.assertEqual(lsa.forwarding_address, 0)
        self.assertEqual(lsa.forwarding_address__as_ip, "0.0.0.0")
        self.assertEqual(lsa.external_route_tag, 0)
