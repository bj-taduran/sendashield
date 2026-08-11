"""Verifies the outbound-network guard in conftest.py actually blocks sockets.

If this test fails, every other test in the suite may be silently allowed to
hit real provider APIs — treat a failure here as a build break.
"""

from __future__ import annotations

import socket

import pytest

from conftest import BlockedNetworkAccess


def test_socket_connect_is_blocked() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    with pytest.raises(BlockedNetworkAccess):
        sock.connect(("example.com", 80))


def test_create_connection_is_blocked() -> None:
    with pytest.raises(BlockedNetworkAccess):
        socket.create_connection(("example.com", 80))


def test_getaddrinfo_is_blocked() -> None:
    with pytest.raises(BlockedNetworkAccess):
        socket.getaddrinfo("example.com", 80)
