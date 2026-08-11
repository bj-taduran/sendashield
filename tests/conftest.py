"""Test-wide guards.

Blocks all outbound network sockets for the duration of the test run, so a
test can never accidentally hit a real provider API, even by mistake.
Adapters must be tested against fakes or recorded fixtures (see
docs/build-plan.md, Phase 4) — this fixture is the backstop that makes a
silent regression into a loud failure instead.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator
from typing import Any

import pytest


class BlockedNetworkAccess(RuntimeError):
    """Raised when test code attempts to open a real network connection."""


_real_socket = socket.socket


class _GuardedSocket(_real_socket):
    """A socket subclass that refuses to ever actually connect."""

    def connect(self, *args: Any, **kwargs: Any) -> Any:
        raise BlockedNetworkAccess(
            "Outbound network access is blocked during tests. "
            "Use a fake adapter or a recorded fixture instead of a real socket."
        )

    def connect_ex(self, *args: Any, **kwargs: Any) -> Any:
        raise BlockedNetworkAccess(
            "Outbound network access is blocked during tests. "
            "Use a fake adapter or a recorded fixture instead of a real socket."
        )


def _blocked_create_connection(*args: Any, **kwargs: Any) -> Any:
    raise BlockedNetworkAccess(
        "Outbound network access is blocked during tests. "
        "Use a fake adapter or a recorded fixture instead of a real socket."
    )


def _blocked_getaddrinfo(*args: Any, **kwargs: Any) -> Any:
    raise BlockedNetworkAccess(
        "DNS resolution is blocked during tests. "
        "Use a fake adapter or a recorded fixture instead of a real socket."
    )


@pytest.fixture(autouse=True)
def _block_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Autouse: replace socket-level primitives so no test can dial out.

    Covers socket.socket().connect()/connect_ex() (the low-level path),
    socket.create_connection() (used by urllib/http.client), and
    socket.getaddrinfo() (DNS resolution, which is itself outbound traffic).
    """
    monkeypatch.setattr(socket, "socket", _GuardedSocket)
    monkeypatch.setattr(socket, "create_connection", _blocked_create_connection)
    monkeypatch.setattr(socket, "getaddrinfo", _blocked_getaddrinfo)
    yield
