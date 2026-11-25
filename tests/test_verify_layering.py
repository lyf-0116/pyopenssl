from __future__ import annotations

import pytest

from OpenSSL.crypto import (
    FILETYPE_PEM,
    X509,
    load_certificate,
    load_privatekey,
)
from OpenSSL.SSL import (
    VERIFY_FAIL_IF_NO_PEER_CERT,
    VERIFY_PEER,
    Connection,
    Context,
    Error,
    SSLv23_METHOD,
)

from .test_crypto import root_cert_pem, root_key_pem
from .test_ssl import handshake_in_memory


def _server_connection() -> Connection:
    context = Context(SSLv23_METHOD)
    context.use_certificate(load_certificate(FILETYPE_PEM, root_cert_pem))
    context.use_privatekey(load_privatekey(FILETYPE_PEM, root_key_pem))
    return Connection(context, None)


def _allow_callback(
    calls: list[tuple[int, int]],
) -> object:
    def callback(
        connection: Connection,
        certificate: X509,
        error_number: int,
        depth: int,
        preverify_ok: int,
    ) -> bool:
        calls.append((depth, preverify_ok))
        return True

    return callback


def test_connection_mode_only_update_preserves_context_callback() -> None:
    calls: list[tuple[int, int]] = []
    context = Context(SSLv23_METHOD)
    callback = _allow_callback(calls)
    context.set_verify(VERIFY_PEER, callback)  # type: ignore[arg-type]

    connection = Connection(context, None)
    connection.set_verify(VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT)

    assert connection.get_verify_mode() == (
        VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT
    )
    assert connection._verify_helper is context._verify_helper
    assert connection._verify_callback is context._verify_callback

    handshake_in_memory(connection, _server_connection())
    assert calls


def test_connection_mode_only_update_preserves_connection_callback() -> None:
    context_calls: list[tuple[int, int]] = []
    connection_calls: list[tuple[int, int]] = []
    context = Context(SSLv23_METHOD)
    context.set_verify(
        VERIFY_PEER,
        _allow_callback(context_calls),  # type: ignore[arg-type]
    )

    connection = Connection(context, None)
    connection_callback = _allow_callback(connection_calls)
    connection.set_verify(VERIFY_PEER, connection_callback)  # type: ignore[arg-type]
    helper = connection._verify_helper

    connection.set_verify(VERIFY_PEER | VERIFY_FAIL_IF_NO_PEER_CERT)

    assert connection._verify_helper is helper
    handshake_in_memory(connection, _server_connection())
    assert connection_calls
    assert not context_calls


def test_connection_explicit_none_restores_default_verification() -> None:
    calls: list[tuple[int, int]] = []
    context = Context(SSLv23_METHOD)
    context.set_verify(
        VERIFY_PEER,
        _allow_callback(calls),  # type: ignore[arg-type]
    )

    connection = Connection(context, None)
    connection.set_verify(VERIFY_PEER, None)

    assert connection._verify_helper is None
    assert connection._verify_callback is None
    with pytest.raises(Error, match="certificate verify failed"):
        handshake_in_memory(connection, _server_connection())
    assert not calls
