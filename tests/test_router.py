from unittest.mock import Mock, patch

import pytest

from router import Router


def test_router_init():
    router = Router("mac1", "ip1", "host", 12345)
    assert router.mac == "mac1"
    assert router.ip == "ip1"
    assert router.host == "host"
    assert router.port == 12345


def test_router_start_server_success():
    router = Router("mac1", "ip1", "host", 12345)
    mock_socket = Mock()
    with patch("socket.socket") as mock_socket_func:
        mock_socket_func.return_value = mock_socket
        router.start_server()
    mock_socket.bind.assert_called_once_with(("host", 12345))
    mock_socket.listen.assert_called_once()


def test_router_start_server_failure():
    router = Router("mac1", "ip1", "host", 12345)
    with patch("socket.socket") as mock_socket_func:
        mock_socket_func.side_effect = Exception("Socket error")
        with pytest.raises(Exception):
            router.start_server()


def test_router_handle_client():
    router = Router("mac1", "ip1", "host", 12345)
    mock_socket = Mock()
    mock_socket.recv.side_effect = [b"data1", b"", Exception("Socket error")]
    router.handle_client(mock_socket)
    assert mock_socket.recv.call_count == 2
    mock_socket.close.assert_called_once()


def test_router_send():
    router = Router("mac1", "ip1", "host", 12345)
    mock_socket = Mock()
    router.ip_to_socket["1A"] = mock_socket
    router.send("1A", "message")
    mock_socket.sendall.assert_called_once_with(b"message")


def test_router_start():
    router = Router("mac1", "ip1", "host", 12345)
    router.server_thread = Mock()
    router.start()
    router.server_thread.start.assert_called_once()
