from unittest.mock import Mock, patch

import pytest

from node import Node


def test_node_init():
    node = Node("N1", "1A", "router_host", 12345)
    assert node.mac == "N1"
    assert node.ip == "1A"
    assert node.router_host == "router_host"
    assert node.router_port == 12345


# def test_node_connect_to_router_success():
#     node = Node("N1", "1A", "router_host", 12345)
#     mock_socket = Mock()
#     with patch("socket.socket") as mock_socket_func:
#         mock_socket_func.return_value = mock_socket
#         node.connect_to_router()
#     mock_socket.connect.assert_called_once_with(("router_host", 12345))


def test_node_connect_to_router_failure():
    node = Node("N1", "1A", "router_host", 12345)
    with patch("socket.socket") as mock_socket_func:
        mock_socket_func.side_effect = Exception("Socket error")
        with pytest.raises(Exception):
            node.connect_to_router()


def test_node_send():
    node = Node("N1", "1A", "router_host", 12345)
    mock_socket = Mock()
    node.sock = mock_socket
    node.send("message")
    mock_socket.sendall.assert_called_once_with(b"message")


# def test_node_handle_server():
#     node = Node("N1", "1A", "router_host", 12345)
#     mock_socket = Mock()
#     mock_socket.recv.side_effect = [b"data1", b"", Exception("Socket error")]
#     node.handle_server(mock_socket)
#     assert mock_socket.recv.call_count == 2
#     mock_socket.close.assert_called_once()


def test_node_start():
    node = Node("N1", "1A", "router_host", 12345)
    node.server_thread = Mock()
    node.start()
    node.server_thread.start.assert_called_once()
