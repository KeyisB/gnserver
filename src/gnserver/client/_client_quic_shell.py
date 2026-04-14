import asyncio
import socket
from contextlib import asynccontextmanager
from ipaddress import ip_address
from typing import AsyncGenerator, Callable, Optional, cast, TYPE_CHECKING, Type

from aioquic.quic.configuration import QuicConfiguration
from aioquic.quic.connection import QuicTokenHandler
from aioquic.tls import SessionTicketHandler
from aioquic.asyncio.protocol import QuicConnectionProtocol, QuicStreamHandler

__all__ = ["connect"]

from ..server._datagram_enc import DatagramEndpoint
from .._gn_pq_quic import GNQuicClientSettings, GNQuicConnection


if TYPE_CHECKING:
    from ._client import QuicClient, RawQuicClient

@asynccontextmanager
async def connect(
    quicClient: 'QuicClient',
    host: str,
    port: int,
    domain: str,
    configuration: QuicConfiguration,
    create_protocol: Type['RawQuicClient'],
    encType: int = 0,
    gn_pq_client_settings: Optional[GNQuicClientSettings] = None,

    stream_handler: Optional[QuicStreamHandler] = None,
    wait_connected: bool = True,
    local_port: int = 0,
) -> AsyncGenerator['RawQuicClient', None]:

    loop = asyncio.get_event_loop()

    # resolve addr
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
    addr = infos[0][4]
    if len(addr) == 2:  # v4 → v6 mapping
        addr = ("::ffff:" + addr[0], addr[1], 0, 0)
        if addr[0] == '127.0.0.1':
            addr = ("::1", addr[1], 0, 0)
            
        #addr = ("::1", addr[1], 0, 0)


    # prepare QUIC connection
    if configuration is None:
        configuration = QuicConfiguration(is_client=True)
    if configuration.server_name is None:
        try:
            ip_address(host)
        except ValueError:
            configuration.server_name = host

    quic = GNQuicConnection(
        configuration=configuration,
        gn_pq_client_settings=gn_pq_client_settings,
    )

    # 1. Create protocol_shell (your QuicProtocolShell)
    protocol_shell = create_protocol(
        quic=quic,
        datagramEndpoint=None,   # временно  # type: ignore
        stream_handler=stream_handler,
        client=quicClient,
    )

    # 2. Create DatagramEndpoint (now protocol exists)
    dep_config = quicClient._client.server.DEPConfig if quicClient._client.server is not None else None
    datagramEndpoint = DatagramEndpoint(
        quic_routing=protocol_shell,
        kdc=quicClient._client._kdc,
        dEPConfig=dep_config,
    )

    datagramEndpoint._domain = domain
    datagramEndpoint._default_encryption_type = encType

    # link protocol ↔ endpoint
    protocol_shell.setDatagramEndpoint(datagramEndpoint)

    # 3. Prepare UDP socket manually
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
    sock.bind(("::", local_port, 0, 0))


    transport, _ = await loop.create_datagram_endpoint(
        lambda: datagramEndpoint,
        sock=sock
    )

    try:
        # 5. Start QUIC handshake
        protocol_shell.connect(addr, transmit=wait_connected)

        if wait_connected:
            await protocol_shell.wait_connected()

        yield protocol_shell

    finally:
        protocol_shell.close()
        await protocol_shell.wait_closed()
        transport.close()
