"""BGP session state tracking per TCP stream."""

from __future__ import annotations

from checkers.evpn_bgp.model import BgpMessage, BgpMsgType, BgpSession
from checkers.evpn_bgp.bgp.capabilities import parse_capabilities


def build_sessions(messages: list[BgpMessage]) -> dict[int, BgpSession]:
    """Group BGP messages by TCP stream and build session state.

    Returns a dict keyed by tcp_stream number.
    """
    sessions: dict[int, BgpSession] = {}

    for msg in messages:
        stream = msg.tcp_stream
        if stream not in sessions:
            sessions[stream] = BgpSession(
                tcp_stream=stream,
                src_ip=msg.src_ip,
                dst_ip=msg.dst_ip,
            )
        sess = sessions[stream]
        sess.messages.append(msg)

        if msg.msg_type == BgpMsgType.OPEN:
            # Determine direction: first OPEN sets the peer addresses.
            if not sess.open_received:
                sess.open_received = True
                sess.remote_capabilities = parse_capabilities(msg.raw)
            elif not sess.open_sent:
                sess.open_sent = True
                sess.capabilities = parse_capabilities(msg.raw)

        elif msg.msg_type == BgpMsgType.KEEPALIVE:
            if sess.open_received:
                sess.keepalive_received = True
            # Mark established once we have OPEN + KEEPALIVE from both sides
            if sess.open_received and sess.keepalive_received:
                sess.established = True

        elif msg.msg_type == BgpMsgType.NOTIFICATION:
            sess.terminated = True

    return sessions
