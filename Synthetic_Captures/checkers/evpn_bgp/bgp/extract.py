"""Extract BGP messages from decoded tshark JSON packets."""

from __future__ import annotations

from checkers.evpn_bgp.model import BgpMessage, BgpMsgType


def _get(layers: dict, *keys: str, default: str = "") -> str:
    """Return the first matching field value from *layers*."""
    for key in keys:
        val = layers.get(key)
        if val is not None:
            if isinstance(val, list):
                return str(val[0]) if val else default
            return str(val)
    return default


def extract_bgp_messages(packets: list[dict]) -> list[BgpMessage]:
    """Extract BGP messages from tshark JSON output.

    Each packet dict is expected to have a ``_source`` → ``layers`` structure
    (standard ``tshark -T json`` output).
    """
    messages: list[BgpMessage] = []

    for pkt in packets:
        layers = pkt.get("_source", {}).get("layers", {})
        bgp_type_raw = _get(layers, "bgp.type")
        if not bgp_type_raw:
            continue

        # tshark can produce multiple BGP messages per frame (e.g. OPEN + KEEPALIVE)
        raw_val = layers.get("bgp.type")
        if isinstance(raw_val, list):
            bgp_types = raw_val
        else:
            bgp_types = [bgp_type_raw]
        frame = int(_get(layers, "frame.number", default="0"))
        ts = float(_get(layers, "frame.time_epoch", default="0"))
        src = _get(layers, "ip.src")
        dst = _get(layers, "ip.dst")
        stream = int(_get(layers, "tcp.stream", default="0"))

        for t in bgp_types:
            try:
                msg_type = int(t)
            except (ValueError, TypeError):
                continue
            messages.append(BgpMessage(
                frame_number=frame,
                timestamp=ts,
                msg_type=msg_type,
                tcp_stream=stream,
                src_ip=src,
                dst_ip=dst,
                raw=layers,
            ))

    return messages
