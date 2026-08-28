"""BGP validation rules."""

from __future__ import annotations

from checkers.evpn_bgp.model import (
    BgpMessage, BgpMsgType, BgpSession, Finding, Severity,
)


def check_open_before_update(session: BgpSession) -> list[Finding]:
    """OPEN must precede any UPDATE or KEEPALIVE in a session."""
    findings: list[Finding] = []
    seen_open = False
    for msg in session.messages:
        if msg.msg_type == BgpMsgType.OPEN:
            seen_open = True
        elif (
            msg.msg_type in (BgpMsgType.UPDATE, BgpMsgType.KEEPALIVE)
            and not seen_open
        ):
            findings.append(Finding(
                severity=Severity.FAIL,
                code="BGP-001",
                frame=msg.frame_number,
                message=(
                    f"{msg.msg_type} received before OPEN on session."
                ),
                impact="Session cannot be in a valid state without an OPEN exchange.",
                evidence={"tcp_stream": session.tcp_stream},
                confidence="high",
            ))
            break  # one finding per session suffices
    return findings


def check_hold_time_valid(session: BgpSession) -> list[Finding]:
    """Advertised Hold Time must be 0 or >= 3 seconds (RFC 4271 4.2).

    A Hold Time of 1 or 2 is illegal: the spec requires it to be either
    zero (keepalives disabled) or at least three seconds.  Real BGP
    speakers reject such an OPEN with a NOTIFICATION, so a capture that
    carries one looks unrealistic.
    """
    findings: list[Finding] = []
    open_frame = 0
    for msg in session.messages:
        if msg.msg_type == BgpMsgType.OPEN:
            open_frame = msg.frame_number
            break
    for label, caps in (
        ("local", session.capabilities),
        ("remote", session.remote_capabilities),
    ):
        ht = caps.hold_time
        if 0 < ht < 3:
            findings.append(Finding(
                severity=Severity.WARN,
                code="BGP-004",
                frame=open_frame,
                message=(
                    f"Illegal Hold Time {ht}s advertised in {label} OPEN "
                    f"(must be 0 or >= 3 per RFC 4271 4.2)."
                ),
                impact="A conformant peer would reject the OPEN with a NOTIFICATION.",
                evidence={"tcp_stream": session.tcp_stream, "hold_time": ht},
                confidence="high",
            ))
    return findings


def check_notification_terminates(session: BgpSession) -> list[Finding]:
    """No UPDATE or KEEPALIVE should follow a NOTIFICATION."""
    findings: list[Finding] = []
    seen_notification = False
    notification_frame = 0
    for msg in session.messages:
        if msg.msg_type == BgpMsgType.NOTIFICATION:
            seen_notification = True
            notification_frame = msg.frame_number
        elif seen_notification and msg.msg_type in (
            BgpMsgType.UPDATE, BgpMsgType.KEEPALIVE,
        ):
            findings.append(Finding(
                severity=Severity.FAIL,
                code="BGP-002",
                frame=msg.frame_number,
                message=(
                    f"Message type {msg.msg_type} received after "
                    f"NOTIFICATION (frame {notification_frame})."
                ),
                impact="A NOTIFICATION should terminate the session.",
                evidence={
                    "tcp_stream": session.tcp_stream,
                    "notification_frame": notification_frame,
                },
                confidence="high",
            ))
            break
    return findings


def check_route_refresh_capability(session: BgpSession) -> list[Finding]:
    """ROUTE-REFRESH should only appear if the capability was negotiated."""
    findings: list[Finding] = []
    has_rr = (
        session.capabilities.route_refresh
        or session.remote_capabilities.route_refresh
    )
    for msg in session.messages:
        if msg.msg_type == BgpMsgType.ROUTE_REFRESH and not has_rr:
            findings.append(Finding(
                severity=Severity.WARN,
                code="BGP-003",
                frame=msg.frame_number,
                message="ROUTE-REFRESH sent without negotiated capability.",
                impact="Peer may reject or ignore the route-refresh request.",
                evidence={"tcp_stream": session.tcp_stream},
                confidence="medium",
            ))
            break
    return findings


def run_bgp_rules(
    sessions: dict[int, BgpSession],
    partial_capture: bool = False,
) -> list[Finding]:
    """Run all BGP session rules and return findings."""
    findings: list[Finding] = []
    for session in sessions.values():
        if not partial_capture:
            findings.extend(check_open_before_update(session))
        findings.extend(check_hold_time_valid(session))
        findings.extend(check_notification_terminates(session))
        findings.extend(check_route_refresh_capability(session))
    return findings
