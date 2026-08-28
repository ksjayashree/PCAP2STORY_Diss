"""Unit tests for the realism/consistency checker rules added for protocol
correctness: BGP-004 (illegal hold time), BGP-001 (KEEPALIVE before OPEN),
and EVPN-008 (invalid MAC in a Type 2 advertisement)."""

from __future__ import annotations

from checkers.evpn_bgp.model import (
    BgpCapabilities, BgpMessage, BgpMsgType, BgpSession,
    EvpnRoute, EvpnRouteType,
)
from checkers.evpn_bgp.bgp.rules import (
    check_hold_time_valid, check_open_before_update,
)
from checkers.evpn_bgp.evpn.rules import check_valid_mac_type2


def _msg(frame: int, mtype: BgpMsgType) -> BgpMessage:
    return BgpMessage(
        frame_number=frame, timestamp=float(frame), msg_type=mtype,
        tcp_stream=0, src_ip="10.0.0.1", dst_ip="10.0.0.2",
    )


def _session(messages, hold_time=0, remote_hold_time=0) -> BgpSession:
    return BgpSession(
        tcp_stream=0,
        capabilities=BgpCapabilities(hold_time=hold_time),
        remote_capabilities=BgpCapabilities(hold_time=remote_hold_time),
        messages=messages,
    )


def _route(mac: str, frame: int = 1, withdrawal: bool = False) -> EvpnRoute:
    return EvpnRoute(
        frame_number=frame, timestamp=float(frame),
        route_type=EvpnRouteType.MAC_IP_ADV, mac=mac, is_withdrawal=withdrawal,
    )


# --- BGP-004: illegal hold time -------------------------------------------

def test_hold_time_1_is_flagged():
    sess = _session([_msg(1, BgpMsgType.OPEN)], hold_time=1)
    findings = check_hold_time_valid(sess)
    assert [f.code for f in findings] == ["BGP-004"]
    assert findings[0].severity == "WARN"
    assert findings[0].frame == 1


def test_hold_time_2_is_flagged():
    sess = _session([_msg(7, BgpMsgType.OPEN)], remote_hold_time=2)
    findings = check_hold_time_valid(sess)
    assert [f.code for f in findings] == ["BGP-004"]


def test_hold_time_0_is_valid():
    # 0 means keepalives disabled -- legal.
    sess = _session([_msg(1, BgpMsgType.OPEN)], hold_time=0)
    assert check_hold_time_valid(sess) == []


def test_hold_time_90_is_valid():
    sess = _session([_msg(1, BgpMsgType.OPEN)], hold_time=90, remote_hold_time=180)
    assert check_hold_time_valid(sess) == []


# --- BGP-001: KEEPALIVE / UPDATE before OPEN ------------------------------

def test_keepalive_before_open_is_flagged():
    sess = _session([_msg(1, BgpMsgType.KEEPALIVE), _msg(2, BgpMsgType.OPEN)])
    findings = check_open_before_update(sess)
    assert [f.code for f in findings] == ["BGP-001"]
    assert findings[0].frame == 1


def test_update_before_open_is_flagged():
    sess = _session([_msg(1, BgpMsgType.UPDATE)])
    findings = check_open_before_update(sess)
    assert [f.code for f in findings] == ["BGP-001"]


def test_normal_order_is_clean():
    sess = _session([
        _msg(1, BgpMsgType.OPEN),
        _msg(2, BgpMsgType.KEEPALIVE),
        _msg(3, BgpMsgType.UPDATE),
    ])
    assert check_open_before_update(sess) == []


# --- EVPN-008: invalid MAC in Type 2 --------------------------------------

def test_broadcast_mac_is_flagged():
    findings = check_valid_mac_type2([_route("ff:ff:ff:ff:ff:ff")])
    assert [f.code for f in findings] == ["EVPN-008"]
    assert "broadcast" in findings[0].evidence["reason"]


def test_multicast_mac_is_flagged():
    # First octet 0x01 -> I/G bit set.
    findings = check_valid_mac_type2([_route("01:00:5e:00:00:01")])
    assert [f.code for f in findings] == ["EVPN-008"]
    assert "multicast" in findings[0].evidence["reason"]


def test_all_zero_mac_is_flagged():
    findings = check_valid_mac_type2([_route("00:00:00:00:00:00")])
    assert [f.code for f in findings] == ["EVPN-008"]
    assert findings[0].evidence["reason"] == "all-zero"


def test_normal_unicast_mac_is_clean():
    assert check_valid_mac_type2([_route("00:aa:bb:cc:dd:ee")]) == []


def test_locally_administered_unicast_is_clean():
    # U/L bit (0x02) set but I/G bit (0x01) clear -> valid unicast.
    assert check_valid_mac_type2([_route("02:aa:bb:cc:dd:ee")]) == []


def test_withdrawal_is_ignored():
    assert check_valid_mac_type2([_route("ff:ff:ff:ff:ff:ff", withdrawal=True)]) == []


def test_duplicate_invalid_mac_reported_once():
    findings = check_valid_mac_type2([
        _route("ff:ff:ff:ff:ff:ff", frame=1),
        _route("ff:ff:ff:ff:ff:ff", frame=2),
    ])
    assert len(findings) == 1
