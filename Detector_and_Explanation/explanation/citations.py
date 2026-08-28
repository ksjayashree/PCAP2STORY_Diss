"""RFC query construction for this project's explanation layer.

Fresh implementation, referenced against pcap2story's citations.py
(C:\\PCAP2STORY\\rule_based\\explain\\citations.py) for design only (the
"fault_type + trigger_mechanism + root_cause_node, plus RFC-domain
vocabulary" query-construction pattern, and the retrieve()-min_score
gate on select_citation() returning [] rather than forcing a citation).

Deviates from pcap2story in three deliberate ways -- see the module's
own build report for the fuller reasoning:
  1. MAC Mobility and RD Collision get real FAULT_TYPE_QUERY_TERMS
     entries (pcap2story had none for either -- confirmed by reading its
     FAULT_TYPE_QUERY_TERMS dict directly, only Link Down/RR Down/
     ESDF Toggle/RT Misconfiguration were keyed).
  2. PE Cease also gets a real entry -- pcap2story's dict has none for
     it either (PE Cease was not in that project's evaluated fault set).
  3. RR Down's query is built from the incident's OWN evidence
     (trigger_mechanism, real peer-breadth via affected_nodes,
     recovery_status) instead of a fixed "redundant RRs" phrase that
     biased every RR Down retrieval toward RR-redundancy/CLUSTER_ID
     text regardless of what actually happened on the wire.
  4. RT Misconfiguration's ES-Import sub-condition gate is
     trigger_mechanism == "ES-Import RT Mismatch" (this project's real
     field/value, confirmed by reading rt_misconfiguration.py's detect()
     directly), not affected_route_types == [4] -- that field doesn't
     exist anywhere in this project's schema.py output shape at all.
"""
from retrieval import retrieve

# Fault types that DON'T need special-cased query construction below
# (RR Down, RT Misconfiguration) -- their domain vocabulary is appended
# generically by _query_for_incident.
FAULT_TYPE_QUERY_TERMS = {
    # New (gap confirmed in pcap2story investigation): grounded in RFC 4486
    # Section 3 "Subcode Definition" (Administrative Shutdown is subcode 2)
    # and RFC 4271 Section 6.7 "Cease" -- both real, indexed corpus sections
    # (rfc4486_3, rfc4271_6.7), confirmed present via build_rfc_corpus.py's
    # own output. pe_cease.py's only real trigger_mechanism value is
    # "Cease/Administrative Shutdown" (confirmed by reading pe_cease.py).
    "PE Cease": "Cease NOTIFICATION Administrative Shutdown subcode peer session termination",
    # New (gap confirmed in pcap2story investigation): grounded in RFC 7432
    # Section 7.7 "MAC Mobility Extended Community" (the wire encoding) and
    # Section 15 "MAC Mobility" (the actual sequence-number algorithm) --
    # both real, indexed corpus sections (rfc7432_7.7, rfc7432_15).
    "MAC Mobility": "MAC Mobility Extended Community sequence number MAC move re-advertisement from a different PE",
    # New (gap confirmed in pcap2story investigation): grounded in RFC 7432
    # Section 7.9 "Route Distinguisher Assignment per MAC-VRF" (rfc7432_7.9)
    # -- the RD-uniqueness requirement a colliding/duplicate RD violates.
    "RD Collision": "Route Distinguisher uniqueness per MAC-VRF Type 1 RD assignment collision",
}

# 2026-08-17: replaced the single fixed Link Down phrase (which literally
# contained the words "Hold Timer Expired" regardless of which of the 3
# real trigger mechanisms actually fired) with a per-mechanism dict --
# confirmed via direct investigation that the old shared phrase biased
# retrieval toward RFC 4271 Section 8.1.3 (Timer Events)/RFC 5880 (BFD)
# material even for TcpConnectionFails incidents. Each phrase below uses
# real terms from the RFC section(s) that actually document that specific
# mechanism (confirmed against the real RFC text this session, not
# guessed): BFD Down -> RFC 5880 SS6.8.16/6.8.18 (AdminDown, Required Min
# RX Interval, Detection Time); Hold Timer Expired -> RFC 4271 S8.1.3
# (HoldTimer_Expires, KeepaliveTimer_Expires, BGP FSM); TcpConnectionFails
# -> RFC 4271 S8.1.4 (Event 18, TCP connection failure) -- deliberately
# excludes "Hold Timer"/BFD vocabulary so this mechanism no longer gets
# pulled toward the other two's material.
LINK_DOWN_QUERY_TERMS = {
    "BFD Down": (
        "BFD session Down AdminDown administrative disable "
        "Required Min RX Interval Detection Time expiry "
        "loss of BFD control packets"
    ),
    "Hold Timer Expired": (
        "BGP Hold Timer expiration missed Keepalive messages "
        "BGP finite state machine timer-driven session teardown"
    ),
    "TcpConnectionFails": (
        "TCP connection failure closed or reset "
        "BGP transport session teardown Event 18 TcpConnectionFails"
    ),
}
# Fallback for any trigger_mechanism value outside the 3 known real ones
# (shouldn't happen for real Link Down data -- safety net, not expected
# to fire) -- the old shared phrase, kept only as a last resort.
_LINK_DOWN_FALLBACK_TERMS = "session loss withdrawal of routes learned from that peer"

# 2026-08-17: same fix as Link Down, applied to ESDF Toggle's 4 real
# trigger mechanisms -- confirmed via direct investigation that the old
# shared phrase ("DF election finite state machine ES_UP ES_DOWN LOST_ES
# RCVD_ES Ethernet Segment route withdrawal") caused RFC 8584 Section
# 1.3.2 (Traffic Black-Holing on Individual AC Failures -- a section
# whose actual thesis is that LOGICAL/AC failures do NOT trigger
# re-election) to rank #1 for all four mechanisms, including "Dual-PE
# Type-1 Per-ES Withdrawal (ES Full Failure)", a genuine PHYSICAL/full
# failure that §1.3.2 only mentions in passing before pivoting to its
# real (opposite) point -- this directly explained an earlier confirmed
# mischaracterization in esdf_toggle_full_failure_no_recovery_pe3pe4's
# real output. Each phrase below is grounded in the real RFC section that
# actually documents that specific mechanism (verified against the real
# RFC text this session): Type-4 ES Route Withdrawal -> RFC 7432 S7.4/
# S8.1/S8.1.1 (the ES route itself, DF-election candidate discovery);
# Type-1 Per-EVI EAD Withdrawal -> RFC 7432 S8.4 (Aliasing and Backup
# Path, where "Ethernet A-D per EVI route" is defined); Dual-PE Type-1
# Per-ES Withdrawal (ES Full Failure) -> RFC 7432 S8.2/S8.2.1 (Fast
# Convergence, the per-ES A-D route) + S17.3 -- deliberately avoids any
# ACS/AC-DF/logical-failure vocabulary so it no longer competes toward
# S1.3.2; AC-State DF Election Community Toggle -> RFC 8584 S1.3.2/S4/
# S4.1 (ACS, AC-DF -- the actual logical-failure-specific sections).
ESDF_TOGGLE_QUERY_TERMS = {
    # 2026-08-21: added FSM-trigger vocabulary (RCVD_ES/LOST_ES/DF_CALC)
    # back in, confirmed missing via direct investigation -- the ES route
    # (Type-4) itself is a base-FSM DF-re-election trigger (RFC 8584
    # Section 2.1: "DF_DONE on ... RCVD_ES, or LOST_ES: Transition to
    # DF_CALC"), independent of the AC-DF extension in Section 4. The
    # 2026-08-17 rewrite dropped this vocabulary entirely while fixing an
    # unrelated bias toward Section 1.3.2, leaving Section 2.1 unreachable
    # for this query (confirmed: scored rank #61/324, well below the
    # min_score-clearing but never-retrieved range). Kept deliberately
    # free of ACS/AC-DF/logical-failure terms, same as before, so this
    # still doesn't re-attract Section 1.3.2.
    "Type-4 ES Route Withdrawal": (
        "Ethernet Segment Route Type 4 multihomed Ethernet Segment "
        "auto-discovery constructing the Ethernet Segment route "
        "DF election candidate discovery finite state machine event "
        "reception or withdrawal of an ES route triggers DF re-election "
        "transition to DF_CALC recompute the DF"
    ),
    "Type-1 Per-EVI EAD Withdrawal": (
        "Ethernet A-D per EVI route aliasing and backup path "
        "remote PE next hop reachability via that EVI"
    ),
    "Dual-PE Type-1 Per-ES Withdrawal (ES Full Failure)": (
        "Ethernet A-D per ES route withdrawal fast convergence "
        "PE-to-CE connectivity failure mass withdraw next hop removal"
    ),
    "AC-State DF Election Community Toggle": (
        "AC-Influenced DF Election Capability Access Circuit Status ACS "
        "logical failure individual AC DF Election Extended Community"
    ),
}
# Fallback for any trigger_mechanism value outside the 4 known real ones
# (safety net, not expected to fire) -- the old shared phrase.
_ESDF_TOGGLE_FALLBACK_TERMS = "DF election finite state machine ES_UP ES_DOWN LOST_ES RCVD_ES Ethernet Segment route withdrawal"

_RT_MISCONFIG_BASE_TERMS = " Route Target Community used to identify VPN routes eligible for import into a VRF"
_RT_MISCONFIG_ES_IMPORT_TERMS = " ES-Import Route Target automatically derived from the Ethernet Segment Identifier import filtering"

# This project's real trigger_mechanism value for the ES-Import RT branch
# (rt_misconfiguration.py's detect(), es_import mechanism, confirmed by reading
# the actual code this session) -- NOT pcap2story's affected_route_types
# field, which doesn't exist anywhere in this project's schema.py.
ES_IMPORT_TRIGGER_MECHANISM = "ES-Import RT Mismatch"


def _rr_down_query(incident):
    """RR Down query built from THIS incident's own evidence, not a fixed
    phrase. trigger_mechanism is rr_down.py's real, wire-derived value
    ("TCP_connection_closed" for bgpdkill's mass FIN/RESET/BFD-Down
    signature, "Cease/Administrative Shutdown" for graceful's per-session
    NOTIFICATION signature -- confirmed by reading rr_down.py's detect()
    directly). affected_nodes REMOVED from the incident schema (2026-08-15)
    -- this function no longer has a peer-breadth number to describe, so
    that phrase is dropped from the query rather than computed from a
    field that no longer exists. recovery_status is the incident's own real
    outcome. Neither of these bias toward a specific RFC narrative the way
    a fixed "redundant RRs" phrase would -- they describe what actually
    happened on the wire for THIS incident."""
    mechanism = incident.get("trigger_mechanism") or ""
    recovery = incident.get("recovery_status") or ""
    parts = ["route reflector client session failure"]
    if mechanism == "TCP_connection_closed":
        parts.append("simultaneous TCP connection reset BFD Down across all client sessions abrupt failure")
    elif mechanism == "Cease/Administrative Shutdown":
        parts.append("sequential Cease Administrative Shutdown NOTIFICATION per client session graceful shutdown")
    if recovery == "RECOVERED":
        parts.append("session re-establishment after route reflector recovery")
    elif recovery == "NOT_RECOVERED":
        parts.append("route reflector remains unreachable no re-establishment observed")
    return " ".join(parts)


def _query_for_incident(incident):
    """Query text from the incident's own fields (fault_type +
    trigger_mechanism) plus that fault_type's RFC-domain vocabulary, same
    pattern as pcap2story's citations.py (referenced for design, not
    copied) -- except RR Down, which routes through _rr_down_query()
    instead of a fixed FAULT_TYPE_QUERY_TERMS entry.

    2026-08-17: root_cause_node deliberately excluded (previously
    included here) -- confirmed via direct investigation that embedding a
    raw node-identifier string in the semantic retrieval query is pure
    noise (RFC text never contains project node names) that can
    meaningfully perturb the query embedding: e.g. "PE1" vs "XPE1" (same
    fault_type/trigger_mechanism, different topology's naming convention)
    shifted RFC 5880's BFD chunk from outside the top 6 candidates to
    rank #1 for every real 3rr TCP-fail file tested, silently displacing
    the correct RFC 4271 Section 8.1.4 citation. Node identity is already
    given to the LLM directly via the full incident facts elsewhere in
    the prompt -- nothing is lost at generation time by excluding it
    here."""
    fault_type = incident.get("fault_type") or ""
    if fault_type == "RR Down":
        return _rr_down_query(incident)

    trigger_mechanism = incident.get("trigger_mechanism") or ""
    parts = [p for p in (fault_type, trigger_mechanism) if p]
    if fault_type == "Link Down":
        domain_terms = LINK_DOWN_QUERY_TERMS.get(trigger_mechanism, _LINK_DOWN_FALLBACK_TERMS)
    elif fault_type == "ESDF Toggle":
        domain_terms = ESDF_TOGGLE_QUERY_TERMS.get(trigger_mechanism, _ESDF_TOGGLE_FALLBACK_TERMS)
    else:
        domain_terms = FAULT_TYPE_QUERY_TERMS.get(fault_type, "")
    if domain_terms:
        parts.append(domain_terms)
    return " ".join(parts)


def select_citation(incident, k=2):
    """Retrieves up to k grounding chunks for this incident. Returns []
    (never a forced/fabricated citation) if nothing scores above
    retrieval.py's min_score threshold."""
    fault_type = incident.get("fault_type")
    if fault_type == "RT Misconfiguration":
        if incident.get("trigger_mechanism") == ES_IMPORT_TRIGGER_MECHANISM:
            query = _query_for_incident(incident) + _RT_MISCONFIG_ES_IMPORT_TERMS
        else:
            query = _query_for_incident(incident) + _RT_MISCONFIG_BASE_TERMS
    else:
        query = _query_for_incident(incident)
    return retrieve(query, k=k)
