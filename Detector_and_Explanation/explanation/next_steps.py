"""Template next-step recommendations for this project's real incident
schema (root_cause_node/affected_node_pair/affected_node_group,
recovery_status enum, detectability_status enum -- confirmed via
schema.py's build_result(), NOT pcap2story's recovered/recovery_basis/
"UNRESOLVABLE" fields, which don't exist in this project's output shape).
Fresh implementation, referenced against pcap2story's next_steps.py for
design only (template recommendation keyed on fault_type + recovery
outcome, returning None when nothing applies rather than forcing text)."""


def select_next_step(incident, topology=None):
    fault_type = incident.get("fault_type")
    recovery_status = incident.get("recovery_status")

    if recovery_status == "NOT_RECOVERED":
        return "recommend extending capture duration to confirm whether reconnection eventually occurs"

    if fault_type == "ESDF Toggle" and recovery_status == "UNKNOWN":
        return "recommend correlating with PE-side or dataplane data to confirm DF forwarding state, since this capture alone cannot verify it"

    if fault_type == "RT Misconfiguration" and incident.get("root_cause_node") is None:
        return "recommend capturing from the other route reflector's vantage point to resolve which PE actually originated the deviant advertisement"

    return None
