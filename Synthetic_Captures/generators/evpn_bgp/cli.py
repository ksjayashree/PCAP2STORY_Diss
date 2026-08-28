"""Click-based CLI for the synthetic EVPN pcap generator."""

import hashlib
import random
import sys
from pathlib import Path

import click

# ---------------------------------------------------------------------------
# Scenario registry: section → fault-type → variant → class path
# ---------------------------------------------------------------------------

SCENARIO_REGISTRY = {
    # 1: {
        # "quiet": {
            # None: "generators.evpn_bgp.scenarios.normal.QuietNormalScenario",
            # "pe1-pe3": "generators.evpn_bgp.scenarios.normal.QuietPE1PE3Scenario",
            # "pe4-pe5": "generators.evpn_bgp.scenarios.normal.QuietPE4PE5Scenario",
        # },
        # "moderate": {
            # None: "generators.evpn_bgp.scenarios.normal.ModerateNormalScenario",
            # "pe2-pe4": "generators.evpn_bgp.scenarios.normal.ModeratePE2PE4Scenario",
            # "pe1-pe5": "generators.evpn_bgp.scenarios.normal.ModeratePE1PE5Scenario",
        # },
        # "busy": {
            # None: "generators.evpn_bgp.scenarios.normal.BusyNormalScenario",
            # "pe2-pe3": "generators.evpn_bgp.scenarios.normal.BusyPE2PE3Scenario",
            # "pe1-pe4": "generators.evpn_bgp.scenarios.normal.BusyPE1PE4Scenario",
        # },
        # "mac-mobility": {
            # "pe1-pe2": "generators.evpn_bgp.scenarios.normal.MACMobilityPE1toPE2",
            # "pe2-pe1": "generators.evpn_bgp.scenarios.normal.MACMobilityPE2toPE1",
        # },
        # "connection-collision": {
            # "pe1": "generators.evpn_bgp.scenarios.normal.ConnectionCollisionPE1",
        # },
    # },
    2: {
        # "link-down": {
            # "simultaneous": "generators.evpn_bgp.scenarios.link_down.LinkDownSimultaneous",
            # "fast-recovery-pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownFastRecoveryPE1",
            # "fast-recovery-pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownFastRecoveryPE2",
            # "fast-recovery-pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownFastRecoveryPE3",
            # "fast-recovery-pe4": "generators.evpn_bgp.scenarios.link_down.LinkDownFastRecoveryPE4",
            # "fast-recovery-pe5": "generators.evpn_bgp.scenarios.link_down.LinkDownFastRecoveryPE5",
            # "slow-recovery-pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownSlowRecoveryPE1",
            # "slow-recovery-pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownSlowRecoveryPE2",
            # "slow-recovery-pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownSlowRecoveryPE3",
            # "slow-recovery-pe4": "generators.evpn_bgp.scenarios.link_down.LinkDownSlowRecoveryPE4",
            # "slow-recovery-pe5": "generators.evpn_bgp.scenarios.link_down.LinkDownSlowRecoveryPE5",
            # "no-recovery-pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownNoRecoveryPE1",
            # "no-recovery-pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownNoRecoveryPE2",
            # "no-recovery-pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownNoRecoveryPE3",
            # "no-recovery-pe4": "generators.evpn_bgp.scenarios.link_down.LinkDownNoRecoveryPE4",
            # "no-recovery-pe5": "generators.evpn_bgp.scenarios.link_down.LinkDownNoRecoveryPE5",
            # "hold-timer-pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownHoldTimerExpiryPE1",
            # "hold-timer-pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownHoldTimerExpiryPE2",
            # "hold-timer-pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownHoldTimerExpiryPE3",
            # "hold-timer-pe4": "generators.evpn_bgp.scenarios.link_down.LinkDownHoldTimerExpiryPE4",
            # "hold-timer-pe5": "generators.evpn_bgp.scenarios.link_down.LinkDownHoldTimerExpiryPE5",
            # "rst-slow-pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownRstSlowPE1",
            # "rst-slow-pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownRstSlowPE2",
            # "rst-slow-pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownRstSlowPE3",
            # "rst-slow-pe4": "generators.evpn_bgp.scenarios.link_down.LinkDownRstSlowPE4",
            # "rst-slow-pe5": "generators.evpn_bgp.scenarios.link_down.LinkDownRstSlowPE5",
            # "hold-timer-fast-pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownHoldTimerFastPE1",
            # "hold-timer-fast-pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownHoldTimerFastPE2",
            # "hold-timer-fast-pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownHoldTimerFastPE3",
            # "hold-timer-fast-pe4": "generators.evpn_bgp.scenarios.link_down.LinkDownHoldTimerFastPE4",
            # "hold-timer-fast-pe5": "generators.evpn_bgp.scenarios.link_down.LinkDownHoldTimerFastPE5",
            # "fast-recovery-midchurn-pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownFastRecoveryMidChurnPE1",
            # "fast-recovery-midchurn-pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownFastRecoveryMidChurnPE2",
            # "fast-recovery-midchurn-pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownFastRecoveryMidChurnPE3",
        # },
        # "link-down-graceful-restart": {
        #     "pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartPE1",
        #     "pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartPE2",
        #     "pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartPE3",
        #     "pe4": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartPE4",
        #     "pe5": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartPE5",
        #     "notified-pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartNotifiedPE1",
        #     "notified-pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartNotifiedPE2",
        #     "notified-pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartNotifiedPE3",
        #     "timeout-pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartTimeoutPE1",
        #     "timeout-pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartTimeoutPE2",
        #     "timeout-pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartTimeoutPE3",
        #     "notified-holdtimer-pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartNotifiedHoldTimerPE1",
        #     "notified-holdtimer-pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartNotifiedHoldTimerPE2",
        #     "notified-holdtimer-pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownGracefulRestartNotifiedHoldTimerPE3",
        # },
        # "link-down-hard-reset": {
            # "pe1": "generators.evpn_bgp.scenarios.link_down.LinkDownHardResetPE1",
            # "pe2": "generators.evpn_bgp.scenarios.link_down.LinkDownHardResetPE2",
            # "pe3": "generators.evpn_bgp.scenarios.link_down.LinkDownHardResetPE3",
        # },
        # "rr-down": {
            # "clean-restart-rr1": "generators.evpn_bgp.scenarios.rr_down.RRDownCleanRestartRR1",
            # "clean-restart-rr2": "generators.evpn_bgp.scenarios.rr_down.RRDownCleanRestartRR2",
            # "slow-restart-rr1": "generators.evpn_bgp.scenarios.rr_down.RRDownSlowRestartRR1",
            # "slow-restart-rr2": "generators.evpn_bgp.scenarios.rr_down.RRDownSlowRestartRR2",
            # "no-recovery-rr1": "generators.evpn_bgp.scenarios.rr_down.RRDownNoRecoveryRR1",
            # "no-recovery-rr2": "generators.evpn_bgp.scenarios.rr_down.RRDownNoRecoveryRR2",
            # "hold-timer-rr1": "generators.evpn_bgp.scenarios.rr_down.RRDownHoldTimerExpiryRR1",
            # "hold-timer-rr2": "generators.evpn_bgp.scenarios.rr_down.RRDownHoldTimerExpiryRR2",
            # "both-simultaneous": "generators.evpn_bgp.scenarios.rr_down.RRDownBothSimultaneous",
            # "graceful-restart-rr2": "generators.evpn_bgp.scenarios.rr_down.RRDownGracefulRestartRR2",
            # "graceful-restart-notified": "generators.evpn_bgp.scenarios.rr_down.RRDownGracefulRestartNotified",
            # "graceful-restart-timeout": "generators.evpn_bgp.scenarios.rr_down.RRDownGracefulRestartTimeout",
            # "graceful-restart-notified-holdtimer": "generators.evpn_bgp.scenarios.rr_down.RRDownGracefulRestartNotifiedHoldTimer",
            # "clean-restart-midchurn-rr2": "generators.evpn_bgp.scenarios.rr_down.RRDownCleanRestartMidChurnRR2",
        # },
        "esdf-toggle": {
            "single-pe1": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleTogglePE1",
            "single-pe2": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleTogglePE2",
            "repeated-pe1": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFRepeatedTogglePE1",
            "repeated-pe2": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFRepeatedTogglePE2",
            "no-recovery-pe1": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFNoRecoveryPE1",
            "no-recovery-pe2": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFNoRecoveryPE2",
            "slow": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSlowToggle",
            "single-midchurn-pe1": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleToggleMidChurnPE1",
            "single-midchurn-pe2": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleToggleMidChurnPE2",
            # Type-1 per-EVI EAD withdrawal trigger (RFC 8584's second
            # DF-election trigger type), distinct from the Type-4 ES-route
            # trigger above.
            "type1-evi-pe1": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFType1EVITogglePE1",
            "type1-evi-pe2": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFType1EVITogglePE2",
            # Local AC (attachment circuit) state trigger (RFC 8584's first
            # DF-election trigger type) -- DF Election Extended Community on
            # a Type-4 re-advertisement, never a withdrawal.
            "ac-state-pe1": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFACStateTogglePE1",
            "ac-state-pe2": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFACStateTogglePE2",
            # ES/DF Full Failure: both multihomed PEs lose DF role together.
            # Class definitions live in mixed.py.
            "full-failure-recovery": "generators.evpn_bgp.scenarios.mixed.ESDFFullFailureRecovery",
            "full-failure-no-recovery": "generators.evpn_bgp.scenarios.mixed.ESDFFullFailureNoRecovery",
            # 3RR/10PE topology entries: PE3/PE4 and PE6/PE7 are that
            # topology's ES pairs. Use --config configs/3rr_topology.yaml.
            "single-pe3": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleTogglePE3",
            "single-pe4": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleTogglePE4",
            "single-pe6": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleTogglePE6",
            "single-pe7": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleTogglePE7",
            "type1-evi-pe3": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFType1EVITogglePE3",
            "type1-evi-pe4": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFType1EVITogglePE4",
            "type1-evi-pe6": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFType1EVITogglePE6",
            "type1-evi-pe7": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFType1EVITogglePE7",
            "ac-state-pe3": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFACStateTogglePE3",
            "ac-state-pe4": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFACStateTogglePE4",
            "ac-state-pe6": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFACStateTogglePE6",
            "ac-state-pe7": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFACStateTogglePE7",
            "full-failure-recovery-pe3pe4": "generators.evpn_bgp.scenarios.mixed.ESDFFullFailureRecoveryPE3PE4",
            "full-failure-no-recovery-pe3pe4": "generators.evpn_bgp.scenarios.mixed.ESDFFullFailureNoRecoveryPE3PE4",
            "full-failure-recovery-pe6pe7": "generators.evpn_bgp.scenarios.mixed.ESDFFullFailureRecoveryPE6PE7",
            "full-failure-no-recovery-pe6pe7": "generators.evpn_bgp.scenarios.mixed.ESDFFullFailureNoRecoveryPE6PE7",
            # 3RR/10PE topology entries: repeated-toggle, no-recovery, and
            # single-midchurn variants for PE3/PE4/PE6/PE7, mirroring the
            # PE1/PE2 keys above.
            "repeated-pe3": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFRepeatedTogglePE3",
            "repeated-pe4": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFRepeatedTogglePE4",
            "repeated-pe6": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFRepeatedTogglePE6",
            "repeated-pe7": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFRepeatedTogglePE7",
            "no-recovery-pe3": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFNoRecoveryPE3",
            "no-recovery-pe4": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFNoRecoveryPE4",
            "no-recovery-pe6": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFNoRecoveryPE6",
            "no-recovery-pe7": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFNoRecoveryPE7",
            "single-midchurn-pe3": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleToggleMidChurnPE3",
            "single-midchurn-pe4": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleToggleMidChurnPE4",
            "single-midchurn-pe6": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleToggleMidChurnPE6",
            "single-midchurn-pe7": "generators.evpn_bgp.scenarios.esdf_toggle.ESDFSingleToggleMidChurnPE7",
        },
        "rt-misconfig": {
            # "pe1": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigPE1",
            # "pe2": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigPE2",
            # "pe3": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigPE3",
            # "pe4": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigPE4",
            # "pe5": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigPE5",
            # "import-pe1": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigImportPE1",
            # "import-pe2": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigImportPE2",
            # "import-pe3": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigImportPE3",
            # "import-pe4": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigImportPE4",
            # "import-pe5": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigImportPE5",
            # "export-pe1": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigExportPE1",
            # "export-pe2": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigExportPE2",
            # "export-pe3": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigExportPE3",
            # "export-pe4": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigExportPE4",
            # "export-pe5": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigExportPE5",
            # "recovery-pe1": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigWithRecoveryPE1",
            # "recovery-pe2": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigWithRecoveryPE2",
            # "recovery-pe3": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigWithRecoveryPE3",
            # "recovery-pe4": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigWithRecoveryPE4",
            # "recovery-pe5": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigWithRecoveryPE5",
            "es-import-pe1": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportPE1",
            "es-import-pe2": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportPE2",
            "es-import-recovery-pe1": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportRecoveryPE1",
            "es-import-recovery-pe2": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportRecoveryPE2",
            # 3RR/10PE topology entries, same ES pairs as esdf-toggle above --
            # use --config configs/3rr_topology.yaml.
            "es-import-pe3": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportPE3",
            "es-import-pe4": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportPE4",
            "es-import-pe6": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportPE6",
            "es-import-pe7": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportPE7",
            "es-import-recovery-pe3": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportRecoveryPE3",
            "es-import-recovery-pe4": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportRecoveryPE4",
            "es-import-recovery-pe6": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportRecoveryPE6",
            "es-import-recovery-pe7": "generators.evpn_bgp.scenarios.rt_misconfig.RTMisconfigESImportRecoveryPE7",
        },
        # MAC Mobility rapid-flap: withdraw-then-advertise ordering (matches
        # the detector), unlike normal.py's MACMobilityNormalScenario.
        "mac-mobility": {
            "rapid-pe1-pe2": "generators.evpn_bgp.scenarios.mac_mobility.MACMobilityRapidFlapPE1toPE2",
            "rapid-pe2-pe1": "generators.evpn_bgp.scenarios.mac_mobility.MACMobilityRapidFlapPE2toPE1",
            "repeated-pe1-pe2": "generators.evpn_bgp.scenarios.mac_mobility.MACMobilityRepeatedFlapPE1toPE2",
            "repeated-pe2-pe1": "generators.evpn_bgp.scenarios.mac_mobility.MACMobilityRepeatedFlapPE2toPE1",
            # PE4/PE5 are standalone (no ESI) and both home to RR2, avoiding
            # the ESI-partner exclusion that PE1/PE2 above is subject to.
            "rapid-pe4-pe5": "generators.evpn_bgp.scenarios.mac_mobility.MACMobilityRapidFlapPE4toPE5",
            "rapid-pe5-pe4": "generators.evpn_bgp.scenarios.mac_mobility.MACMobilityRapidFlapPE5toPE4",
            "repeated-pe4-pe5": "generators.evpn_bgp.scenarios.mac_mobility.MACMobilityRepeatedFlapPE4toPE5",
            "repeated-pe5-pe4": "generators.evpn_bgp.scenarios.mac_mobility.MACMobilityRepeatedFlapPE5toPE4",
        },
    },
    # 3: {
        # ------------------------------------------------------------------
        # Existing pairwise combos (kept from old Section 3)
        # ------------------------------------------------------------------
        # "overlapping": {
            # "ld-ld-pe2-pe3":  "generators.evpn_bgp.scenarios.mixed.MixedOverlappingFaults",
            # "ld-rr-pe1-rr2":  "generators.evpn_bgp.scenarios.mixed.MixedOverlappingPE1RR2",
        # },
        # "ld-esdf": {
            # "pe1-pe2": "generators.evpn_bgp.scenarios.section4.MixedESDFAndLinkDownPE1PE2",
        # },
        # "ld-rt": {
            # "pe2-pe3": "generators.evpn_bgp.scenarios.section4.MixedRTMisconfigAndLinkDownPE2PE3",
        # },
        # ------------------------------------------------------------------
        # New: Link Down on multihomed PE causing peer's ES/DF re-election (causal)
        # ------------------------------------------------------------------
        # "ld-triggers-esdf": {
            # "pe1": "generators.evpn_bgp.scenarios.mixed.LinkDownTriggersESDFPE1",
            # "pe2": "generators.evpn_bgp.scenarios.mixed.LinkDownTriggersESDFPE2",
        # },
        # ------------------------------------------------------------------
        # New: mixed mechanism/recovery pairings (independent faults)
        # ------------------------------------------------------------------
        # "ld-esdf-overlap": {
            # "pe1-pe2": "generators.evpn_bgp.scenarios.mixed.LinkDownPE1NoRecovery_ESDFPE2Overlap",
            # "pe3-pe2": "generators.evpn_bgp.scenarios.mixed.LinkDownPE3NoRecovery_ESDFPE2Overlap",
        # },
        # "ld-rt-overlap": {
            # "pe2-pe3": "generators.evpn_bgp.scenarios.mixed.LinkDownPE2HoldTimer_RTMisconfigPE3Overlap",
            # "pe3-pe1": "generators.evpn_bgp.scenarios.mixed.LinkDownPE3HoldTimer_RTMisconfigPE1Overlap",
        # },
        # "rr-then-ld": {
            # "rr2-pe1": "generators.evpn_bgp.scenarios.mixed.RRDownRR2_LinkDownPE1Sequential",
            # "rr2-pe3": "generators.evpn_bgp.scenarios.mixed.RRDownRR2_LinkDownPE3Sequential",
        # },
        # ------------------------------------------------------------------
        # "planned-maintenance": {
        #     "pe1": "generators.evpn_bgp.scenarios.mixed.MixedPlannedMaintenancePE1",
        #     "pe2": "generators.evpn_bgp.scenarios.mixed.MixedPlannedMaintenancePE2",
        #     "pe3": "generators.evpn_bgp.scenarios.mixed.MixedPlannedMaintenancePE3",
        #     "rr1": "generators.evpn_bgp.scenarios.section4.RRPlannedMaintenanceRR1",
        #     "rr2": "generators.evpn_bgp.scenarios.section4.RRPlannedMaintenanceRR2",
        # },
        # ------------------------------------------------------------------
        # "node-removal": {
        #     "pe1": "generators.evpn_bgp.scenarios.mixed.MixedUnseenTopologyPE1Removed",
        # },
        # "unseen-topology": {
        #     "pe6-joins": "generators.evpn_bgp.scenarios.mixed.MixedUnseenTopology",
        # },
        # ------------------------------------------------------------------
        # A. NEW fault types — never seen in Section 2 training
        # ------------------------------------------------------------------
        # "as-misconfig": {
        #     "pe1": "generators.evpn_bgp.scenarios.eval_scenarios.ASMisconfigPE1",
        #     "pe3": "generators.evpn_bgp.scenarios.eval_scenarios.ASMisconfigPE3",
        # },
        # "hold-timer-mismatch": {
        #     "pe2": "generators.evpn_bgp.scenarios.eval_scenarios.HoldTimerMismatchPE2",
        # },
        # "max-prefix": {
        #     "pe1": "generators.evpn_bgp.scenarios.eval_scenarios.MaxPrefixLimitPE1",
        # },
        # "admin-reset": {
        #     "pe2": "generators.evpn_bgp.scenarios.eval_scenarios.AdminResetPE2",
        #     "pe3": "generators.evpn_bgp.scenarios.eval_scenarios.AdminResetPE3",
        # },
        # "peer-deconfig": {
        #     "pe1": "generators.evpn_bgp.scenarios.eval_scenarios.PeerDeConfigPE1",
        # },
        # "invalid-nexthop": {
        #     "pe1": "generators.evpn_bgp.scenarios.eval_scenarios.InvalidNextHopPE1",
        #     "pe3": "generators.evpn_bgp.scenarios.eval_scenarios.InvalidNextHopPE3",
        # },
        # "dup-mac": {
        #     "pe1-pe3": "generators.evpn_bgp.scenarios.eval_scenarios.DuplicateMACPE1PE3",
        # },
        # "vni-mismatch": {
        #     "pe2": "generators.evpn_bgp.scenarios.eval_scenarios.VNIMismatchPE2",
        # },
        # "fsm-error": {
        #     "pe1": "generators.evpn_bgp.scenarios.eval_scenarios.FSMErrorPE1",
        #     "pe3": "generators.evpn_bgp.scenarios.eval_scenarios.FSMErrorPE3",
        # },
        # "malformed-aspath": {
        #     "pe2": "generators.evpn_bgp.scenarios.eval_scenarios.MalformedASPathPE2",
        # },
        # "out-of-resources": {
        #     "rr1": "generators.evpn_bgp.scenarios.eval_scenarios.OutOfResourcesRR1",
        #     "rr2": "generators.evpn_bgp.scenarios.eval_scenarios.OutOfResourcesRR2",
        # },
        # "af-mismatch": {
        #     "pe1": "generators.evpn_bgp.scenarios.eval_scenarios.AFMismatchPE1",
        #     "pe3": "generators.evpn_bgp.scenarios.eval_scenarios.AFMismatchPE3",
        # },
        # "graceful-restart": {
        #     "pe1": "generators.evpn_bgp.scenarios.eval_scenarios.GracefulRestartPE1",
        #     "pe3": "generators.evpn_bgp.scenarios.eval_scenarios.GracefulRestartPE3",
        #     "timeout-pe2": "generators.evpn_bgp.scenarios.eval_scenarios.GracefulRestartTimeoutPE2",
        # },
        # ------------------------------------------------------------------
        # B. Missing pairwise combinations
        # ------------------------------------------------------------------
        # "rr-esdf": {
            # "rr1-pe1": "generators.evpn_bgp.scenarios.eval_scenarios.RRDownESDFRR1PE1",
        # },
        # "rr-rt": {
            # "rr1-pe2": "generators.evpn_bgp.scenarios.eval_scenarios.RRDownRTRR1PE2",
        # },
        # "esdf-rt": {
            # "pe1-pe2": "generators.evpn_bgp.scenarios.eval_scenarios.ESDFRTPe1Pe2",
        # },
        # ------------------------------------------------------------------
        # C. Triple combinations
        # ------------------------------------------------------------------
        # "triple": {
            # "ld-rr-esdf": "generators.evpn_bgp.scenarios.eval_scenarios.TripleLDRRESScenario",
        # },
        # ------------------------------------------------------------------
        # D. Cross-combinations: existing + new fault type
        # ------------------------------------------------------------------
        # "cross": {
        #     "rr-as-misconfig":    "generators.evpn_bgp.scenarios.eval_scenarios.RRASMisconfigScenario",
        #     "rt-invalid-nexthop": "generators.evpn_bgp.scenarios.eval_scenarios.RTInvalidNextHopScenario",
        # },
        # ------------------------------------------------------------------
        # Intermittent RR flaps — unique to Section 3 (section4.* variants live in Section 4)
        # ------------------------------------------------------------------
        # "intermittent": {
            # "rr-flap-rr1": "generators.evpn_bgp.scenarios.rr_down.RRDownIntermittentFlapRR1",
            # "rr-flap-rr2": "generators.evpn_bgp.scenarios.rr_down.RRDownIntermittentFlapRR2",
        # },
        # ------------------------------------------------------------------
        # E. RD Collision (RFC 7432 RD uniqueness violation)
        # ------------------------------------------------------------------
        # "rd-collision": {
        #     "pe1-pe3": "generators.evpn_bgp.scenarios.eval_scenarios.RDCollisionPE1PE3",
        #     "recovery-pe1-pe3": "generators.evpn_bgp.scenarios.eval_scenarios.RDCollisionRecoveryPE1PE3",
        # },
    # },
    # 4: {
        # "cascade": {
            # "rr-down-esdf-rr1": "generators.evpn_bgp.scenarios.section4.CascadeRRDownESDFRR1",
            # "rr-down-esdf-rr2": "generators.evpn_bgp.scenarios.section4.CascadeRRDownESDFRR2",
            # "link-down-rtmisconfig-pe1": "generators.evpn_bgp.scenarios.section4.CascadeLinkDownRTMisconfigPE1",
        # },
        # "intermittent": {
            # "link-flap-pe1": "generators.evpn_bgp.scenarios.section4.IntermittentLinkFlapPE1",
            # "link-flap-pe2": "generators.evpn_bgp.scenarios.section4.IntermittentLinkFlapPE2",
            # "esdf-toggle-pe1": "generators.evpn_bgp.scenarios.section4.IntermittentESDFTogglePE1",
            # "esdf-toggle-pe2": "generators.evpn_bgp.scenarios.section4.IntermittentESDFTogglePE2",
        # },
        # "slow-degradation": {
        #     "pe1": "generators.evpn_bgp.scenarios.section4.SlowDegradationPE1",
        #     "pe2": "generators.evpn_bgp.scenarios.section4.SlowDegradationPE2",
        # },
        # "session-flap": {
        #     "pe1": "generators.evpn_bgp.scenarios.section4.BGPSessionFlapPE1",
        #     "pe2": "generators.evpn_bgp.scenarios.section4.BGPSessionFlapPE2",
        #     "rr1": "generators.evpn_bgp.scenarios.section4.BGPSessionFlapRR1",
        # },
        # "mid-session": {
            # "link-down-pe1": "generators.evpn_bgp.scenarios.section4.MidSessionLinkDownPE1",
            # "link-down-pe2": "generators.evpn_bgp.scenarios.section4.MidSessionLinkDownPE2",
            # "link-down-pe3": "generators.evpn_bgp.scenarios.section4.MidSessionLinkDownPE3",
        # },
    # },
}

SECTION_DIR_MAP = {
    1: "section1_normal",
    2: "section2_labelled",
    3: "section3_mixed",
    4: "section4_additional",
}

DEFAULT_FRAMES = {1: 116000, 2: 8000, 3: 8000, 4: 30000}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _import_class(dotted_path: str):
    """Dynamically import a class from its dotted module path."""
    module_path, class_name = dotted_path.rsplit(".", 1)
    import importlib
    mod = importlib.import_module(module_path)
    return getattr(mod, class_name)


def _class_default_frames(ScenarioClass, section_default: int) -> int:
    """Return the class-level target_frames default if set, else section_default."""
    import inspect
    try:
        sig = inspect.signature(ScenarioClass.__init__)
        param = sig.parameters.get('target_frames')
        if param and param.default is not inspect.Parameter.empty:
            return param.default
    except Exception:
        pass
    return section_default


def _filename_for_scenario(fault_type: str, variant: str | None, copy_idx: int) -> str:
    """Build output filename following student convention."""
    parts = fault_type.replace("-", "_")
    if variant:
        parts += f"_{variant.replace('-', '_')}"
    if copy_idx > 1:
        parts += f"_{copy_idx:03d}"
    return f"{parts}.pcap"


def _iter_scenarios(section=None, fault_type=None, variant=None):
    """Yield (section, fault_type, variant, class_path) tuples matching filters."""
    sections = [section] if section else sorted(SCENARIO_REGISTRY.keys())
    for sec in sections:
        faults = SCENARIO_REGISTRY.get(sec, {})
        fault_keys = [fault_type] if fault_type else sorted(faults.keys())
        for ft in fault_keys:
            variants = faults.get(ft, {})
            if not variants:
                continue
            variant_keys = [variant] if variant else sorted(variants.keys(), key=lambda v: v or "")
            for var in variant_keys:
                class_path = variants.get(var)
                if class_path:
                    yield sec, ft, var, class_path


def _print_scenario_table():
    """Print a formatted table of all available scenarios."""
    header = f"{'Section':<9} {'Fault Type':<14} {'Variant':<20} {'Class'}"
    click.echo(header)
    click.echo("-" * (len(header) + 20))
    for sec, ft, var, cls_path in _iter_scenarios():
        var_display = var if var else "—"
        click.echo(f"{sec:<9} {ft:<14} {var_display:<20} {cls_path}")


# ---------------------------------------------------------------------------
# CLI definition
# ---------------------------------------------------------------------------

@click.command(context_settings={"help_option_names": ["-h", "--help"]})
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to topology YAML config.")
@click.option("--output", "-o", type=click.Path(), help="Output directory for pcap files.")
@click.option("--capture-vantage", type=str, default=None,
              help="Override the config file's capture_vantage (e.g. RR1, RR2) for this run, "
                   "without needing a separate topology YAML per vantage.")
@click.option("--all", "generate_all", is_flag=True, help="Generate all scenarios.")
@click.option("--section", "-s", type=int, help="Generate scenarios for a specific section (1, 2, 3, or 4).")
@click.option("--fault-type", "-f", type=str, help="Generate scenarios for a specific fault type.")
@click.option("--variant", "-v", type=str, help="Generate a specific variant of a fault type.")
@click.option("--frames-per-file", type=int, default=None, help="Number of frames per pcap file.")
@click.option("--copies", type=int, default=1, help="Number of pcap copies per scenario.")
@click.option("--seed", type=int, default=42,
              help="Seed the RNG for reproducible generation. Same seed + same "
                   "selection yields byte-identical pcaps; use different seeds "
                   "to produce distinct train vs test instances of a scenario.")
@click.option("--list-scenarios", is_flag=True, help="List all available scenarios and exit.")
@click.option("--metadata/--no-metadata", default=True,
              help="Generate dataset_metadata.xlsx and per-pcap JSON alongside pcaps. "
                   "Use --no-metadata to skip.")
def main(config, output, capture_vantage, generate_all, section, fault_type, variant, frames_per_file,
         copies, seed, list_scenarios, metadata):
    """Synthetic EVPN pcap generator CLI.

    Generate pcap files containing synthetic BGP/EVPN traffic for
    ML model training and evaluation.
    """
    if list_scenarios:
        _print_scenario_table()
        return

    # Validate required options for generation
    if not config:
        raise click.UsageError("--config is required for generation (or use --list-scenarios).")
    if not output:
        raise click.UsageError("--output is required for generation.")
    if not (generate_all or section or fault_type):
        raise click.UsageError("Specify --all, --section, or --fault-type to select scenarios.")

    from .config import load_config

    # Per-scenario seeding: each scenario is seeded from a hash of (global_seed,
    # class_path, copy_idx) so its output is independent of what else runs in the
    # same CLI invocation.  "--seed 42 --fault-type esdf-toggle" and
    # "--seed 42 --all" will therefore produce byte-identical ESDF files.
    def _scenario_seed(global_seed: int, cls_path: str, copy_idx: int) -> int:
        key = f"{global_seed}:{cls_path}:{copy_idx}"
        return int(hashlib.md5(key.encode()).hexdigest(), 16) % (2**31)

    click.echo(f"Seeded RNG with global seed {seed} (per-scenario deterministic seeding).")

    topology_config = load_config(config)
    if capture_vantage:
        if not topology_config.get_router(capture_vantage):
            raise click.UsageError(
                f"--capture-vantage {capture_vantage!r} is not a router in {config}."
            )
        topology_config.capture_vantage = capture_vantage
    output_dir = Path(output)
    # Reject a --output path that already ends in one of SECTION_DIR_MAP's
    # names, since this CLI always appends the target section's directory
    # onto --output itself and would otherwise create a wrongly-nested
    # directory (e.g. "output/section2_labelled/section2_labelled").
    if output_dir.name in SECTION_DIR_MAP.values():
        raise click.UsageError(
            f"--output {output!r} already ends in {output_dir.name!r}, one of this "
            f"CLI's own section directory names ({sorted(SECTION_DIR_MAP.values())}). "
            f"This CLI always appends the target section's directory onto --output "
            f"itself, so this would create a wrongly-nested "
            f"{output_dir.name}/{output_dir.name}/ directory. Pass the parent "
            f"directory instead (e.g. {str(output_dir.parent)!r})."
        )
    output_dir.mkdir(parents=True, exist_ok=True)

    # Collect scenarios to generate
    scenarios = list(_iter_scenarios(section=section, fault_type=fault_type, variant=variant))
    if not scenarios:
        click.echo("No matching scenarios found.", err=True)
        sys.exit(1)

    click.echo(f"Generating {len(scenarios)} scenario(s) × {copies} cop(ies)...")
    click.echo(f"Config: {config}")
    click.echo(f"Output: {output_dir.resolve()}\n")

    generated_files: list[Path] = []

    for sec, ft, var, cls_path in scenarios:
        ScenarioClass = _import_class(cls_path)
        if frames_per_file:
            frames = frames_per_file
        else:
            frames = _class_default_frames(ScenarioClass, DEFAULT_FRAMES[sec])
        section_dir = output_dir / SECTION_DIR_MAP[sec]
        section_dir.mkdir(parents=True, exist_ok=True)

        scenario_label = f"{ft}/{var}" if var else ft
        click.echo(f"  [{sec}] {scenario_label} ({frames} frames)")

        for copy_idx in range(1, copies + 1):
            random.seed(_scenario_seed(seed, cls_path, copy_idx))
            filename = _filename_for_scenario(ft, var, copy_idx)
            out_path = section_dir / filename

            scenario = ScenarioClass(config=topology_config, target_frames=frames)
            pkt_count = scenario.write(out_path, seed=seed, copy_idx=copy_idx)
            generated_files.append(out_path)
            click.echo(f"    -> {out_path.relative_to(output_dir)} ({pkt_count} packets)")

    click.echo(f"\nDone. Generated {len(generated_files)} pcap file(s).")

    # Metadata generation — Excel spreadsheet + JSON ground-truth files
    if metadata:
        # Excel spreadsheet
        try:
            from .metadata import generate_default_metadata
            from .config import load_config as _lc
            cfg = _lc(config)
            if capture_vantage:
                cfg.capture_vantage = capture_vantage
            writer = generate_default_metadata(cfg, output_dir)
            meta_path = writer.write()
            click.echo(f"[OK] Metadata spreadsheet written to {meta_path}")
        except ImportError as e:
            click.echo(
                f"[WARN] Metadata writer not available ({e}). Skipping spreadsheet.",
                err=True,
            )

        # JSON ground-truth — one .json per .pcap
        try:
            import importlib.util as _ilu
            _script = Path(__file__).parent.parent.parent / "scripts" / "generate_json.py"
            _spec = _ilu.spec_from_file_location("generate_json", _script)
            _mod = _ilu.module_from_spec(_spec)
            _spec.loader.exec_module(_mod)
            click.echo("Generating JSON files...")
            _mod.write_json(output_dir)
            click.echo("[OK] JSON files written.")
        except Exception as e:
            click.echo(f"[WARN] JSON generation failed ({e}).", err=True)


if __name__ == "__main__":
    main()
