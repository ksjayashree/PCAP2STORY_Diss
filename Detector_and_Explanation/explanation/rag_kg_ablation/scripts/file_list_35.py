"""The finalized 35-file stratified ablation sample (folder paths taken
directly from ablation_35_detector_output.json's "folder" field, in the
same order as that file's top-level keys). Materialized here as a plain
list so this ablation study depends on a real project file, not an
ephemeral session scratchpad. Supersedes file_list_44.py for all new
ablation runs."""

FILE_LIST_35 = [
    r"C:\simulation pcap\pilot_containerlab\pcaps\link_down\single\link_down_bfd_pe1_notrecovered",
    r"C:\simulation pcap\pilot_containerlab\pcaps\link_down\single\link_down_bfd_pe1_recovered",
    r"C:\simulation pcap\3rr\pcaps\link_down\single\link_down_holdtimer_xpe1_notrecovered",
    r"C:\simulation pcap\3rr\pcaps\link_down\single\link_down_holdtimer_xpe1_recovered",
    r"C:\simulation pcap\pilot_containerlab\pcaps\link_down\single\link_down_tcpfail_pe1_notrecovered",
    r"C:\simulation pcap\pilot_containerlab\pcaps\link_down\single\link_down_tcpfail_pe1_recovered",
    r"C:\simulation pcap\pilot_containerlab\pcaps\rr_down\single\rr_down_bgpdkill_rr1_notrecovered",
    r"C:\simulation pcap\pilot_containerlab\pcaps\rr_down\single\rr_down_bgpdkill_rr1_recovered",
    r"C:\simulation pcap\3rr\pcaps\rr_down\single\rr_down_graceful_xrr1_notrecovered",
    r"C:\simulation pcap\3rr\pcaps\rr_down\single\rr_down_graceful_xrr1_recovered",
    r"C:\simulation pcap\pilot_containerlab\pcaps\pe_cease\single\pe_cease_pe1_notrecovered",
    r"C:\simulation pcap\3rr\pcaps\pe_cease\single\pe_cease_xpe1_recovered",
    r"C:\simulation pcap\pilot_containerlab\pcaps\rt_misconfig\single\rt_misconfig_autoderive_export_pe1_notfixed",
    r"C:\simulation pcap\3rr\pcaps\rt_misconfig\single\rt_misconfig_autoderive_export_xpe1_fixed",
    r"C:\synthcap\output\rt_misconfig\single\rt_misconfig_es_import_pe1",
    r"C:\synthcap\output\rt_misconfig\single\rt_misconfig_es_import_recovery_pe1",
    r"C:\synthcap\output_3rr\rt_misconfig\single\rt_misconfig_es_import_pe3",
    r"C:\simulation pcap\pilot_containerlab\pcaps\rd_collision\single\rd_collision_pe3_pe4_notfixed",
    r"C:\simulation pcap\pilot_containerlab\pcaps\rd_collision\single\rd_collision_pe3_pe4_fixed",
    r"C:\simulation pcap\3rr\pcaps\rd_collision\single\rd_collision_xpe3_xpe4_notfixed",
    r"C:\simulation pcap\3rr\pcaps\rd_collision\single\rd_collision_xpe3_xpe4_fixed",
    r"C:\simulation pcap\pilot_containerlab\pcaps\rd_collision\single\rd_collision_pe3_pe4_pe5_notfixed",
    r"C:\simulation pcap\pilot_containerlab\pcaps\mac_mobility\single\mac_mobility_cleanmove_pe3to4_settled",
    r"C:\simulation pcap\3rr\pcaps\mac_mobility\single\mac_mobility_cleanmove_xpe7to5_settled",
    r"C:\synthcap\output\mac_mobility\single\mac_mobility_rapid_pe4_pe5",
    r"C:\synthcap\output\esdf_toggle\single\esdf_toggle_ac_state_pe1",
    r"C:\synthcap\output\esdf_toggle\single\esdf_toggle_full_failure_no_recovery",
    r"C:\synthcap\output\esdf_toggle\single\esdf_toggle_full_failure_recovery",
    r"C:\synthcap\output_3rr\esdf_toggle\single\esdf_toggle_full_failure_no_recovery_pe3pe4",
    r"C:\synthcap\output_3rr\esdf_toggle\single\esdf_toggle_full_failure_recovery_pe3pe4",
    r"C:\synthcap\output\esdf_toggle\single\esdf_toggle_type1_evi_pe1",
    r"C:\synthcap\output\esdf_toggle\single\esdf_toggle_single_pe1",
    r"C:\simulation pcap\pilot_containerlab\pcaps\multiple\catB_link_down_x2\catB_link_down_x2_bfd_pe1_holdtimer_pe3",
    r"C:\simulation pcap\pilot_containerlab\pcaps\multiple\catC_rr_down_pe_cease\catC_rrdown_rr2_pecease_pe1",
    r"C:\simulation pcap\3rr\pcaps\multiple\catC_pe_cease_rd_collision\catC_pecease_xpe2_rdcollision_xpe8xpe9",
]
