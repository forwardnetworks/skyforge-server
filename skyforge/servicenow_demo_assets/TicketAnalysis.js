var TicketAnalysis = Class.create();
TicketAnalysis.prototype = {
  initialize: function () {
    this._forward = new ForwardClient();
    this._normalizer = new PathNormalizer();
  },

  _tableFromProperty: function (propName, defaultTable, fallbackTable) {
    function isValidTable(name) {
      try {
        var gr = new GlideRecord(String(name || ""));
        return gr && gr.isValid();
      } catch (e) {
        return false;
      }
    }

    var t = String(gs.getProperty(propName, defaultTable) || "");
    if (t && isValidTable(t)) return t;
    if (fallbackTable && isValidTable(fallbackTable)) return String(fallbackTable);
    return String(defaultTable);
  },

  _ticketTable: function () {
    // Prefer a user-friendly custom table name (Global scope => "u_*"), but fall back
    // to the older demo name if needed.
    return this._tableFromProperty(
      "x_fwd_demo.tables.ticket",
      "u_forward_connectivity_ticket",
      "x_fwd_demo_connectivity_ticket"
    );
  },

  _hopTable: function () {
    return this._tableFromProperty(
      "x_fwd_demo.tables.hop",
      "u_forward_connectivity_hop",
      "x_fwd_demo_connectivity_hop"
    );
  },

  analyzeTicketBySysId: function (ticketSysId) {
    if (!ticketSysId) throw new Error("ticketSysId is required");

    var ticket = new GlideRecord(this._ticketTable());
    if (!ticket.get(ticketSysId)) throw new Error("Ticket not found: " + ticketSysId);

    ticket.u_analysis_status = "running";
    ticket.u_analysis_error = "";
    ticket.update();

    try {
      var snapshotId = String(ticket.u_forward_snapshot_id || "");
      if (!snapshotId) {
        // Pick latest processed snapshot if unset (better demo UX).
        var snaps = this._forward.listSnapshots(String(ticket.u_forward_network_id));
        if (snaps && snaps.length) snapshotId = String(snaps[0].id);
      }
      if (!snapshotId) throw new Error("forward snapshot id required");

      var raw = this._forward.pathSearch({
        networkId: String(ticket.u_forward_network_id),
        snapshotId: snapshotId,
        srcIp: String(ticket.u_src_ip),
        dstIp: String(ticket.u_dst_ip),
        protocol: String(ticket.u_protocol),
        dstPort: String(ticket.u_dst_port),
      });

      var norm = this._normalizer.normalize(raw);
      this._persist(ticket, norm);

      ticket.u_analysis_status = "complete";
      ticket.u_analysis_error = "";
      ticket.update();
    } catch (e) {
      ticket.u_analysis_status = "error";
      ticket.u_analysis_error = e && e.message ? String(e.message) : "Unknown error";
      ticket.update();
      throw e;
    }
  },

  _persist: function (ticket, norm) {
    ticket.u_allowed = Boolean(norm.allowed);
    ticket.u_block_category = norm.block_category || "unknown";
    ticket.u_block_device = norm.block_device || "";
    ticket.u_block_interface = norm.block_interface || "";
    ticket.u_block_rule = norm.block_rule || "";
    ticket.u_block_reason = norm.block_reason || "";
    ticket.u_forward_query_url = norm.query_url || "";
    ticket.u_raw_excerpt = norm.raw_excerpt || "";
    ticket.update();

    var hopGr = new GlideRecord(this._hopTable());
    hopGr.addQuery("u_ticket", ticket.sys_id);
    hopGr.deleteMultiple();

    var hops = Array.isArray(norm.hops) ? norm.hops : [];
    for (var i = 0; i < hops.length; i++) {
      var h = hops[i] || {};
      var rec = new GlideRecord(this._hopTable());
      rec.initialize();
      rec.u_ticket = ticket.sys_id;
      rec.u_hop_index = h.hop_index || i + 1;
      rec.u_device = h.device || "";
      rec.u_ingress = h.ingress || "";
      rec.u_egress = h.egress || "";
      rec.u_note = h.note || "";
      rec.insert();
    }
  },

  type: "TicketAnalysis",
};
