(function () {
  data.networks = [];
  data.snapshots = [];

  function tableFromProperty(propName, defaultTable, fallbackTable) {
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
  }

  function ticketTable() {
    return tableFromProperty(
      "x_fwd_demo.tables.ticket",
      "u_forward_connectivity_ticket",
      "x_fwd_demo_connectivity_ticket"
    );
  }

  function hopTable() {
    return tableFromProperty(
      "x_fwd_demo.tables.hop",
      "u_forward_connectivity_hop",
      "x_fwd_demo_connectivity_hop"
    );
  }

  function bad(msg) {
    data.error = msg;
    return;
  }

  function serializeTicket(t) {
    return {
      sys_id: String(t.sys_id),
      number: String(t.number),
      u_analysis_status: String(t.u_analysis_status || ""),
      u_analysis_error: String(t.u_analysis_error || ""),
      u_allowed: String(t.u_allowed) === "true" || String(t.u_allowed) === "1",
      u_block_category: String(t.u_block_category || ""),
      u_block_device: String(t.u_block_device || ""),
      u_block_interface: String(t.u_block_interface || ""),
      u_block_rule: String(t.u_block_rule || ""),
      u_block_reason: String(t.u_block_reason || ""),
      u_forward_query_url: String(t.u_forward_query_url || ""),
      u_raw_excerpt: String(t.u_raw_excerpt || ""),
      assignment_group: String(t.assignment_group || ""),
    };
  }

  function serializeHop(h) {
    return {
      sys_id: String(h.sys_id),
      u_hop_index: parseInt(String(h.u_hop_index), 10) || 0,
      u_device: String(h.u_device || ""),
      u_ingress: String(h.u_ingress || ""),
      u_egress: String(h.u_egress || ""),
      u_note: String(h.u_note || ""),
    };
  }

  function getGroupSysIdByName(name) {
    var gr = new GlideRecord("sys_user_group");
    gr.addQuery("name", name);
    gr.setLimit(1);
    gr.query();
    return gr.next() ? String(gr.sys_id) : "";
  }

  try {
    var action = (input && input.action) || (options && options.action) || (request && request.queryParams && request.queryParams.action) || "";
    if (!action) action = (input && input.action) || (request && request.queryParams && request.queryParams.action) || "";

    if (!action || action === "init") {
      data.networks = new ForwardClient().listNetworks();
      return;
    }

    if (action === "snapshots") {
      var networkId = (input && input.networkId) || (request.queryParams && request.queryParams.networkId) || "";
      data.snapshots = new ForwardClient().listSnapshots(networkId);
      return;
    }

    if (action === "create") {
      var form = (input && input.form) || {};
      var t = new GlideRecord(ticketTable());
      t.initialize();
      t.short_description = "Connectivity check: " + (form.srcIp || "") + " -> " + (form.dstIp || "");
      t.u_src_ip = form.srcIp || "";
      t.u_dst_ip = form.dstIp || "";
      t.u_protocol = form.protocol || "TCP";
      t.u_dst_port = parseInt(form.dstPort, 10) || 0;
      t.u_forward_network_id = form.networkId || "";
      t.u_forward_snapshot_id = form.snapshotId || "";
      t.u_analysis_status = "not_run";
      var sysId = t.insert();
      data.ticketSysId = String(sysId);
      data.ticketNumber = String(t.number);
      return;
    }

    if (action === "analyze") {
      var ticketSysId = input.ticketSysId || "";
      if (!ticketSysId) return bad("ticketSysId required");
      var t2 = new GlideRecord(ticketTable());
      if (!t2.get(ticketSysId)) return bad("Ticket not found");
      // Prefer a synchronous analysis run to avoid relying on Script Actions (which
      // may be restricted from Table API automation in some PDIs). This keeps the
      // demo "dead simple" and reduces manual steps.
      new TicketAnalysis().analyzeTicketBySysId(ticketSysId);
      return;
    }

    if (action === "result") {
      var ticketSysId2 = (input && input.ticketSysId) || (request.queryParams && request.queryParams.ticketSysId) || "";
      if (!ticketSysId2) return bad("ticketSysId required");
      var ticket = new GlideRecord(ticketTable());
      if (!ticket.get(ticketSysId2)) return bad("Ticket not found");
      data.ticket = serializeTicket(ticket);

      var hops = [];
      var hopGr = new GlideRecord(hopTable());
      hopGr.addQuery("u_ticket", ticket.sys_id);
      hopGr.orderBy("u_hop_index");
      hopGr.query();
      while (hopGr.next()) hops.push(serializeHop(hopGr));
      data.hops = hops;
      return;
    }

    if (action === "route") {
      var team = String(input.team || "");
      var ticketSysId3 = String(input.ticketSysId || "");
      if (!ticketSysId3) return bad("ticketSysId required");

      var ticket3 = new GlideRecord(ticketTable());
      if (!ticket3.get(ticketSysId3)) return bad("Ticket not found");

      var propName =
        team === "network"
          ? "x_fwd_demo.groups.network"
          : team === "security"
          ? "x_fwd_demo.groups.security"
          : "x_fwd_demo.groups.triage";
      var groupName = gs.getProperty(propName, "");
      var groupSysId = groupName ? getGroupSysIdByName(groupName) : "";
      if (groupSysId) ticket3.assignment_group = groupSysId;
      ticket3.work_notes = "Manually routed via portal widget (demo)";
      ticket3.update();
      return;
    }

    return bad("Unknown action: " + action);
  } catch (e) {
    return bad(e && e.message ? e.message : "Server error");
  }
})();
