function ($scope, spUtil) {
  var c = this;

  c.state = {
    loading: true,
    working: false,
    error: "",
    networks: [],
    snapshots: [],
    ticketSysId: "",
    ticketNumber: "",
    result: null,
    hops: [],
  };

  c.form = {
    networkId: "",
    snapshotId: "",
    srcIp: "",
    dstIp: "",
    protocol: "TCP",
    dstPort: "",
  };

  c.init = function () {
    c.state.loading = true;
    c.server.get({ action: "init" }).then(
      function (r) {
        c.state.networks = r.data.networks || [];
        c.state.loading = false;
      },
      function () {
        c.state.error = "Failed to load networks";
        c.state.loading = false;
      },
    );
  };

  c.onNetworkChange = function () {
    c.state.snapshots = [];
    c.form.snapshotId = "";
    if (!c.form.networkId) return;
    c.state.working = true;
    c.server.get({ action: "snapshots", networkId: c.form.networkId }).then(
      function (r) {
        c.state.snapshots = r.data.snapshots || [];
        if (c.state.snapshots.length) c.form.snapshotId = c.state.snapshots[0].id;
        c.state.working = false;
      },
      function () {
        c.state.error = "Failed to load snapshots";
        c.state.working = false;
      },
    );
  };

  c.createTicket = function () {
    c.state.error = "";
    c.state.working = true;
    c.server.update({ action: "create", form: c.form }).then(
      function (r) {
        c.state.ticketSysId = r.data.ticketSysId;
        c.state.ticketNumber = r.data.ticketNumber;
        c.state.working = false;
      },
      function () {
        c.state.error = "Failed to create ticket";
        c.state.working = false;
      },
    );
  };

  c.analyze = function () {
    c.state.error = "";
    c.state.working = true;
    c.server.update({ action: "analyze", ticketSysId: c.state.ticketSysId }).then(
      function () {
        // Analysis runs async; poll until complete.
        c.pollResult(0);
      },
      function () {
        c.state.error = "Failed to start analysis";
        c.state.working = false;
      },
    );
  };

  c.pollResult = function (attempt) {
    c.server.get({ action: "result", ticketSysId: c.state.ticketSysId }).then(
      function (r) {
        c.state.result = r.data.ticket || null;
        c.state.hops = r.data.hops || [];

        var st = c.state.result ? c.state.result.u_analysis_status : "";
        if (st === "running" && attempt < 20) {
          setTimeout(function () {
            c.pollResult(attempt + 1);
          }, 1500);
          return;
        }
        if (st === "error") c.state.error = c.state.result.u_analysis_error || "Analysis failed";
        c.state.working = false;
      },
      function () {
        c.state.error = "Failed to load result";
        c.state.working = false;
      },
    );
  };

  c.route = function (team) {
    c.state.error = "";
    c.state.working = true;
    c.server.update({ action: "route", ticketSysId: c.state.ticketSysId, team: team }).then(
      function () {
        c.pollResult(0);
      },
      function () {
        c.state.error = "Failed to route ticket";
        c.state.working = false;
      },
    );
  };

  c.init();
}

