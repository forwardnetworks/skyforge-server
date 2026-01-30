var ForwardClient = Class.create();
ForwardClient.prototype = {
  initialize: function () {},

  listNetworks: function () {
    var resp = this._execute("List Networks", {});
    if (!resp || !Array.isArray(resp)) return [];

    var out = [];
    for (var i = 0; i < resp.length; i++) {
      var n = resp[i] || {};
      if (typeof n.id !== "string") continue;
      out.push({ id: n.id, name: typeof n.name === "string" ? n.name : n.id });
    }
    return out;
  },

  listSnapshots: function (networkId) {
    if (!networkId) throw new Error("networkId is required");

    var resp = this._execute("List Snapshots", { networkId: networkId });
    if (!resp || typeof resp !== "object") return [];

    var snapshots = Array.isArray(resp.snapshots) ? resp.snapshots : [];
    var out = [];
    for (var i = 0; i < snapshots.length; i++) {
      var s = snapshots[i] || {};
      if (typeof s.id !== "string") continue;
      out.push({
        id: s.id,
        createdAt: typeof s.createdAt === "string" ? s.createdAt : "",
        processedAt: typeof s.processedAt === "string" ? s.processedAt : "",
        note: typeof s.note === "string" ? s.note : "",
      });
    }
    return out;
  },

  pathSearch: function (args) {
    args = args || {};
    var required = ["networkId", "snapshotId", "srcIp", "dstIp", "protocol", "dstPort"];
    for (var i = 0; i < required.length; i++) {
      if (!args[required[i]]) throw new Error(required[i] + " is required");
    }

    var ipProto = String(args.protocol).toUpperCase() === "TCP" ? 6 : 17;
    var maxResults = gs.getProperty("x_fwd_demo.forward.max_results", "1");

    return this._execute("Path Search", {
      networkId: args.networkId,
      query: {
        srcIp: args.srcIp,
        dstIp: args.dstIp,
        ipProto: ipProto,
        dstPort: String(args.dstPort),
        snapshotId: args.snapshotId,
        includeNetworkFunctions: "true",
        maxResults: String(maxResults),
      },
    });
  },

  _execute: function (methodName, opts) {
    opts = opts || {};
    var rm = new sn_ws.RESTMessageV2("Forward API", methodName);

    // Build endpoint from property + known API paths (avoids brittle REST Message endpoint config).
    var baseUrl = String(gs.getProperty("x_fwd_demo.forward.base_url", "https://fwd.app/api"));
    baseUrl = baseUrl.replace(/\/+$/, "");
    var endpointPath = this._endpointPathFor(methodName, opts);
    rm.setEndpoint(baseUrl + endpointPath);

    // Prefer a platform-managed credential on the REST Message, but fall back to explicit
    // basic auth properties if present (useful for automated installers).
    var u = String(gs.getProperty("x_fwd_demo.forward.username", ""));
    var p = String(gs.getProperty("x_fwd_demo.forward.password", ""));
    if (u && p) rm.setBasicAuth(u, p);

    if (opts.networkId) rm.setStringParameterNoEscape("networkId", String(opts.networkId));

    var q = opts.query || {};
    for (var k in q) {
      if (!q.hasOwnProperty(k)) continue;
      rm.setQueryParameter(k, String(q[k]));
    }

    var response = rm.execute();
    var status = response.getStatusCode();
    var body = response.getBody();

    if (status < 200 || status >= 300) {
      var msg = "Forward API error (" + status + ")";
      // Avoid logging secrets; response body is safe but may be large.
      throw new Error(msg + ": " + body);
    }

    if (!body) return null;
    try {
      return JSON.parse(body);
    } catch (e) {
      throw new Error("Failed to parse Forward JSON response");
    }
  },

  _endpointPathFor: function (methodName, opts) {
    // All endpoints are relative to /api (see complete.json "servers": [{ "url": "/api" }]).
    // RESTMessageV2 requires a full URL, so we concatenate with x_fwd_demo.forward.base_url.
    switch (methodName) {
      case "List Networks":
        return "/networks";
      case "List Snapshots":
        return "/networks/" + encodeURIComponent(String(opts.networkId || "")) + "/snapshots";
      case "Path Search":
        return "/networks/" + encodeURIComponent(String(opts.networkId || "")) + "/paths";
      default:
        throw new Error("Unknown Forward API method: " + methodName);
    }
  },

  type: "ForwardClient",
};
