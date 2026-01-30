var PathNormalizer = Class.create();
PathNormalizer.prototype = {
  initialize: function () {},

  normalize: function (raw) {
    raw = raw || {};
    var result = {
      allowed: false,
      block_category: "unknown",
      block_device: "",
      block_interface: "",
      block_rule: "",
      block_reason: "",
      query_url: "",
      raw_excerpt: "",
      hops: [],
    };

    try {
      if (raw && raw.query && raw.query.url) result.query_url = String(raw.query.url);
      result.raw_excerpt = this._excerpt(raw);

      var paths = Array.isArray(raw.paths) ? raw.paths : [];
      if (!paths.length) {
        result.block_reason = "No paths returned";
        return result;
      }

      var p = paths[0] || {};
      result.allowed = Boolean(p.isAllowed || p.allowed);

      var hops = Array.isArray(p.hops) ? p.hops : [];
      result.hops = this._normalizeHops(hops);

      if (!result.allowed) {
        var block = this._findBlock(hops);
        if (block) {
          result.block_device = block.device || "";
          result.block_interface = block.interface || "";
          result.block_rule = block.rule || "";
          result.block_reason = block.reason || "Blocked";
          result.block_category = block.category || "unknown";
        } else {
          result.block_reason = "Blocked (unknown location)";
        }
      } else {
        result.block_reason = "Allowed";
      }
      return result;
    } catch (e) {
      result.block_reason = e && e.message ? String(e.message) : "Normalization error";
      return result;
    }
  },

  _normalizeHops: function (hops) {
    var out = [];
    for (var i = 0; i < hops.length; i++) {
      var h = hops[i] || {};
      out.push({
        hop_index: i + 1,
        device: String(h.deviceName || h.device || ""),
        ingress: String(h.inIntf || h.ingressInterface || h.ingress || ""),
        egress: String(h.outIntf || h.egressInterface || h.egress || ""),
        note: String(h.note || ""),
      });
    }
    return out;
  },

  _findBlock: function (hops) {
    // Best-effort: find the first hop that indicates a deny/drop.
    for (var i = 0; i < hops.length; i++) {
      var h = hops[i] || {};
      if (h.disposition && String(h.disposition).toLowerCase().indexOf("deny") >= 0) {
        return {
          device: String(h.deviceName || h.device || ""),
          interface: String(h.outIntf || h.egressInterface || ""),
          rule: String(h.ruleName || h.rule || ""),
          reason: String(h.disposition || "Denied"),
          category: "security",
        };
      }
      if (h.note && String(h.note).toLowerCase().indexOf("acl") >= 0) {
        return {
          device: String(h.deviceName || h.device || ""),
          interface: String(h.outIntf || h.egressInterface || ""),
          rule: String(h.ruleName || h.rule || ""),
          reason: String(h.note || "Blocked"),
          category: "security",
        };
      }
    }
    return null;
  },

  _excerpt: function (raw) {
    try {
      var s = JSON.stringify(raw);
      if (s.length > 3500) return s.substring(0, 3500) + "...";
      return s;
    } catch (e) {
      return "";
    }
  },

  type: "PathNormalizer",
};

