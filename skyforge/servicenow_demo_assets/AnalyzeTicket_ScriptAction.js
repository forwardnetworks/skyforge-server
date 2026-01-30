(function execute(/*GlideRecord*/ current, /*GlideRecord*/ event, /*string*/ parm1, /*string*/ parm2) {
  try {
    var ticketSysId = String(parm1 || "");
    if (!ticketSysId) return;
    new TicketAnalysis().analyzeTicketBySysId(ticketSysId);
  } catch (e) {
    gs.error("AnalyzeTicket failed: " + (e && e.message ? e.message : e));
  }
})(current, event, parm1, parm2);

