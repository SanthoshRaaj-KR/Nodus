// PLANTED FIXTURE -- not real malware. Stands in for the worm payload that
// persists outside node_modules and therefore survives `npm uninstall`.
// Marker string below is what the advisory's content_markers matches on.
const beacon = "npm-postinstall-beacon";
module.exports = { beacon };
