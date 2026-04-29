//! Static frontend assets, embedded at compile time. Lives in
//! tools/callgraph_http/src/assets/ directly (vendored at the cutover
//! when the legacy tools/callgraph/ in-memory daemon was removed).

pub const index_html = @embedFile("assets/index.html");
pub const app_js = @embedFile("assets/app.js");
pub const trace_js = @embedFile("assets/trace.js");
pub const cytoscape_js = @embedFile("assets/cytoscape.min.js");
