//! callgraph_http — SQL-backed HTTP server for the kernel callgraph index.
//!
//! Drop-in replacement for the in-memory `tools/callgraph/src/server.zig`:
//! same routes, same response shapes, same web UI assets. Reads from
//! `<arch>-<sha>.db` files emitted by the indexer (schema in
//! `tools/indexer/schema.sql`); the daemon discovers DBs by walking
//! `--db-dir` and refuses to open ones lacking `meta('schema_complete','true')`.
//!
//! Default port is 8081 so the legacy server (8080) can stay running while
//! the user A/Bs the two.

const std = @import("std");

const assets = @import("assets.zig");
const handlers = @import("handlers.zig");
const registry_mod = @import("registry.zig");
const util = @import("util.zig");

const respondBytes = util.respondBytes;
const Registry = registry_mod.Registry;

const Args = struct {
    db_dir: []const u8 = "./test/dbs",
    port: u16 = 8081,
    git_root: []const u8 = "../..",
};

fn parseArgs(allocator: std.mem.Allocator) !Args {
    var args = Args{};
    var it = try std.process.argsWithAllocator(allocator);
    defer it.deinit();
    _ = it.next();
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--db-dir")) {
            args.db_dir = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--port")) {
            const v = it.next() orelse return error.MissingValue;
            args.port = try std.fmt.parseInt(u16, v, 10);
        } else if (std.mem.eql(u8, arg, "--git-root")) {
            args.git_root = it.next() orelse return error.MissingValue;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            try printHelp();
            std.process.exit(0);
        } else {
            std.debug.print("unknown argument: {s}\n", .{arg});
            try printHelp();
            std.process.exit(1);
        }
    }
    return args;
}

fn printHelp() !void {
    std.debug.print(
        \\callgraph_http — SQL-backed callgraph daemon
        \\
        \\Usage: callgraph_http [options]
        \\
        \\  --db-dir PATH    Directory to scan for <arch>-<sha>.db files
        \\                   (default: ./test/dbs)
        \\  --port PORT      HTTP port (default: 8081)
        \\  --git-root PATH  Repo root for git plumbing endpoints
        \\                   (default: ../..)
        \\  --help           Show this help
        \\
    , .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const args = try parseArgs(allocator);

    var registry = Registry.init(allocator);
    defer registry.deinit();
    registry.discover(args.db_dir) catch |err| {
        std.debug.print("registry: discover failed: {s}\n", .{@errorName(err)});
    };
    if (registry.commits.count() == 0) {
        std.debug.print(
            "warning: no DBs in {s}; endpoints will return 404 until a DB is added\n",
            .{args.db_dir},
        );
    } else {
        std.debug.print(
            "loaded {d} commit DB(s); default sha = {s}\n",
            .{ registry.commits.count(), registry.default_sha },
        );
    }

    const addr = try std.net.Address.parseIp("127.0.0.1", args.port);
    var net_server = try addr.listen(.{ .reuse_address = true });
    defer net_server.deinit();
    std.debug.print("callgraph_http listening on http://127.0.0.1:{d}\n", .{args.port});

    var recv_buffer: [16 * 1024]u8 = undefined;
    var send_buffer: [16 * 1024]u8 = undefined;
    while (true) {
        const conn = net_server.accept() catch |err| {
            std.debug.print("accept failed: {s}\n", .{@errorName(err)});
            continue;
        };
        defer conn.stream.close();

        var conn_reader = conn.stream.reader(&recv_buffer);
        var conn_writer = conn.stream.writer(&send_buffer);
        var http_server = std.http.Server.init(conn_reader.interface(), &conn_writer.interface);

        var request = http_server.receiveHead() catch |err| {
            std.debug.print("receiveHead failed: {s}\n", .{@errorName(err)});
            continue;
        };
        handleRequest(allocator, &request, &registry, args.git_root) catch |err| {
            std.debug.print("handler error: {s}\n", .{@errorName(err)});
        };
    }
}

fn handleRequest(
    allocator: std.mem.Allocator,
    request: *std.http.Server.Request,
    registry: *Registry,
    git_root: []const u8,
) !void {
    const target = request.head.target;
    const path_end = std.mem.indexOfScalar(u8, target, '?') orelse target.len;
    const path = target[0..path_end];
    const query = if (path_end < target.len) target[path_end + 1 ..] else "";

    // Static assets / index.
    if (std.mem.eql(u8, path, "/")) {
        return respondBytes(request, .ok, "text/html; charset=utf-8", assets.index_html);
    }
    if (std.mem.eql(u8, path, "/static/app.js")) {
        return respondBytes(request, .ok, "application/javascript; charset=utf-8", assets.app_js);
    }
    if (std.mem.eql(u8, path, "/static/trace.js")) {
        return respondBytes(request, .ok, "application/javascript; charset=utf-8", assets.trace_js);
    }
    if (std.mem.eql(u8, path, "/static/cytoscape.min.js")) {
        return respondBytes(request, .ok, "application/javascript; charset=utf-8", assets.cytoscape_js);
    }

    // SQL-backed endpoints.
    if (std.mem.eql(u8, path, "/api/arches")) return handlers.handleArches(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/graph")) return handlers.handleGraph(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/source")) return handlers.handleSource(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/find")) return handlers.handleFind(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/loc")) return handlers.handleLoc(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/fn_source")) return handlers.handleFnSource(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/callers")) return handlers.handleCallers(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/entries")) return handlers.handleEntries(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/reaches")) return handlers.handleReaches(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/modules")) return handlers.handleModules(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/type")) return handlers.handleType(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/trace")) return handlers.handleTrace(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/src_bin")) return handlers.handleSrcBin(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/src_bin_at")) return handlers.handleSrcBinAt(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/bin_addr2line")) return handlers.handleBinAddr2Line(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/bin_dataflow_reg")) return handlers.handleBinDataflowReg(allocator, request, query, registry);
    if (std.mem.eql(u8, path, "/api/findings")) return handlers.handleFindings(allocator, request, query, registry);

    // Git-plumbing endpoints — these shell out to `git -C <git_root>`
    // and don't read any DB. /api/load_commit is special: see the
    // comment on handleLoadCommit for why it's now a presence check
    // rather than a build orchestration call.
    if (std.mem.eql(u8, path, "/api/commits")) {
        return handlers.handleCommits(allocator, request, query, git_root);
    }
    if (std.mem.eql(u8, path, "/api/load_commit")) {
        return handlers.handleLoadCommit(allocator, request, query, registry);
    }
    if (std.mem.eql(u8, path, "/api/load_commit/status")) {
        return handlers.handleLoadCommitStatus(allocator, request, query, registry);
    }
    if (std.mem.eql(u8, path, "/api/diff")) {
        return handlers.handleDiff(allocator, request, query, git_root);
    }
    if (std.mem.eql(u8, path, "/api/diff_files")) {
        return handlers.handleDiffFiles(allocator, request, query, git_root);
    }
    if (std.mem.eql(u8, path, "/api/diff_hunks")) {
        return handlers.handleDiffHunks(allocator, request, query, git_root);
    }

    // /api/review/* — out of scope for this rearchitecture (per spec).
    if (std.mem.startsWith(u8, path, "/api/review/")) {
        return respondBytes(
            request,
            .not_implemented,
            "text/plain; charset=utf-8",
            "review endpoints are out of scope for callgraph_http\n",
        );
    }

    return respondBytes(request, .not_found, "text/plain; charset=utf-8", "not found\n");
}
