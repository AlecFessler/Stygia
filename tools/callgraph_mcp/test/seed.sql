-- Hand-INSERT test fixture for callgraph_mcp until the real indexer ships.
-- Apply with:
--   sqlite3 /tmp/callgraph.db < tools/indexer/schema.sql
--   sqlite3 /tmp/callgraph.db < tools/callgraph_mcp/test/seed.sql

BEGIN;

-- Build metadata. `schema_complete=true` is the open-gate sentinel.
INSERT INTO meta(key,value) VALUES
  ('arch','x86_64'),
  ('commit_sha','abcdef1234567890'),
  ('built_at','2026-04-28T00:00:00Z'),
  ('schema_version','1'),
  ('total_entities','12'),
  ('total_edges','8'),
  ('schema_complete','true');

-- Files. file.source carries the full bytes; we make def_byte_start /
-- def_byte_end below address into these strings.
--                       0123456789012345678901234567890
INSERT INTO file(id,path,sha256,size,source) VALUES
  (1,'kernel/proc/process.zig', x'00', 60,
   'pub fn start() void { setup(); run(); }' || char(10) || 'pub fn run() void { tick(); }' || char(10)),
  (2,'kernel/sched/scheduler.zig', x'00', 70,
   'pub fn tick() void { if (cond) { yield(); } }' || char(10) || 'pub fn yield() void { hlt(); }' || char(10)),
  (3,'kernel/arch/x64/cpu.zig', x'00', 30,
   'pub fn hlt() void { asm volatile ("hlt"); }' || char(10));

-- Modules.
INSERT INTO module(id,qualified_name,root_file_id) VALUES
  (1,'proc',1),
  (2,'sched',2),
  (3,'arch.x64',3);

-- Entities. byte ranges below were measured against the file source
-- strings above (sqlite is 1-indexed for substr but the schema's
-- def_byte_start is 0-indexed — the formula is substr(source, start+1, end-start)).
-- proc.process.start: 'pub fn start() void { setup(); run(); }' → bytes 0..39
-- proc.process.run:   'pub fn run() void { tick(); }'           → bytes 40..69
-- sched.scheduler.tick: 'pub fn tick() void { if (cond) { yield(); } }'  → bytes 0..45
-- sched.scheduler.yield: 'pub fn yield() void { hlt(); }'                → bytes 46..76
-- arch.x64.cpu.hlt:    'pub fn hlt() void { asm volatile ("hlt"); }'    → bytes 0..43
INSERT INTO entity(id,kind,qualified_name,module_id,def_file_id,
                   def_byte_start,def_byte_end,def_line,def_col,
                   generic_parent_id,is_ast_only,is_slab_backed) VALUES
  (1,'fn','proc.process.start',         1,1, 0,39, 1, 1, NULL,0,0),
  (2,'fn','proc.process.run',           1,1,40,69, 2, 1, NULL,0,0),
  (3,'fn','sched.scheduler.tick',       2,2, 0,45, 1, 1, NULL,0,0),
  (4,'fn','sched.scheduler.yield',      2,2,46,76, 2, 1, NULL,0,0),
  (5,'fn','arch.x64.cpu.hlt',           3,3, 0,43, 1, 1, NULL,0,0),
  (6,'fn','proc.process.setup',         1,1, 0,39, 1, 1, NULL,1,0),  -- ast-only / inlined
  (7,'type','proc.process.Process',     1,1, 0,39, 1, 1, NULL,0,1),  -- slab-backed
  (8,'fn','sched.SlabRef.lock<Port>',   2,2, 0,45, 1, 1, 9, 0,0),    -- generic instantiation
  (9,'fn','sched.SlabRef.lock',         2,2, 0,45, 1, 1, NULL,0,0),  -- generic parent
  (10,'fn','sched.SlabRef.lock<EC>',    2,2, 0,45, 1, 1, 9, 0,0),    -- generic instantiation
  (11,'fn','debug.assert',              2,2, 0,45, 1, 1, NULL,0,0),
  (12,'fn','std.mem.eql',               2,2, 0,45, 1, 1, NULL,0,0);

-- AST nodes — only enough for the trace tool to walk a parent chain.
-- For each call site, give it a parent if/while/etc.
--   ast 100 = block (root of fn body)
--   ast 101 = if inside tick
--   ast 102 = call expr `setup()` inside start
--   ast 103 = call expr `run()` inside start
--   ast 104 = call expr `tick()` inside run
--   ast 105 = call expr `yield()` inside the if-body of tick
--   ast 106 = call expr `hlt()` inside yield
INSERT INTO ast_node(id,file_id,parent_id,kind,byte_start,byte_end,entity_id) VALUES
  (100,1,NULL,'fn_decl',0,39,1),
  (101,2,NULL,'if',21,44,NULL),
  (102,1,100,'call_expr',22,29,NULL),
  (103,1,100,'call_expr',31,36,NULL),
  (104,1,NULL,'call_expr',60,66,NULL),
  (105,2,101,'call_expr',32,40,NULL),
  (106,3,NULL,'call_expr',20,38,NULL);

INSERT INTO ast_edge(parent_id,child_id,role) VALUES
  (100,102,'body'),
  (100,103,'body'),
  (101,105,'then');

-- IR call graph.
--   start → setup (direct)
--   start → run   (direct)
--   run   → tick  (direct)
--   tick  → yield (direct, inside an `if`)
--   yield → hlt   (direct)
--   yield → debug.assert (direct, hidden by hide_assertions)
--   start → std.mem.eql (direct, hidden by hide_library)
--   start → <indirect>  (call_kind=indirect, callee NULL)
--   SlabRef.lock<Port> → SlabRef.lock<EC>  (cross-instantiation, exercises generic_parent_id)
INSERT INTO ir_call(id,caller_entity_id,callee_entity_id,call_kind,resolved_via,confidence,ast_node_id,site_line) VALUES
  (1, 1, 6, 'direct', NULL, NULL, 102, 1),
  (2, 1, 2, 'direct', NULL, NULL, 103, 1),
  (3, 2, 3, 'direct', NULL, NULL, 104, 2),
  (4, 3, 4, 'direct', NULL, NULL, 105, 1),
  (5, 4, 5, 'direct', NULL, NULL, 106, 2),
  (6, 4, 11,'direct', NULL, NULL, NULL, 2),
  (7, 1, 12,'direct', NULL, NULL, NULL, 1),
  (8, 1, NULL,'indirect','ast_fnptr', 60, NULL, 1),
  (9, 8, 10,'direct', NULL, NULL, NULL, 1);

-- Entry points: start is a syscall, hlt is a leaf-ish trap, scheduler.tick is a timer.
INSERT INTO entry_point(entity_id,kind,vector,syscall_nr,label) VALUES
  (1,'syscall', NULL, 7, 'sys_start'),
  (5,'trap',     14, NULL, 'page_fault_stub'),
  (3,'timer',    32, NULL, 'tick_timer');

-- Type system: Process is a struct with two fields.
INSERT INTO type(id,entity_id,kind,size,align) VALUES (1,7,'struct',64,8);
INSERT INTO type_field(type_id,idx,name,offset,type_ref) VALUES
  (1,0,'pid',0,NULL),
  (1,1,'state',8,NULL);

-- Const alias chain: pretend `proc.process.run` is also exposed as `proc.api.run`.
-- (Use entity 2's id for both endpoints just to exercise the recursive CTE.)
INSERT INTO const_alias(entity_id,target_entity_id) VALUES (2,1);

-- Binary section. Two functions get bin_symbols; bin_inst spans them.
-- start: addr 0x1000 size 0x10
-- run:   addr 0x1010 size 0x08
-- yield: addr 0x1018 size 0x08
INSERT INTO bin_symbol(addr,entity_id,size,section) VALUES
  (4096, 1, 16, '.text'),
  (4112, 2,  8, '.text'),
  (4120, 4,  8, '.text');

INSERT INTO bin_inst(addr,bytes,mnemonic,operands) VALUES
  (4096, x'4889E5', 'mov',  'rbp, rsp'),
  (4099, x'E80C00', 'call', 'proc.process.run'),
  (4104, x'4889C7', 'mov',  'rdi, rax'),
  (4107, x'C3',     'ret',  ''),
  (4112, x'B801',   'mov',  'eax, 1'),
  (4115, x'C3',     'ret',  ''),
  (4120, x'F4',     'hlt',  ''),
  (4121, x'C3',     'ret',  '');

INSERT INTO dwarf_line(addr_lo,addr_hi,file_id,line,col) VALUES
  (4096,4103, 1, 1, 1),
  (4104,4111, 1, 1, 22),
  (4112,4119, 1, 2, 1),
  (4120,4127, 2, 2, 22);

-- Rebuild FTS index over qualified_name.
INSERT INTO entity_fts(entity_fts) VALUES('rebuild');

COMMIT;
