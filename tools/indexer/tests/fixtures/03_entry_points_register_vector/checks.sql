-- Gap 2: every `interrupts.registerVector(vec, handler, .kind)` handler must
-- be an entry_point, including the ones the legacy name list missed —
-- alias-qualified (`paging_mod.tlbShootdownHandler`), loop-registered
-- (`deviceIrqHandler`) and same-named-in-two-files (`pmiHandler`).
SELECT ep.kind || '  ' || e.qualified_name
  FROM entry_point ep
  JOIN entity e ON e.id = ep.entity_id
 WHERE ep.kind IN ('irq', 'exception')
 ORDER BY ep.kind, e.qualified_name;

-- A defined-but-never-registered handler must stay out.
SELECT 'unregistered_rooted=' || COUNT(*)
  FROM entry_point ep
  JOIN entity e ON e.id = ep.entity_id
 WHERE e.qualified_name = 'arch.x64.irq.neverRegistered';
