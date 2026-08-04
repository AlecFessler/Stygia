-- Gap 2, aarch64 half: `&handler` bound as an inline-asm operand inside a
-- `callconv(.naked)` fn is the only static link from the exception vector
-- table to its Zig handlers.
SELECT ep.kind || '  ' || e.qualified_name
  FROM entry_point ep
  JOIN entity e ON e.id = ep.entity_id
 WHERE ep.kind IN ('irq', 'exception')
 ORDER BY ep.kind, e.qualified_name;

-- `&handler` taken in an ordinary function is a callback, not a vector.
SELECT 'non_naked_rooted=' || COUNT(*)
  FROM entry_point ep
  JOIN entity e ON e.id = ep.entity_id
 WHERE e.qualified_name = 'arch.aarch64.exceptions.notAVector';
