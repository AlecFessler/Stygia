-- Gap 1: a call whose LLVM callee is a quoted, monomorphized generic must
-- land in ir_call, resolved back to the generic *declaration* entity and
-- tagged with its demangling provenance.
SELECT 'edge ' || ca.qualified_name || ' -> ' || ce.qualified_name ||
       ' via=' || COALESCE(ic.resolved_via, 'exact')
  FROM ir_call ic
  JOIN entity ca ON ca.id = ic.caller_entity_id
  JOIN entity ce ON ce.id = ic.callee_entity_id
 WHERE ca.qualified_name = 'source.propagateAndWake'
 ORDER BY 1;

-- The generic's own body must be attributed to the declaration entity too,
-- otherwise the chain stops one hop later.
SELECT 'edge ' || ca.qualified_name || ' -> ' || ce.qualified_name ||
       ' via=' || COALESCE(ic.resolved_via, 'exact')
  FROM ir_call ic
  JOIN entity ca ON ca.id = ic.caller_entity_id
  JOIN entity ce ON ce.id = ic.callee_entity_id
 WHERE ca.qualified_name = 'slab.forEachAlive'
 ORDER BY 1;

-- Both monomorphizations collapse onto their declaration entity.
SELECT 'ir_fn ' || e.qualified_name || ' <= ' || f.ir_name
  FROM ir_fn f JOIN entity e ON e.id = f.entity_id
 WHERE e.qualified_name LIKE 'slab.%'
 ORDER BY 1;

-- End-to-end: the full chain is walkable through ir_call alone.
WITH RECURSIVE r(id, depth) AS (
    SELECT id, 0 FROM entity WHERE qualified_name = 'source.fire' AND kind = 'fn'
    UNION
    SELECT c.callee_entity_id, r.depth + 1
      FROM ir_call c JOIN r ON c.caller_entity_id = r.id
     WHERE c.callee_entity_id IS NOT NULL
       AND c.call_kind IN ('direct', 'dispatch_x64', 'dispatch_aarch64')
       AND r.depth < 16
)
SELECT 'reach ' || e.qualified_name || ' @depth ' || MIN(r.depth)
  FROM r JOIN entity e ON e.id = r.id
 GROUP BY e.qualified_name
 ORDER BY MIN(r.depth), e.qualified_name;
