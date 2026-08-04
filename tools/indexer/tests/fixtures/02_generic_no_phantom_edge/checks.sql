-- `mod.caller` makes two calls: one to a suffix-decorated local fn (must
-- resolve, tagged ir_mono_suffix) and one to an unknown std generic (must
-- stay unresolved rather than invent an edge to `mod.append`).
SELECT 'callee ' || COALESCE(ce.qualified_name, '<unresolved>') ||
       ' via=' || COALESCE(ic.resolved_via, 'exact')
  FROM ir_call ic
  JOIN entity ca ON ca.id = ic.caller_entity_id
  LEFT JOIN entity ce ON ce.id = ic.callee_entity_id
 WHERE ca.qualified_name = 'mod.caller'
 ORDER BY 1;

-- No edge may exist from `mod.caller` straight into `mod.append`.
SELECT 'phantom_edges=' || COUNT(*)
  FROM ir_call ic
  JOIN entity ca ON ca.id = ic.caller_entity_id
  JOIN entity ce ON ce.id = ic.callee_entity_id
 WHERE ca.qualified_name = 'mod.caller' AND ce.qualified_name = 'mod.append';
