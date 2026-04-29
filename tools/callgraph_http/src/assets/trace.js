/* Zag callgraph explorer — Trace mode.
 *
 * Renders the same /api/graph data as Graph mode but as recursively-nested
 * boxes (Nassi-Shneiderman style, extended across function-call boundaries).
 *
 * Public interface (called from app.js):
 *   - traceMode.render(rootFnId)         — rebuild #trace_view from scratch
 *   - traceMode.show()                   — make trace UI visible, hide graph
 *   - traceMode.hide()                   — restore graph view
 *   - traceMode.onEntryChange(rootFnId)  — entry dropdown changed; clear stack
 *   - traceMode.setContext(ctx)          — wire shared helpers (fnById,
 *                                          isLibrary, showNodePanel)
 *
 * Drill stack:
 *   - Double-left-click on any nested box → push current root, re-root to
 *     clicked box's fn id.
 *   - Double-right-click anywhere in the trace view → pop stack.
 *   - Breadcrumb above the view shows the stack; click any crumb to jump.
 *   - Per-entry stack persisted in `entryStacks[entryId]` so toggling Graph
 *     ↔ Trace doesn't lose state for that entry.
 */

(function () {
  "use strict";

  // ------------------------------------------------------------------ shared context
  // app.js calls setContext at startup with these helpers; we keep them as
  // module-locals to avoid coupling the trace renderer to app.js's globals.
  let ctx = {
    fnById: null,           // Map<fnId, fn>
    isLibrary: function () { return false; },
    isDebug: function () { return false; },
    getHideLibrary: function () { return true; },
    getHideDebug: function () { return true; },
    getDepth: function () { return 4; },
    showNodePanel: null,    // open the right-hand info panel for a fn
    // Predicate, set by app.js when compare mode is active and ready.
    // Returns true for fns whose def_loc lives in a file that differs
    // between live and the secondary commit. The trace renderer adds a
    // `trace_diffhint` class so the user can spot drill-targets worth
    // clicking through to the source pane. Defaults to no-op.
    isChangedFn: function () { return false; },
    // Same shape as isChangedFn but returns true when the fn or any
    // descendant in its reachable subtree is changed. Used to mark
    // depth-capped leaves (and intermediate boxes) with a "drill to
    // find diff" stripe — without it, entries flagged in the dropdown
    // can have all their actual changes past the depth limit and the
    // trace view shows nothing highlighted.
    hasChangedDescendant: function () { return false; },
  };

  /** name-or-mangled -> Function record index, rebuilt every time
   *  setContext fires with a fresh fnById. Used for the name-fallback
   *  lookup when a call atom has `to: null` but the resolver gave it a
   *  qualified name (typical for fully-inlined helpers like
   *  `arch.dispatch.cpu.kEntry`). */
  let fnByName = new Map();

  function rebuildFnByName(fnById) {
    fnByName = new Map();
    if (!fnById) return;
    fnById.forEach(function (fn) {
      if (!fn) return;
      if (fn.name) fnByName.set(fn.name, fn);
      if (fn.mangled && !fnByName.has(fn.mangled)) fnByName.set(fn.mangled, fn);
    });
  }

  // ------------------------------------------------------------------ state

  /** entryFnId currently driving the trace view (top of breadcrumb). */
  let originEntryId = null;
  /** Drill stack for the *current* origin entry. Top of stack is current root. */
  let drillStack = [];
  /** Per-entry remembered drill stack so Graph<->Trace flips preserve state. */
  const entryStacks = new Map();

  /** rootId of the most recent successful render. Used to short-circuit
   *  redundant re-renders (e.g. toggling Graph↔Trace without changing the
   *  entry — the existing trace DOM is still valid). Cleared by
   *  `invalidate()` whenever the cached tree is no longer correct
   *  (graph data swap, filter toggle, drill change). */
  let lastRenderedRootId = null;
  /** Depth used in the cached render. Cache is only valid if the current
   *  depth slider matches; bumping the slider must rebuild. */
  let lastRenderedDepth = -1;

  /** Right-click double-click bookkeeping for popping the drill stack. */
  let lastRightClick = 0;
  const RIGHT_DBLCLICK_MS = 400;

  // ------------------------------------------------------------------ DOM

  const els = {
    view: null,           // #trace_view (scrollable container)
    breadcrumb: null,     // #trace_breadcrumb
  };

  function ensureDom() {
    if (els.view) return;
    els.view = document.getElementById("trace_view");
    els.breadcrumb = document.getElementById("trace_breadcrumb");
    els.wrap = document.getElementById("trace_view_wrap");
    if (!els.view) return;

    // Right-click anywhere in the trace view: count as a "back" gesture if
    // the previous right-click was within RIGHT_DBLCLICK_MS. Always suppress
    // the browser context menu in the trace area.
    els.view.addEventListener("contextmenu", function (e) {
      e.preventDefault();
      const now = Date.now();
      if (now - lastRightClick < RIGHT_DBLCLICK_MS) {
        lastRightClick = 0;
        popDrill();
      } else {
        lastRightClick = now;
      }
    });

    // Double-left-click on a box → drill in. Use event delegation; the
    // closest `.trace_box[data-fnid]` to the event target wins.
    els.view.addEventListener("dblclick", function (e) {
      const box = e.target.closest && e.target.closest(".trace_box[data-fnid]");
      if (!box) return;
      const fnId = parseInt(box.getAttribute("data-fnid"), 10);
      if (Number.isNaN(fnId)) return;
      // Don't drill into the current root (it's the outermost box).
      if (drillStack.length > 0 && drillStack[drillStack.length - 1] === fnId) return;
      e.preventDefault();
      e.stopPropagation();
      pushDrill(fnId);
    });
  }

  // ------------------------------------------------------------------ helpers

  function fmtLoc(loc) {
    if (!loc || !loc.file) return "";
    const file = loc.file;
    const line = loc.line != null ? loc.line : 0;
    return shortenFile(file) + ":" + line;
  }

  function fullLoc(loc) {
    if (!loc || !loc.file) return "";
    const line = loc.line != null ? loc.line : 0;
    return loc.file + ":" + line;
  }

  /** Strip the kernel-root prefix from a path so it displays as
   *  `proc/process.zig:705` rather than `/home/alec/Zag/kernel/proc/...`.
   *
   *  Heuristic: find the LAST `/kernel/` substring and strip everything up
   *  to and including it. Works for absolute paths originating in the Zag
   *  worktree as well as relative paths that already start with `kernel/`.
   *  Limitation: a source path with `/kernel/` baked in further down (e.g.
   *  some forwarded shim file) would be over-stripped, but in practice the
   *  callgraph IR never produces such paths.
   *
   *  Falls back to `/usr/lib/zig/` stripping for stdlib paths, then to the
   *  raw input. */
  function shortenFile(file) {
    if (!file) return "";
    const k = file.lastIndexOf("/kernel/");
    if (k >= 0) return file.slice(k + 1);
    if (file.startsWith("kernel/")) return file.slice("kernel/".length);
    const z = file.indexOf("/usr/lib/zig/");
    if (z >= 0) return file.slice(z + 1);
    return file;
  }

  function shortName(name) {
    if (!name) return "(anon)";
    const parts = name.split(".");
    if (parts.length <= 2) return name;
    return parts.slice(-2).join(".");
  }

  // ------------------------------------------------------------------ public api

  /** Optional callback fired after every successful primary render
   *  (including cache hits). Receives { rootId, rootName }. Used by the
   *  compare feature to mirror the primary's selection in the secondary
   *  pane without polling. */
  let onRenderedCallback = null;

  function setOnRendered(cb) {
    onRenderedCallback = (typeof cb === "function") ? cb : null;
  }

  function fireOnRendered(rootId) {
    if (!onRenderedCallback) return;
    const fn = (rootId != null && ctx.fnById) ? ctx.fnById.get(rootId) : null;
    onRenderedCallback({
      rootId: rootId,
      rootName: fn ? fn.name : null,
    });
  }

  function setContext(c) {
    if (c.fnById) {
      ctx.fnById = c.fnById;
      rebuildFnByName(c.fnById);
      // fnById changed (graph swap / arch flip): the cached tree references
      // the prior fnById, so invalidate even if the entry id happens to
      // collide.
      lastRenderedRootId = null;
    }
    if (c.isLibrary) ctx.isLibrary = c.isLibrary;
    if (c.isDebug) ctx.isDebug = c.isDebug;
    if (c.getHideLibrary) ctx.getHideLibrary = c.getHideLibrary;
    if (c.getHideDebug) ctx.getHideDebug = c.getHideDebug;
    if (c.getDepth) ctx.getDepth = c.getDepth;
    if (c.showNodePanel) ctx.showNodePanel = c.showNodePanel;
    if (c.isChangedFn) {
      ctx.isChangedFn = c.isChangedFn;
      // Predicate change invalidates the cached tree (the diff-hint
      // classes baked into the prior DOM no longer reflect reality).
      lastRenderedRootId = null;
    }
    if (c.hasChangedDescendant) {
      ctx.hasChangedDescendant = c.hasChangedDescendant;
      lastRenderedRootId = null;
    }
  }

  /** Called by app.js when the entry dropdown changes. Clears the drill
   *  stack for the new entry (or restores a remembered one). */
  function onEntryChange(rootFnId) {
    originEntryId = rootFnId;
    if (entryStacks.has(rootFnId)) {
      drillStack = entryStacks.get(rootFnId).slice();
    } else {
      drillStack = [rootFnId];
      entryStacks.set(rootFnId, drillStack.slice());
    }
    render();
  }

  function show() {
    ensureDom();
    // The wrap is a flex row that holds primary (left) + optional secondary
    // (right). Toggling the wrap, not just #trace_view, lets the secondary
    // pane participate in flex-basis when compare mode adds it.
    if (els.wrap) els.wrap.style.display = "";
    if (els.view) els.view.style.display = "";
    if (els.breadcrumb) els.breadcrumb.style.display = "";
  }

  function hide() {
    ensureDom();
    if (els.wrap) els.wrap.style.display = "none";
    if (els.view) els.view.style.display = "none";
    if (els.breadcrumb) els.breadcrumb.style.display = "none";
  }

  // ------------------------------------------------------------------ drill stack

  function pushDrill(fnId) {
    drillStack.push(fnId);
    if (originEntryId != null) entryStacks.set(originEntryId, drillStack.slice());
    render();
  }

  /** Drill into a fn identified by qualified name. Used by the secondary
   *  pane: a dblclick over there gives us a fn from the secondary graph,
   *  and we mirror by asking the primary to push a drill onto whichever
   *  primary fn shares that name. Returns true if the primary had a
   *  matching fn (and thus drilled), false otherwise — caller decides
   *  what to do for absent-on-primary fns (typically: ignore, since the
   *  primary couldn't show that fn's body anyway). */
  function pushDrillByName(name) {
    if (!name || !fnByName) return false;
    const fn = fnByName.get(name);
    if (!fn || fn.id == null) return false;
    pushDrill(fn.id);
    return true;
  }

  function popDrill() {
    if (drillStack.length <= 1) {
      // Flash the breadcrumb so the user knows the gesture registered.
      if (els.breadcrumb) {
        els.breadcrumb.classList.add("flash");
        setTimeout(function () {
          if (els.breadcrumb) els.breadcrumb.classList.remove("flash");
        }, 250);
      }
      return;
    }
    drillStack.pop();
    if (originEntryId != null) entryStacks.set(originEntryId, drillStack.slice());
    render();
  }

  function jumpTo(level) {
    // Pop until drillStack.length === level + 1.
    if (level < 0 || level >= drillStack.length) return;
    drillStack = drillStack.slice(0, level + 1);
    if (originEntryId != null) entryStacks.set(originEntryId, drillStack.slice());
    render();
  }

  // ------------------------------------------------------------------ render

  function render(rootFnIdOverride) {
    ensureDom();
    if (!els.view || !ctx.fnById) return;

    if (rootFnIdOverride != null) {
      // External re-render (re-show, no drill change).
      // (Currently unused — onEntryChange/pushDrill already drive render().)
    }

    const rootId = drillStack.length > 0
      ? drillStack[drillStack.length - 1]
      : originEntryId;

    // Cache hit: same root rendered last time at the same depth, and the
    // view still has content. Skip the rebuild — toggling Graph↔Trace on
    // an unchanged entry would otherwise pay the full layout+paint cost
    // (≈700ms on big trees like kEntry) for no visual change.
    const curDepth = Math.max(1, ctx.getDepth() | 0);
    if (rootId != null && rootId === lastRenderedRootId
        && curDepth === lastRenderedDepth
        && els.view.firstChild) {
      if (typeof window.__cgSignalReady === "function") window.__cgSignalReady();
      fireOnRendered(rootId);
      return;
    }

    renderBreadcrumb();

    els.view.innerHTML = "";
    if (rootId == null) {
      const empty = document.createElement("div");
      empty.className = "trace_empty";
      empty.textContent = "(no entry selected)";
      els.view.appendChild(empty);
      lastRenderedRootId = null;
      if (typeof window.__cgSignalReady === "function") window.__cgSignalReady();
      return;
    }

    const fn = ctx.fnById.get(rootId);
    if (!fn) {
      const empty = document.createElement("div");
      empty.className = "trace_empty";
      empty.textContent = "(function not in graph)";
      els.view.appendChild(empty);
      lastRenderedRootId = null;
      if (typeof window.__cgSignalReady === "function") window.__cgSignalReady();
      return;
    }

    // Build the in-memory subtree first, then attach in one shot. Cap
    // recursion at the depth slider so we don't synthesize 10k+ DOM nodes
    // for a kernel-wide entry (kEntry was 17,370 boxes uncapped — multi-
    // second hang on first paint). Beyond the cap a leaf with the qualified
    // name renders in place; the user double-clicks to drill in via the
    // existing pushDrill mechanism.
    //
    // Recursion guard: visited keys are node-identity strings (`id:N` for
    // fns we expanded by id, `name:foo` for fns we expanded by name
    // fallback). The string-keyed approach keeps name-resolved-but-id-null
    // call atoms protected from infinite recursion the same way id-based
    // expansion is.
    const maxDepth = Math.max(1, ctx.getDepth() | 0);
    const rootKey = nodeKeyFor(fn);
    const visited = new Set([rootKey]);
    const primaryTctx = {
      fnById: ctx.fnById,
      fnByName: fnByName,
      isLibrary: ctx.isLibrary,
      isDebug: ctx.isDebug,
      getHideLibrary: ctx.getHideLibrary,
      getHideDebug: ctx.getHideDebug,
      showNodePanel: ctx.showNodePanel,
      isChangedFn: ctx.isChangedFn,
      hasChangedDescendant: ctx.hasChangedDescendant,
    };
    const tree = buildFnBox(fn, visited, 0, maxDepth, primaryTctx);
    visited.delete(rootKey);

    els.view.appendChild(tree);
    lastRenderedRootId = rootId;
    lastRenderedDepth = maxDepth;

    // Perf-harness ready signal (see app.js for the contract). Inert when
    // no harness is watching.
    if (typeof window.__cgSignalReady === "function") window.__cgSignalReady();
    fireOnRendered(rootId);
  }

  /** Mark the cached render as stale. Callers (filter changes, graph
   *  swap, etc.) should call this before requesting a fresh render. */
  function invalidate() {
    lastRenderedRootId = null;
  }

  /** Build the recursion-guard key for a Function record. Prefer `id` when
   *  the IR knows the function; fall back to qualified name (so
   *  name-resolved fns with `id == null` still get protected). */
  function nodeKeyFor(fn) {
    if (!fn) return "name:?";
    if (fn.id != null) return "id:" + fn.id;
    if (fn.name) return "name:" + fn.name;
    return "name:?";
  }

  function renderBreadcrumb() {
    if (!els.breadcrumb) return;
    els.breadcrumb.innerHTML = "";
    if (drillStack.length === 0) return;

    for (let i = 0; i < drillStack.length; i += 1) {
      const id = drillStack[i];
      const fn = ctx.fnById ? ctx.fnById.get(id) : null;
      const crumb = document.createElement("span");
      crumb.className = "crumb";
      if (i === drillStack.length - 1) crumb.classList.add("current");
      crumb.textContent = fn ? shortName(fn.name) : ("#" + id);
      crumb.title = fn ? fn.name : ("fn id " + id);
      const idx = i;
      crumb.addEventListener("click", function () { jumpTo(idx); });
      els.breadcrumb.appendChild(crumb);
      if (i < drillStack.length - 1) {
        const sep = document.createElement("span");
        sep.className = "crumb_sep";
        sep.textContent = " ▸ ";
        els.breadcrumb.appendChild(sep);
      }
    }
  }

  // ------------------------------------------------------------------ tree builders

  /** Build the outermost-or-inner box for a fully-known function.
   *  `level` is the call depth from the rendered root (root=0). `maxDepth`
   *  caps recursion: when a child call would push past it, we render a
   *  drillable leaf instead of expanding the callee body. */
  function buildFnBox(fn, visited, level, maxDepth, tctx) {
    const box = document.createElement("div");
    box.className = "trace_box trace_fn";
    box.setAttribute("data-fnid", String(fn.id));
    if (fn.is_entry) box.classList.add("entry");
    if (fn.is_ast_only) box.classList.add("ast_only");
    // Diff-mode hint: two levels of flagging.
    //   trace_diffhint_direct  — this fn was changed (◆ glyph + bright stripe)
    //   trace_diffhint_subtree — this fn or any descendant changed (faint stripe,
    //                             tells the user "drill in here to find the diff")
    // Inert when compare is off (predicates default to false).
    if (tctx.isChangedFn && tctx.isChangedFn(fn)) {
      box.classList.add("trace_diffhint", "trace_diffhint_direct");
    } else if (tctx.hasChangedDescendant && tctx.hasChangedDescendant(fn)) {
      box.classList.add("trace_diffhint", "trace_diffhint_subtree");
    }

    box.appendChild(buildHeader(shortName(fn.name), fn.def_loc, {
      fullName: fn.name,
      // AST-only fns have no IR `define` because the compiler inlined every
      // call site. The body shown here is reconstructed from the source AST,
      // so we mark the header with a small "↪ inlined" badge so the user
      // knows they're looking at a synthesized record.
      badge: fn.is_ast_only ? "↪ inlined" : null,
      onClick: function () {
        if (tctx.showNodePanel) {
          tctx.showNodePanel({
            id: "n" + fn.id,
            fullName: fn.name,
            label: fn.name,
            mangled: fn.mangled,
            file: fn.def_loc ? fn.def_loc.file : "",
            line: fn.def_loc ? fn.def_loc.line : 0,
            col: fn.def_loc ? fn.def_loc.col : 0,
            isEntry: !!fn.is_entry,
            entryKind: fn.entry_kind || "",
            kind: "fn",
          });
        }
      },
    }));

    const body = document.createElement("div");
    body.className = "trace_body";

    const intra = fn.intra || [];
    if (intra.length === 0) {
      const e = document.createElement("div");
      e.className = "trace_empty";
      e.textContent = "(no calls)";
      body.appendChild(e);
    } else {
      for (const atom of intra) {
        body.appendChild(buildAtom(atom, visited, level, maxDepth, tctx));
      }
    }
    box.appendChild(body);
    return box;
  }

  function buildHeader(title, loc, opts) {
    opts = opts || {};
    const h = document.createElement("div");
    h.className = "trace_header";

    const name = document.createElement("span");
    name.className = "trace_title";
    name.textContent = title;
    if (opts.fullName) name.title = opts.fullName;
    if (opts.onClick) {
      name.classList.add("clickable");
      name.addEventListener("click", function (e) {
        e.stopPropagation();
        opts.onClick();
      });
    }
    h.appendChild(name);

    if (opts.badge) {
      const badge = document.createElement("span");
      badge.className = "trace_badge";
      badge.textContent = opts.badge;
      badge.title = "Inlined by the compiler — body reconstructed from source AST";
      h.appendChild(badge);
    }

    if (loc) {
      const locSpan = document.createElement("span");
      locSpan.className = "trace_loc";
      locSpan.textContent = fmtLoc(loc);
      locSpan.title = fullLoc(loc);
      h.appendChild(locSpan);
    }
    return h;
  }

  /** Dispatch on atom shape: call / branch / loop. */
  function buildAtom(atom, visited, level, maxDepth, tctx) {
    if (atom.call) return buildCallBox(atom.call, visited, level, maxDepth, tctx);
    if (atom.branch) return buildBranchBox(atom.branch, visited, level, maxDepth, tctx);
    if (atom.loop) return buildLoopBox(atom.loop, visited, level, maxDepth, tctx);
    const u = document.createElement("div");
    u.className = "trace_box trace_unknown";
    u.textContent = "(unknown atom)";
    return u;
  }

  function buildCallBox(c, visited, level, maxDepth, tctx) {
    const kind = c.kind || "direct";

    // Resolve the target function via two lookups:
    //   1) `to` (id) — present when LLVM emitted a `define` for the callee.
    //   2) `name` / `mangled` — name-fallback for inlined helpers etc.
    //      The AST resolver attaches a qualified name to the call atom even
    //      when the IR has no separate function record (e.g. `inline fn`s
    //      get inlined into the caller). Without this fallback, trace mode
    //      dead-ends at boxes like `arch.dispatch.cpu.kEntry` even though
    //      we *do* have a function record under that name.
    //
    // Note: in the secondary (compare) pane, fn IDs are from a different
    // build, so we look up by name first when the secondary's tctx has its
    // own fnByName but no fnById match for the primary's id.
    let fn = null;
    if (c.to != null && tctx.fnById) fn = tctx.fnById.get(c.to) || null;
    if (!fn && c.name) fn = tctx.fnByName.get(c.name) || null;
    if (!fn && c.mangled) fn = tctx.fnByName.get(c.mangled) || null;

    // Apply the debug filter *before* the indirect render so that a debug
    // helper that happens to be reached indirectly still renders as a
    // closed debug leaf (and we don't traverse callees).
    if (fn && tctx.getHideDebug && tctx.getHideDebug() && tctx.isDebug && tctx.isDebug(fn)) {
      return makeLeafBox("↓ debug: " + shortName(fn.name), c.site, "trace_debug");
    }
    if (!fn && tctx.getHideDebug && tctx.getHideDebug() && tctx.isDebug && tctx.isDebug(c)) {
      return makeLeafBox("↓ debug: " + (c.name || "(debug)"), c.site, "trace_debug");
    }

    // Genuinely indirect: kind says so AND we have nothing resolved.
    if (!fn && kind === "indirect") {
      return makeLeafBox("? indirect: " + (c.name || "(unresolved)"), c.site, "trace_indirect");
    }

    // Direct/dispatch/vtable target whose IR record we don't have. The
    // most common case: a direct call to an `inline fn` that LLVM
    // dropped. Render the qualified name as a leaf with a dimmer border
    // (NOT red, NOT marked indirect — it's a known target).
    if (!fn) {
      if (kind === "direct" && c.name) {
        return makeLeafBox(c.name, c.site, "trace_inlined");
      }
      return makeLeafBox("? " + (c.name || "(unknown)"), c.site, "trace_unknown");
    }

    // Library leaf.
    if (tctx.isLibrary && tctx.isLibrary(fn) && tctx.getHideLibrary && tctx.getHideLibrary()) {
      return makeLeafBox("→ stdlib: " + shortName(fn.name), c.site, "trace_library");
    }

    // Recursion guard — fn already on the active call stack from this path.
    // Use a node-identity key (id-or-name) so name-fallback expansions are
    // protected the same way id-based expansions are.
    const key = nodeKeyFor(fn);
    if (visited.has(key)) {
      return makeLeafBox("↻ recursive: " + shortName(fn.name), c.site, "trace_recursive");
    }

    // Depth cap: render the callee as a drillable leaf instead of expanding
    // its body. Mirrors the graph mode's depth slider — keeps initial
    // render bounded so multi-thousand-fn entries (kEntry) don't lock up.
    // Double-clicking the leaf re-roots into it via the existing
    // pushDrill mechanism (the data-fnid attribute is what dblclick reads).
    if (level + 1 >= maxDepth) {
      const leaf = makeLeafBox("▸ " + shortName(fn.name), c.site, "trace_capped");
      leaf.setAttribute("data-fnid", String(fn.id));
      leaf.title = fn.name + " — double-click to drill in";
      // Color-code by edge kind so the user still sees dispatch/vtable info.
      leaf.classList.add("kind_" + kind);
      // Diff-mode hint also applies at depth-cap leaves, so the user
      // can see right at the cap that drilling further would land on
      // a changed fn (direct) or a fn whose subtree contains changes
      // (subtree).
      if (tctx.isChangedFn && tctx.isChangedFn(fn)) {
        leaf.classList.add("trace_diffhint", "trace_diffhint_direct");
      } else if (tctx.hasChangedDescendant && tctx.hasChangedDescendant(fn)) {
        leaf.classList.add("trace_diffhint", "trace_diffhint_subtree");
      }
      return leaf;
    }

    // Recurse into the callee.
    visited.add(key);
    const inner = buildFnBox(fn, visited, level + 1, maxDepth, tctx);
    visited.delete(key);

    // Color-code the box border by edge kind so the user sees how the
    // call resolved (direct / dispatch_x64 / vtable / ...).
    inner.classList.add("kind_" + kind);

    return inner;
  }

  function makeLeafBox(label, site, klass) {
    const box = document.createElement("div");
    box.className = "trace_box " + klass;

    const h = document.createElement("div");
    h.className = "trace_header";
    const name = document.createElement("span");
    name.className = "trace_title";
    name.textContent = label;
    name.title = label;
    h.appendChild(name);
    if (site && site.file) {
      const locSpan = document.createElement("span");
      locSpan.className = "trace_loc";
      locSpan.textContent = fmtLoc(site);
      locSpan.title = fullLoc(site);
      h.appendChild(locSpan);
    }
    box.appendChild(h);
    return box;
  }

  function buildBranchBox(b, visited, level, maxDepth, tctx) {
    const wrap = document.createElement("div");
    wrap.className = "trace_branch";

    const arms = b.arms || [];
    // Title row (kind + loc) above the columns.
    const head = document.createElement("div");
    head.className = "trace_branch_head";
    const kw = document.createElement("span");
    kw.className = "trace_branch_kw";
    kw.textContent = b.kind === "if_else" ? "if / else" : "switch";
    head.appendChild(kw);
    if (b.loc) {
      const locSpan = document.createElement("span");
      locSpan.className = "trace_loc";
      locSpan.textContent = fmtLoc(b.loc);
      locSpan.title = fullLoc(b.loc);
      head.appendChild(locSpan);
    }
    wrap.appendChild(head);

    // Columns flex horizontally with a fixed 280px min-width per arm and
    // overflow-x:auto on the parent (see CSS). This keeps each arm
    // readable even in 65-arm syscall switches, at the cost of a
    // horizontal scrollbar.
    const cols = document.createElement("div");
    cols.className = "trace_branch_cols";

    for (const arm of arms) {
      const col = document.createElement("div");
      col.className = "trace_arm";

      const lab = document.createElement("div");
      lab.className = "trace_arm_label";
      const labelText = arm.label || "(arm)";
      lab.textContent = labelText;
      lab.title = labelText;
      col.appendChild(lab);

      const armBody = document.createElement("div");
      armBody.className = "trace_arm_body";
      const seq = arm.seq || [];
      if (seq.length === 0) {
        const e = document.createElement("div");
        e.className = "trace_empty";
        e.textContent = "(no calls)";
        armBody.appendChild(e);
      } else {
        for (const a of seq) {
          armBody.appendChild(buildAtom(a, visited, level, maxDepth, tctx));
        }
      }
      col.appendChild(armBody);
      cols.appendChild(col);
    }
    wrap.appendChild(cols);
    return wrap;
  }

  function buildLoopBox(l, visited, level, maxDepth, tctx) {
    const box = document.createElement("div");
    box.className = "trace_box trace_loop";

    const h = document.createElement("div");
    h.className = "trace_header";
    const name = document.createElement("span");
    name.className = "trace_title";
    name.textContent = "↻ loop";
    h.appendChild(name);
    if (l.loc) {
      const locSpan = document.createElement("span");
      locSpan.className = "trace_loc";
      locSpan.textContent = "@ " + fmtLoc(l.loc);
      locSpan.title = fullLoc(l.loc);
      h.appendChild(locSpan);
    }
    box.appendChild(h);

    const body = document.createElement("div");
    body.className = "trace_body";
    const inner = l.body || [];
    if (inner.length === 0) {
      const e = document.createElement("div");
      e.className = "trace_empty";
      e.textContent = "(no calls)";
      body.appendChild(e);
    } else {
      for (const a of inner) {
        body.appendChild(buildAtom(a, visited, level, maxDepth, tctx));
      }
    }
    box.appendChild(body);
    return box;
  }

  /** Re-run the current render without disturbing the drill stack. Useful
   *  after a filter-toggle change (library/debug) where the user expects
   *  the same drilled-into view, just with newly-filtered leaves. */
  function rerender() {
    // Caller is asking for fresh output (filter changed); bypass the
    // same-root cache.
    lastRenderedRootId = null;
    render();
  }

  // ------------------------------------------------------------------ secondary

  /** Render a tree into an arbitrary container using a different graph.
   *  Used by the compare/diff feature: the right pane mirrors the primary's
   *  current root by name, but resolves it against a graph from a different
   *  commit. Read-only — drill clicks on the secondary do nothing; the user
   *  drives navigation from the primary.
   *
   *  opts: { view, fnById, fnByName, rootName, depth, helpers? }
   *    view       — DOM container to write into
   *    fnById     — Map<fnId, fn> for the secondary graph
   *    fnByName   — Map<name, fn> for the secondary graph (caller-supplied;
   *                 we don't recompute since the caller already has it)
   *    rootName   — qualified name of the function to root at; looked up in
   *                 fnByName. If not found, an "(absent in this commit)"
   *                 placeholder renders.
   *    depth      — render depth (mirrors primary's current depth slider)
   *    helpers    — { isLibrary, isDebug, getHideLibrary, getHideDebug } —
   *                 same predicates the primary uses; resused so filtering
   *                 stays consistent across panes. */
  function renderSecondary(opts) {
    if (!opts || !opts.view) return;
    opts.view.innerHTML = "";
    const fn = opts.rootName && opts.fnByName ? (opts.fnByName.get(opts.rootName) || null) : null;
    if (!fn) {
      const empty = document.createElement("div");
      empty.className = "trace_empty";
      empty.textContent = opts.rootName
        ? "(no `" + opts.rootName + "` in this commit)"
        : "(no entry selected)";
      opts.view.appendChild(empty);
      return;
    }
    const helpers = opts.helpers || {};
    const tctx = {
      fnById: opts.fnById || new Map(),
      fnByName: opts.fnByName || new Map(),
      isLibrary: helpers.isLibrary || function () { return false; },
      isDebug: helpers.isDebug || function () { return false; },
      getHideLibrary: helpers.getHideLibrary || function () { return true; },
      getHideDebug: helpers.getHideDebug || function () { return true; },
      // No node-panel hookup on the secondary: clicks on the right pane's
      // headers are inert. Source-pane interactions are driven from the
      // primary so both stay in sync.
      showNodePanel: null,
      isChangedFn: helpers.isChangedFn || function () { return false; },
      hasChangedDescendant: helpers.hasChangedDescendant || function () { return false; },
    };
    const maxDepth = Math.max(1, (opts.depth | 0) || 4);
    const rootKey = nodeKeyFor(fn);
    const visited = new Set([rootKey]);
    const tree = buildFnBox(fn, visited, 0, maxDepth, tctx);
    visited.delete(rootKey);
    opts.view.appendChild(tree);
  }

  /** Build a {name -> fn} map from a {id -> fn} map. Mirrors the
   *  module-private `rebuildFnByName` but exported so callers (e.g. the
   *  compare pane) can prebuild for their own graph data without poking
   *  module internals. */
  function buildFnByName(fnById) {
    const out = new Map();
    if (!fnById) return out;
    fnById.forEach(function (fn) {
      if (!fn) return;
      if (fn.name) out.set(fn.name, fn);
      if (fn.mangled && !out.has(fn.mangled)) out.set(fn.mangled, fn);
    });
    return out;
  }

  // ------------------------------------------------------------------ export
  window.traceMode = {
    setContext: setContext,
    onEntryChange: onEntryChange,
    show: show,
    hide: hide,
    render: render,
    rerender: rerender,
    invalidate: invalidate,
    renderSecondary: renderSecondary,
    buildFnByName: buildFnByName,
    setOnRendered: setOnRendered,
    pushDrillByName: pushDrillByName,
    popDrill: popDrill,
  };
})();
