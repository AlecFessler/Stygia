//! Allocator-backed, node-based red–black tree.
//!
//! Stores elements of type `T` **by value**, ordered by a caller-provided strict
//! total-order comparator `(a: T, b: T) -> std.math.Order`. Duplicate handling is
//! configurable at compile time. The tree supports insertion, removal,
//! membership queries, predecessor/successor (neighbor) search, rotations, and
//! invariant validation.
//!
//! No recursion is used (`deinit` is iterative). The implementation preserves
//! all red–black invariants: the root is always black, red nodes never have red
//! children, all root-to-leaf paths contain the same number of black nodes,
//! and all keys satisfy BST ordering.
//!
//! # Directory
//!
//! ## Type Definitions
//! - `ContainerError` – error set for duplicate insertion / missing removal.
//! - `RedBlackTree` – factory that returns the specialized tree type.
//! - `RedBlackTree.Color` – node color enum (`Red` | `Black`).
//! - `RedBlackTree.Direction` – child side enum (`left` | `right`).
//! - `RedBlackTree.Node` – internal node storing one `T` and links.
//!
//! ## Constants
//! - None.
//!
//! ## Variables
//! - None.
//!
//! ## Functions
//! - `RedBlackTree` – returns the specialized tree `type`.
//! - `RedBlackTree.init` – create an empty tree.
//! - `RedBlackTree.deinit` – free all nodes iteratively.
//! - `RedBlackTree.contains` – membership test by comparator equality.
//! - `RedBlackTree.insert` – insert a value (duplicates policy configurable).
//! - `RedBlackTree.insertAtPtr` – internal insert at a specific parent/side.
//! - `RedBlackTree.insertFix` – restore invariants after insert.
//! - `RedBlackTree.remove` – remove by value and return it.
//! - `RedBlackTree.removeFromPtr` – remove a known node pointer.
//! - `RedBlackTree.removeFix` – restore invariants after delete.
//! - `RedBlackTree.rotate` – single rotation around a pivot.
//! - `RedBlackTree.findNeighbors` – predecessor/successor around a key.
//! - `RedBlackTree.validateRedBlackTree` – verify invariants on a subtree.
//! - `RedBlackTree.Node.create` – allocate a new red node.
//! - `RedBlackTree.Node.destroy` – free a node.
//! - `RedBlackTree.Node.getChild` – read a child pointer.
//! - `RedBlackTree.Node.setParentChildRelation` – set child and fix parent.
//! - `RedBlackTree.Node.getSibling` – sibling of a node.
//! - `RedBlackTree.Node.getUncle` – parent’s sibling.
//! - `RedBlackTree.Node.getGrandparent` – parent’s parent.

const std = @import("std");

/// Errors returned by container operations.
pub const ContainerError = error{
    /// Duplicate insert when duplicates are configured to be errors.
    Duplicate,
    /// Requested element was not found.
    NotFound,
};

/// Summary:
/// Produces a concrete red–black tree type specialized by element type `T`,
/// comparator `cmpFn`, and duplicate-handling policy.
///
/// Arguments:
/// - `T`: Element type stored by value.
/// - `cmpFn`: Comparator `(a: T, b: T) -> std.math.Order`.
/// - `duplicateIsError`: If `true`, equal keys cause `error.Duplicate`; if `false`,
///   equal keys are inserted into the left subtree.
///
/// Returns:
/// - The specialized red–black tree `type`.
///
/// Errors:
/// - None.
///
/// Panics:
/// - None.
pub fn RedBlackTree(
    comptime T: type,
    comptime cmpFn: fn (T, T) std.math.Order,
    comptime duplicateIsError: bool,
) type {
    return struct {
        const Self = @This();

        /// Allocator used for node storage.
        allocator: std.mem.Allocator,
        /// Root node pointer (null when empty).
        root: ?*Node,
        /// Number of elements in the tree.
        count: usize,

        /// Node color.
        pub const Color = enum {
            red,
            black,

            /// Summary:
            /// Returns the opposite color.
            ///
            /// Arguments:
            /// - `c`: Color to flip.
            ///
            /// Returns:
            /// - Opposite color.
            ///
            /// Errors:
            /// - None.
            ///
            /// Panics:
            /// - None.
            fn flip(c: Color) Color {
                return switch (c) {
                    Color.red => Color.black,
                    Color.black => Color.red,
                };
            }
        };

        /// Child side used by many helpers.
        pub const Direction = enum {
            left,
            right,

            /// Summary:
            /// Returns the opposite child side.
            ///
            /// Arguments:
            /// - `d`: Direction to flip.
            ///
            /// Returns:
            /// - Opposite direction.
            ///
            /// Errors:
            /// - None.
            ///
            /// Panics:
            /// - None.
            fn flip(d: Direction) Direction {
                return @enumFromInt(1 - @intFromEnum(d));
            }
        };

        /// Internal tree node holding one `T` value.
        pub const Node = struct {
            /// Red/black state.
            color: Color,
            /// Child pointers `[left, right]`.
            children: [2]?*Node,
            /// Parent pointer (null for root).
            parent: ?*Node,
            /// Stored element.
            data: T,

            /// Summary:
            /// Allocates and initializes a red node with `data`.
            ///
            /// Arguments:
            /// - `allocator`: Backing allocator for the node.
            /// - `data`: Element value to store.
            ///
            /// Returns:
            /// - Pointer to the newly created `Node`.
            ///
            /// Errors:
            /// - `std.mem.Allocator.Error` on allocation failure.
            ///
            /// Panics:
            /// - None.
            fn create(allocator: std.mem.Allocator, data: T) !*Node {
                const ptr = try allocator.create(Node);
                ptr.* = .{
                    .color = Color.red,
                    .children = .{ null, null },
                    .parent = null,
                    .data = data,
                };
                return ptr;
            }

            /// Summary:
            /// Destroys the node using `allocator`.
            ///
            /// Arguments:
            /// - `self`: Node to destroy.
            /// - `allocator`: Allocator that owns the node.
            ///
            /// Returns:
            /// - void.
            ///
            /// Errors:
            /// - None.
            ///
            /// Panics:
            /// - None.
            fn destroy(self: *Node, allocator: std.mem.Allocator) void {
                allocator.destroy(self);
            }

            /// Summary:
            /// Reads a child pointer by direction.
            ///
            /// Arguments:
            /// - `self`: Node to inspect.
            /// - `d`: Which child to return.
            ///
            /// Returns:
            /// - Child pointer (`?*Node`) for side `d`.
            ///
            /// Errors:
            /// - None.
            ///
            /// Panics:
            /// - None.
            pub fn getChild(self: *Node, d: Direction) ?*Node {
                return self.children[@intFromEnum(d)];
            }

            /// Summary:
            /// Sets parent↔child links atomically for `self` and `child`.
            ///
            /// Arguments:
            /// - `self`: Parent node whose child to set.
            /// - `child`: Child pointer (nullable).
            /// - `d`: Which side to set.
            ///
            /// Returns:
            /// - void.
            ///
            /// Errors:
            /// - None.
            ///
            /// Panics:
            /// - None.
            fn setParentChildRelation(self: *Node, child: ?*Node, d: Direction) void {
                self.children[@intFromEnum(d)] = child;
                if (child) |c| c.parent = self;
            }

            /// Summary:
            /// Returns the sibling node if any.
            ///
            /// Arguments:
            /// - `self`: Node whose sibling to fetch.
            ///
            /// Returns:
            /// - Sibling pointer or `null` if none.
            ///
            /// Errors:
            /// - None.
            ///
            /// Panics:
            /// - None.
            fn getSibling(self: *Node) ?*Node {
                if (self.parent) |p| {
                    std.debug.assert(p.getChild(.left) == self or p.getChild(.right) == self);
                    return if (self == p.getChild(Direction.left))
                        p.getChild(Direction.right)
                    else
                        p.getChild(Direction.left);
                }
                return null;
            }

            /// Summary:
            /// Returns the parent's sibling (uncle) if any.
            ///
            /// Arguments:
            /// - `self`: Node whose uncle to fetch.
            ///
            /// Returns:
            /// - Uncle pointer or `null` if none.
            ///
            /// Errors:
            /// - None.
            ///
            /// Panics:
            /// - None.
            fn getUncle(self: *Node) ?*Node {
                if (self.parent) |p| {
                    return p.getSibling();
                }
                return null;
            }

            /// Summary:
            /// Returns the grandparent if any.
            ///
            /// Arguments:
            /// - `self`: Node whose grandparent to fetch.
            ///
            /// Returns:
            /// - Grandparent pointer or `null` if none.
            ///
            /// Errors:
            /// - None.
            ///
            /// Panics:
            /// - None.
            fn getGrandparent(self: *Node) ?*Node {
                if (self.parent) |p| {
                    if (p.parent) |gp| {
                        std.debug.assert(gp.getChild(.left) == p or gp.getChild(.right) == p);
                        std.debug.assert(p.getChild(.left) == self or p.getChild(.right) == self);
                        return gp;
                    }
                }
                return null;
            }
        };

        /// Summary:
        /// Creates an empty tree using `allocator`.
        ///
        /// Arguments:
        /// - `allocator`: Backing allocator for node storage.
        ///
        /// Returns:
        /// - New empty `Self`.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        pub fn init(allocator: std.mem.Allocator) Self {
            return .{
                .allocator = allocator,
                .root = null,
                .count = 0,
            };
        }

        /// Summary:
        /// Frees all nodes and resets the tree to empty.
        ///
        /// Arguments:
        /// - `self`: Tree to deinitialize.
        ///
        /// Returns:
        /// - void.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        ///
        /// Notes:
        /// - Complexity O(n). Traverses and destroys nodes without recursion.
        pub fn deinit(self: *Self) void {
            var current = self.root;

            while (current) |c| {
                if (c.getChild(Direction.left)) |left| {
                    current = left;
                } else if (c.getChild(Direction.right)) |right| {
                    current = right;
                } else {
                    const parent = c.parent;

                    if (parent) |p| {
                        if (p.getChild(Direction.left) == c) {
                            p.setParentChildRelation(null, Direction.left);
                        } else {
                            p.setParentChildRelation(null, Direction.right);
                        }
                    }

                    c.destroy(self.allocator);
                    current = parent;
                }
            }

            self.root = null;
        }

        /// Summary:
        /// Returns true if an equal element exists.
        ///
        /// Arguments:
        /// - `self`: Tree to query.
        /// - `data`: Element to look up.
        ///
        /// Returns:
        /// - `true` if an equal key exists, else `false`.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        pub fn contains(self: *Self, data: T) bool {
            var current = self.root;

            while (current) |node| {
                switch (cmpFn(data, node.data)) {
                    .eq => return true,
                    .lt => {
                        current = node.getChild(Direction.left);
                        if (current) |c| @prefetch(c, .{});
                    },
                    .gt => {
                        current = node.getChild(Direction.right);
                        if (current) |c| @prefetch(c, .{});
                    },
                }
            }

            return false;
        }

        /// Summary:
        /// Inserts `data` according to `cmpFn`.
        ///
        /// Arguments:
        /// - `self`: Target tree.
        /// - `data`: Element to insert.
        ///
        /// Returns:
        /// - void.
        ///
        /// Errors:
        /// - `ContainerError.Duplicate` if equal key and `duplicateIsError = true`.
        /// - `std.mem.Allocator.Error` on allocation failure.
        ///
        /// Panics:
        /// - None.
        ///
        /// Notes:
        /// - If `duplicateIsError = false`, equal keys go to the left subtree.
        pub fn insert(self: *Self, data: T) !void {
            if (self.root == null) {
                _ = try self.insertAtPtr(null, Direction.left, data);
                return;
            }

            var current: ?*Node = self.root.?;
            var parent: ?*Node = null;
            var dir: Direction = Direction.left;

            while (current) |c| {
                parent = c;
                switch (cmpFn(data, c.data)) {
                    .lt => {
                        dir = Direction.left;
                        current = c.getChild(Direction.left);
                    },
                    .gt => {
                        dir = Direction.right;
                        current = c.getChild(Direction.right);
                    },
                    .eq => {
                        if (duplicateIsError) return ContainerError.Duplicate;
                        dir = Direction.left;
                        current = c.getChild(Direction.left);
                    },
                }
            }

            _ = try self.insertAtPtr(parent.?, dir, data);
        }

        /// Summary:
        /// Inserts a new node as `parent`’s `dir` child and rebalances if needed.
        ///
        /// Arguments:
        /// - `self`: Target tree.
        /// - `parent`: Parent under which to insert (null => becomes root).
        /// - `dir`: Side under parent to place the node.
        /// - `data`: Element to store in the node.
        ///
        /// Returns:
        /// - Pointer to the created node.
        ///
        /// Errors:
        /// - `std.mem.Allocator.Error` on allocation failure.
        ///
        /// Panics:
        /// - None.
        pub fn insertAtPtr(self: *Self, parent: ?*Node, dir: Direction, data: T) !*Node {
            const node = try Node.create(self.allocator, data);

            if (parent) |p| {
                std.debug.assert(p.getChild(dir) == null);

                node.color = Color.red;
                p.setParentChildRelation(node, dir);

                if (p.color == Color.red) {
                    self.insertFix(node);
                }
            } else {
                node.color = Color.black;
                self.root = node;
            }
            self.count += 1;
            return node;
        }

        /// Summary:
        /// Restores red-black invariants after insertion.
        ///
        /// Arguments:
        /// - `self`: Target tree.
        /// - `node`: Recently inserted node to fix up from.
        ///
        /// Returns:
        /// - void.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        fn insertFix(self: *Self, node: *Node) void {
            var current = node;
            while (current.parent) |p| {
                if (p.color == Color.black) break;

                var gp = current.getGrandparent() orelse break;
                const uncle = current.getUncle();
                const d = if (p == gp.getChild(Direction.left)) Direction.left else Direction.right;

                if (uncle) |u| {
                    if (u.color == Color.red) {
                        p.color = Color.black;
                        u.color = Color.black;
                        gp.color = Color.red;
                        current = gp;
                    } else {
                        if (current == p.getChild(d.flip())) {
                            self.rotate(p, d);
                            current = p;
                            current.parent.?.color = Color.black;
                        } else {
                            p.color = Color.black;
                        }
                        gp.color = Color.red;
                        self.rotate(gp, d.flip());
                        break;
                    }
                } else {
                    if (current == p.getChild(d.flip())) {
                        self.rotate(p, d);
                        current = p;
                        current.parent.?.color = Color.black;
                    } else {
                        p.color = Color.black;
                    }
                    gp.color = Color.red;
                    self.rotate(gp, d.flip());
                    break;
                }
            }

            self.root.?.color = Color.black;
        }

        /// Summary:
        /// Removes an element equal to `data` and returns the removed value.
        ///
        /// Arguments:
        /// - `self`: Target tree.
        /// - `data`: Element to remove (by equality under `cmpFn`).
        ///
        /// Returns:
        /// - The removed value of type `T`.
        ///
        /// Errors:
        /// - `ContainerError.NotFound` if no equal element exists.
        ///
        /// Panics:
        /// - None.
        pub fn remove(self: *Self, data: T) !T {
            var current: ?*Node = self.root orelse return ContainerError.NotFound;

            while (current) |c| {
                switch (cmpFn(data, c.data)) {
                    .lt => current = c.getChild(Direction.left),
                    .gt => current = c.getChild(Direction.right),
                    .eq => break,
                }
            }

            if (current == null) return ContainerError.NotFound;
            return self.removeFromPtr(current.?);
        }

        /// Summary:
        /// Removes the node at `target_node` and returns its value.
        ///
        /// Arguments:
        /// - `self`: Target tree.
        /// - `target_node`: Node to remove (obtained via prior search/traversal).
        ///
        /// Returns:
        /// - The removed value of type `T`.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        ///
        /// Notes:
        /// - Rebalances as needed to maintain red-black invariants.
        pub fn removeFromPtr(self: *Self, target_node: *Node) T {
            self.count -= 1;
            var parent_of_target: ?*Node = target_node.parent;
            const removed_value = target_node.data;

            const has_at_most_one_child =
                (target_node.getChild(.left) == null) or
                (target_node.getChild(.right) == null);

            if (has_at_most_one_child) {
                const non_null_direction: Direction =
                    if (target_node.getChild(.left) == null) Direction.right else Direction.left;
                const child_replacement = target_node.getChild(non_null_direction);

                if (target_node == self.root) {
                    self.root = child_replacement;
                    if (child_replacement) |r| {
                        r.parent = null;
                        r.color = Color.black;
                    }
                } else {
                    const direction_from_parent: Direction =
                        if (target_node == parent_of_target.?.getChild(.left)) Direction.left else Direction.right;

                    parent_of_target.?.setParentChildRelation(child_replacement, direction_from_parent);

                    if (target_node.color == Color.black) {
                        if (child_replacement) |r| {
                            if (r.color == Color.red) r.color = Color.black;
                        } else {
                            self.removeFix(parent_of_target.?, direction_from_parent);
                        }
                    }
                }

                target_node.destroy(self.allocator);
                return removed_value;
            } else {
                var successor_node: *Node = target_node.getChild(.right).?;
                var parent_of_successor: ?*Node = null;
                while (successor_node.getChild(.left)) |left_child| {
                    parent_of_successor = successor_node;
                    successor_node = left_child;
                }

                const original_color_of_successor = successor_node.color;
                const replacement_subchild: ?*Node = successor_node.getChild(.right);

                if (parent_of_successor) |_| {
                    parent_of_successor.?.setParentChildRelation(replacement_subchild, .left);
                    successor_node.setParentChildRelation(target_node.getChild(.right), .right);
                }

                const parent_ptr = target_node.parent;
                if (parent_ptr) |p| {
                    const direction_to_target: Direction =
                        if (p.getChild(.left) == target_node) Direction.left else Direction.right;
                    p.setParentChildRelation(successor_node, direction_to_target);
                } else {
                    self.root = successor_node;
                    successor_node.parent = null;
                }

                successor_node.setParentChildRelation(target_node.getChild(.left), .left);
                successor_node.color = target_node.color;

                target_node.destroy(self.allocator);

                if (original_color_of_successor == .black) {
                    const double_black_parent: *Node = if (parent_of_successor) |pos| pos else successor_node;
                    const double_black_side: Direction = if (parent_of_successor != null) Direction.left else Direction.right;
                    if (replacement_subchild) |child| {
                        if (child.color == .red) {
                            child.color = .black;
                        } else {
                            self.removeFix(double_black_parent, double_black_side);
                        }
                    } else {
                        self.removeFix(double_black_parent, double_black_side);
                    }
                }

                return removed_value;
            }
        }

        /// Summary:
        /// Restores invariants after deletion where a black-height deficit exists.
        ///
        /// Arguments:
        /// - `self`: Target tree.
        /// - `parent`: Parent at which the deficit is observed.
        /// - `which_child`: Side of the deficit under `parent`.
        ///
        /// Returns:
        /// - void.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        fn removeFix(
            self: *Self,
            parent: *Node,
            which_child: Direction,
        ) void {
            var current_parent = parent;
            var deficit_side = which_child;

            while (true) {
                const deficit_node = current_parent.getChild(deficit_side);

                if (deficit_node) |node_with_deficit| {
                    if (node_with_deficit.color == .red) {
                        node_with_deficit.color = .black;
                        break;
                    }
                }

                const sibling_opt = current_parent.getChild(deficit_side.flip());
                if (sibling_opt == null) {
                    if (current_parent.color == .red) {
                        current_parent.color = Color.black;
                        break;
                    }
                    const grand_opt = current_parent.parent;
                    if (grand_opt == null) break;
                    const grandparent = grand_opt.?;
                    deficit_side = if (current_parent == grandparent.getChild(.left)) .left else .right;
                    current_parent = grandparent;
                    continue;
                }

                const sibling = sibling_opt.?;
                const near_child = sibling.getChild(deficit_side);
                const far_child = sibling.getChild(deficit_side.flip());

                if (sibling.color == .red) {
                    self.rotate(current_parent, deficit_side);
                    sibling.color = Color.black;
                    current_parent.color = Color.red;
                    continue;
                } else {
                    const far_is_red = if (far_child) |f| f.color == .red else false;
                    const near_is_red = if (near_child) |n| n.color == .red else false;

                    if (!far_is_red and !near_is_red) {
                        sibling.color = Color.red;
                        if (current_parent.color == .red) {
                            current_parent.color = Color.black;
                            break;
                        }
                        const grand_opt = current_parent.parent;
                        if (grand_opt == null) break;
                        const grandparent = grand_opt.?;
                        deficit_side = if (current_parent == grandparent.getChild(.left)) .left else .right;
                        current_parent = grandparent;
                        continue;
                    } else if (far_is_red) {
                        sibling.color = current_parent.color;
                        current_parent.color = Color.black;
                        far_child.?.color = Color.black;
                        self.rotate(current_parent, deficit_side);
                        break;
                    } else {
                        sibling.color = Color.red;
                        near_child.?.color = Color.black;
                        self.rotate(sibling, deficit_side.flip());
                        continue;
                    }
                }
            }

            if (self.root) |root_node| root_node.color = Color.black;
        }

        /// Summary:
        /// Single rotation around `pivot`. Direction `d` identifies the deficit side.
        ///
        /// Arguments:
        /// - `self`: Target tree.
        /// - `pivot`: Node to rotate around.
        /// - `d`: Direction of deficit (determines left/right rotation).
        ///
        /// Returns:
        /// - void.
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        fn rotate(
            self: *Self,
            pivot: *Node,
            d: Direction,
        ) void {
            const new_parent = pivot.getChild(d.flip()).?;

            pivot.setParentChildRelation(new_parent.getChild(d), d.flip());

            new_parent.parent = pivot.parent;
            if (pivot.parent) |p| {
                std.debug.assert(p.getChild(.left) == pivot or p.getChild(.right) == pivot);
                const pivot_direction = if (p.getChild(Direction.left) == pivot) Direction.left else Direction.right;
                p.setParentChildRelation(new_parent, pivot_direction);
            } else {
                self.root = new_parent;
            }

            new_parent.setParentChildRelation(pivot, d);
        }

        /// Summary:
        /// Finds neighbors of `data` in the order defined by `cmpFn`.
        ///
        /// Arguments:
        /// - `self`: Tree to query.
        /// - `data`: Key to search around.
        ///
        /// Returns:
        /// - `{ lower, upper }` where:
        ///   - `lower` is the greatest element ≤ `data` (predecessor or equal)
        ///   - `upper` is the least element ≥ `data` (successor or equal)
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        pub fn findNeighbors(self: *Self, data: T) struct {
            lower: ?T,
            upper: ?T,
        } {
            var current = self.root;
            var lower: ?T = null;
            var upper: ?T = null;

            while (current) |node| {
                switch (cmpFn(data, node.data)) {
                    .lt => {
                        upper = node.data;
                        current = node.getChild(.left);
                        if (current) |c| @prefetch(c, .{});
                    },
                    .gt => {
                        lower = node.data;
                        current = node.getChild(.right);
                        if (current) |c| @prefetch(c, .{});
                    },
                    .eq => {
                        lower = node.data;
                        upper = node.data;
                        break;
                    },
                }
            }

            return .{ .lower = lower, .upper = upper };
        }

        pub fn forEachInRange(
            self: *Self,
            range_start: T,
            range_end: T,
            context: anytype,
            comptime callback: fn (@TypeOf(context), T) void,
        ) void {
            var current = self.root;
            var stack: [64]?*Node = undefined;
            var stack_top: usize = 0;

            while (current != null or stack_top > 0) {
                while (current) |c| {
                    if (cmpFn(c.data, range_end) != .lt) {
                        current = c.getChild(.left);
                    } else {
                        stack[stack_top] = c;
                        stack_top += 1;
                        current = c.getChild(.left);
                    }
                }

                if (stack_top == 0) break;
                stack_top -= 1;
                const node = stack[stack_top].?;

                if (cmpFn(node.data, range_start) != .lt) {
                    callback(context, node.data);
                }

                current = node.getChild(.right);
            }
        }

        /// Summary:
        /// Validates red-black invariants and returns `(valid, black_height)`.
        ///
        /// Arguments:
        /// - `node`: Subtree root to validate (null = leaf).
        /// - `min_val`: Strict lower bound (exclusive) for BST ordering, or null.
        /// - `max_val`: Strict upper bound (exclusive) for BST ordering, or null.
        ///
        /// Returns:
        /// - `{ valid: bool, black_height: i32 }` where `black_height` is the
        ///   number of black nodes on any path to leaves (including leaf nil).
        ///
        /// Errors:
        /// - None.
        ///
        /// Panics:
        /// - None.
        ///
        /// Notes:
        /// - On failure, logs a diagnostic dump of the offending node.
        pub fn validateRedBlackTree(
            node: ?*Node,
            min_val: ?T,
            max_val: ?T,
        ) struct {
            valid: bool,
            black_height: i32,
        } {
            if (node == null) return .{ .valid = true, .black_height = 1 };
            const n = node.?;

            const fail = struct {
                fn dump(node_ptr: *Node, reason: []const u8) void {
                    std.debug.print("\n[RBTree Validation Failed]\n", .{});
                    std.debug.print("Reason: {s}\n", .{reason});
                    std.debug.print("Node @ {x}\n", .{@intFromPtr(node_ptr)});
                    std.debug.print("  data = {}\n", .{node_ptr.data});
                    std.debug.print("  color = {s}\n", .{if (node_ptr.color == .red) "Red" else "Black"});

                    if (node_ptr.parent) |p| {
                        std.debug.print("  parent @ {x}, data = {}\n", .{ @intFromPtr(p), p.data });
                    } else {
                        std.debug.print("  parent = null\n", .{});
                    }
                    if (node_ptr.getChild(.left)) |l| {
                        std.debug.print("  left @ {x}, data = {}\n", .{ @intFromPtr(l), l.data });
                    } else {
                        std.debug.print("  left = null\n", .{});
                    }
                    if (node_ptr.getChild(.right)) |r| {
                        std.debug.print("  right @ {x}, data = {}\n", .{ @intFromPtr(r), r.data });
                    } else {
                        std.debug.print("  right = null\n", .{});
                    }
                }
            };

            // Root must have null parent on the top-level call
            if (min_val == null and max_val == null) {
                if (n.parent != null) {
                    fail.dump(n, "Root has non-null parent");
                    return .{ .valid = false, .black_height = 0 };
                }
            }

            // ---- Symmetry checks (both directions) ----
            // Upward: if a parent exists, it must reference us as a child.
            if (n.parent) |p| {
                const parent_points_to_us =
                    (p.getChild(.left) == n) or (p.getChild(.right) == n);
                if (!parent_points_to_us) {
                    fail.dump(n, "Parent does not point to this node");
                    return .{ .valid = false, .black_height = 0 };
                }
            }

            // Downward: any child must have us as its parent.
            if (n.getChild(.left)) |l| {
                if (l.parent != n) {
                    fail.dump(n, "Left child's parent != this node");
                    return .{ .valid = false, .black_height = 0 };
                }
            }
            if (n.getChild(.right)) |r| {
                if (r.parent != n) {
                    fail.dump(n, "Right child's parent != this node");
                    return .{ .valid = false, .black_height = 0 };
                }
            }

            // Invariant: BST property
            if (min_val) |min| {
                if (cmpFn(n.data, min) != .gt) {
                    fail.dump(n, "BST violation: data <= min bound");
                    return .{ .valid = false, .black_height = 0 };
                }
            }
            if (max_val) |max| {
                if (cmpFn(n.data, max) != .lt) {
                    fail.dump(n, "BST violation: data >= max bound");
                    return .{ .valid = false, .black_height = 0 };
                }
            }

            // Invariant: red node never has a red child
            if (n.color == .red) {
                if (n.getChild(.left)) |left| {
                    if (left.color == .red) {
                        fail.dump(n, "Red node has red left child");
                        return .{ .valid = false, .black_height = 0 };
                    }
                }
                if (n.getChild(.right)) |right| {
                    if (right.color == .red) {
                        fail.dump(n, "Red node has red right child");
                        return .{ .valid = false, .black_height = 0 };
                    }
                }
            }

            // Recurse
            const left_result = validateRedBlackTree(n.getChild(.left), min_val, n.data);
            if (!left_result.valid) return left_result;

            const right_result = validateRedBlackTree(n.getChild(.right), n.data, max_val);
            if (!right_result.valid) return right_result;

            // Invariant: equal black height on all descendant paths
            if (left_result.black_height != right_result.black_height) {
                fail.dump(n, "Black height mismatch between children");
                return .{ .valid = false, .black_height = 0 };
            }

            const black_contribution: i32 = if (n.color == .black) 1 else 0;
            return .{
                .valid = true,
                .black_height = left_result.black_height + black_contribution,
            };
        }
    };
}

// test case comparator
fn i32Order(a: i32, b: i32) std.math.Order {
    return std.math.order(a, b);
}

test "insert and contains" {
    const allocator = std.testing.allocator;
    var tree = RedBlackTree(i32, i32Order, false).init(allocator);
    defer tree.deinit();

    try tree.insert(42);
    try std.testing.expect(tree.contains(42));
}

test "insert then remove and not contains" {
    const allocator = std.testing.allocator;
    var tree = RedBlackTree(i32, i32Order, false).init(allocator);
    defer tree.deinit();

    try tree.insert(7);
    try std.testing.expect(tree.contains(7));
    _ = try tree.remove(7);
    try std.testing.expect(!tree.contains(7));
}

test "insert duplicate returns error if configured" {
    const allocator = std.testing.allocator;
    var tree = RedBlackTree(i32, i32Order, true).init(allocator);
    defer tree.deinit();

    try tree.insert(99);
    const err = tree.insert(99);
    try std.testing.expectError(error.Duplicate, err);
}

test "remove nonexistent value returns error" {
    const allocator = std.testing.allocator;
    var tree = RedBlackTree(i32, i32Order, false).init(allocator);
    defer tree.deinit();

    const err = tree.remove(1234);
    try std.testing.expectError(error.NotFound, err);
}

test "insert many and deinit without leaks" {
    const allocator = std.testing.allocator;
    var tree = RedBlackTree(i32, i32Order, false).init(allocator);
    defer tree.deinit();

    for (0..1000) |i| {
        try tree.insert(@intCast(i));
    }
}

test "insertFix case 1: recoloring when uncle is red" {
    const Tree = RedBlackTree(i32, i32Order, false);

    const allocator = std.testing.allocator;

    const gp = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(gp, allocator);
    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const uncle = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(uncle, allocator);
    const new_node = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_node, allocator);

    const gp_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(gp_expected, allocator);
    const parent_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent_expected, allocator);
    const uncle_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(uncle_expected, allocator);
    const new_node_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_node_expected, allocator);

    gp.* = .{
        .data = 10,
        .color = .black,
        .children = .{ parent, uncle },
        .parent = null,
    };
    parent.* = .{
        .data = 5,
        .color = .red,
        .children = .{ new_node, null },
        .parent = gp,
    };
    uncle.* = .{
        .data = 15,
        .color = .red,
        .children = .{ null, null },
        .parent = gp,
    };
    new_node.* = .{
        .data = 2,
        .color = .red,
        .children = .{ null, null },
        .parent = parent,
    };

    gp_expected.* = .{
        .data = 10,
        .color = .black,
        .children = .{ parent_expected, uncle_expected },
        .parent = null,
    };
    parent_expected.* = .{
        .data = 5,
        .color = .black,
        .children = .{ new_node_expected, null },
        .parent = gp_expected,
    };
    uncle_expected.* = .{
        .data = 15,
        .color = .black,
        .children = .{ null, null },
        .parent = gp_expected,
    };
    new_node_expected.* = .{
        .data = 2,
        .color = .red,
        .children = .{ null, null },
        .parent = parent_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = gp;

    tree.insertFix(new_node);

    try Tree.expectSameTree(tree.root, gp_expected);
}

test "insertFix case 2a: triangle (rotate parent)" {
    const Tree = RedBlackTree(i32, i32Order, false);

    const allocator = std.testing.allocator;

    const grand = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(grand, allocator);
    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const new_node = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_node, allocator);

    const grand_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(grand_expected, allocator);
    const left_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left_expected, allocator);
    const right_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(right_expected, allocator);

    grand.* = .{
        .data = 10,
        .color = .black,
        .children = .{ parent, null },
        .parent = null,
    };
    parent.* = .{
        .data = 5,
        .color = .red,
        .children = .{ null, new_node },
        .parent = grand,
    };
    new_node.* = .{
        .data = 7,
        .color = .red,
        .children = .{ null, null },
        .parent = parent,
    };

    grand_expected.* = .{
        .data = 7,
        .color = .black,
        .children = .{ left_expected, right_expected },
        .parent = null,
    };
    left_expected.* = .{
        .data = 5,
        .color = .red,
        .children = .{ null, null },
        .parent = grand_expected,
    };
    right_expected.* = .{
        .data = 10,
        .color = .red,
        .children = .{ null, null },
        .parent = grand_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = grand;

    tree.insertFix(new_node);

    try Tree.expectSameTree(tree.root, grand_expected);
}

test "insertFix case 2b: line (rotate grandparent)" {
    const Tree = RedBlackTree(i32, i32Order, false);

    const allocator = std.testing.allocator;

    const grand = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(grand, allocator);
    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const new_node = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_node, allocator);

    const root_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(root_expected, allocator);
    const left_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left_expected, allocator);
    const right_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(right_expected, allocator);

    grand.* = .{
        .data = 10,
        .color = .black,
        .children = .{ parent, null },
        .parent = null,
    };
    parent.* = .{
        .data = 5,
        .color = .red,
        .children = .{ new_node, null },
        .parent = grand,
    };
    new_node.* = .{
        .data = 2,
        .color = .red,
        .children = .{ null, null },
        .parent = parent,
    };

    root_expected.* = .{
        .data = 5,
        .color = .black,
        .children = .{ left_expected, right_expected },
        .parent = null,
    };
    left_expected.* = .{
        .data = 2,
        .color = .red,
        .children = .{ null, null },
        .parent = root_expected,
    };
    right_expected.* = .{
        .data = 10,
        .color = .red,
        .children = .{ null, null },
        .parent = root_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = grand;

    tree.insertFix(new_node);

    try Tree.expectSameTree(tree.root, root_expected);
}

test "removeFix case 1: red sibling" {
    const Tree = RedBlackTree(i32, i32Order, false);
    const allocator = std.testing.allocator;

    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const sibling = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling, allocator);

    const new_root = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_root, allocator);
    const left_of_root = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left_of_root, allocator);

    parent.* = .{
        .data = 10,
        .color = .black,
        .children = .{ null, sibling },
        .parent = null,
    };
    sibling.* = .{
        .data = 15,
        .color = .red,
        .children = .{ null, null },
        .parent = parent,
    };

    new_root.* = .{
        .data = 15,
        .color = .black,
        .children = .{ left_of_root, null },
        .parent = null,
    };
    left_of_root.* = .{
        .data = 10,
        .color = .black,
        .children = .{ null, null },
        .parent = new_root,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(parent, .left);

    try Tree.expectSameTree(tree.root, new_root);
}

test "removeFix case 2: black sibling, red far child" {
    const Tree = RedBlackTree(i32, i32Order, false);
    const allocator = std.testing.allocator;

    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const sibling = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling, allocator);
    const far = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(far, allocator);

    const new_root = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(new_root, allocator);
    const left = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left, allocator);
    const far_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(far_expected, allocator);

    parent.* = .{
        .data = 10,
        .color = .black,
        .children = .{ null, sibling },
        .parent = null,
    };
    sibling.* = .{
        .data = 15,
        .color = .black,
        .children = .{ null, far },
        .parent = parent,
    };
    far.* = .{
        .data = 20,
        .color = .red,
        .children = .{ null, null },
        .parent = sibling,
    };

    new_root.* = .{
        .data = 15,
        .color = .black,
        .children = .{ left, far_expected },
        .parent = null,
    };
    left.* = .{
        .data = 10,
        .color = .black,
        .children = .{ null, null },
        .parent = new_root,
    };
    far_expected.* = .{
        .data = 20,
        .color = .black,
        .children = .{ null, null },
        .parent = new_root,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(parent, .left);

    try Tree.expectSameTree(tree.root, new_root);
}

test "removeFix case 3: black sibling, red near child" {
    const Tree = RedBlackTree(i32, i32Order, false);
    const allocator = std.testing.allocator;

    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const sibling = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling, allocator);
    const near = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(near, allocator);

    const root_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(root_expected, allocator);
    const left_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(left_expected, allocator);
    const right_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(right_expected, allocator);

    parent.* = .{
        .data = 10,
        .color = .black,
        .children = .{ null, sibling },
        .parent = null,
    };
    sibling.* = .{
        .data = 15,
        .color = .black,
        .children = .{ near, null },
        .parent = parent,
    };
    near.* = .{
        .data = 12,
        .color = .red,
        .children = .{ null, null },
        .parent = sibling,
    };

    root_expected.* = .{
        .data = 12,
        .color = .black,
        .children = .{ left_expected, right_expected },
        .parent = null,
    };
    left_expected.* = .{
        .data = 10,
        .color = .black,
        .children = .{ null, null },
        .parent = root_expected,
    };
    right_expected.* = .{
        .data = 15,
        .color = .black,
        .children = .{ null, null },
        .parent = root_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(parent, .left);

    try Tree.expectSameTree(tree.root, root_expected);
}

test "removeFix case 4: black sibling, black children" {
    const Tree = RedBlackTree(i32, i32Order, false);
    const allocator = std.testing.allocator;

    const parent = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent, allocator);
    const sibling = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling, allocator);

    const parent_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(parent_expected, allocator);
    const sibling_expected = try Tree.testCreateNode(allocator);
    defer Tree.testDestroyNode(sibling_expected, allocator);

    parent.* = .{
        .data = 10,
        .color = .black,
        .children = .{ null, sibling },
        .parent = null,
    };
    sibling.* = .{
        .data = 15,
        .color = .black,
        .children = .{ null, null },
        .parent = parent,
    };

    parent_expected.* = .{
        .data = 10,
        .color = .black,
        .children = .{ null, sibling_expected },
        .parent = null,
    };
    sibling_expected.* = .{
        .data = 15,
        .color = .red,
        .children = .{ null, null },
        .parent = parent_expected,
    };

    var tree = Tree.init(allocator);
    tree.root = parent;

    tree.removeFix(parent, .left);

    try Tree.expectSameTree(tree.root, parent_expected);
}

test "insert remove insert cycles maintain red-black tree invariants" {
    const allocator = std.testing.allocator;

    const Tree = RedBlackTree(i32, i32Order, false);

    var tree = Tree.init(allocator);
    defer tree.deinit();

    const initial_values = [_]i32{ 10, 5, 15, 3, 7, 12, 18, 1, 4, 6, 8, 11, 13, 16, 20 };
    for (initial_values) |val| {
        try tree.insert(val);
    }

    const to_remove_1 = [_]i32{ 3, 15, 8, 1 };
    for (to_remove_1) |val| {
        _ = try tree.remove(val);
    }

    const to_insert_2 = [_]i32{ 2, 9, 14, 17, 25, 30 };
    for (to_insert_2) |val| {
        try tree.insert(val);
    }

    const to_remove_2 = [_]i32{ 7, 12, 20, 2 };
    for (to_remove_2) |val| {
        _ = try tree.remove(val);
    }

    const to_insert_3 = [_]i32{ 22, 26, 35, 40, 45 };
    for (to_insert_3) |val| {
        try tree.insert(val);
    }

    // Validate red-black tree invariants
    if (tree.root) |root| {
        // Invariant 1: Root is black
        try std.testing.expect(root.color == .black);

        // Validate all invariants
        const result = Tree.validateRedBlackTree(
            root,
            null,
            null,
        );
        try std.testing.expect(result.valid);
    }

    const expected_present = [_]i32{ 10, 5, 4, 6, 11, 13, 16, 18, 9, 14, 17, 25, 30, 26, 22, 35, 40, 45 };
    for (expected_present) |val| {
        try std.testing.expect(tree.contains(val));
    }

    const expected_absent = [_]i32{ 3, 15, 8, 1, 7, 12, 20, 2 };
    for (expected_absent) |val| {
        try std.testing.expect(!tree.contains(val));
    }
}

test "findNeighbors returns correct lower and upper" {
    const allocator = std.testing.allocator;
    const Tree = RedBlackTree(i32, i32Order, false);
    var tree = Tree.init(allocator);
    defer tree.deinit();

    try tree.insert(10);
    try tree.insert(20);
    try tree.insert(40);
    try tree.insert(50);

    const neighbors = tree.findNeighbors(30);

    try std.testing.expectEqual(@as(?i32, 20), neighbors.lower);
    try std.testing.expectEqual(@as(?i32, 40), neighbors.upper);
}
