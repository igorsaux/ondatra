const std = @import("std");

const jit = @import("../jit.zig");
const CodeArena = @import("code_arena.zig").CodeArena;

pub const BlockCache = struct {
    pub const BlockFn = CodeArena.BlockFn;

    pub const Entry = struct {
        func: BlockFn,
        start_pc: u32,
    };

    map: std.AutoHashMap(u32, Entry),

    pub inline fn init(allocator: std.mem.Allocator) BlockCache {
        return .{
            .map = std.AutoHashMap(u32, Entry).init(allocator),
        };
    }

    pub inline fn deinit(this: *BlockCache) void {
        this.map.deinit();
    }

    pub inline fn lookup(this: *const BlockCache, pc: u32) ?Entry {
        return this.map.get(pc);
    }

    pub inline fn insert(this: *BlockCache, pc: u32, entry: Entry) !void {
        try this.map.put(pc, entry);
    }

    pub inline fn invalidateAll(this: *BlockCache) void {
        this.map.clearRetainingCapacity();
    }

    pub inline fn invalidateRange(this: *BlockCache, start: u32, end: u32) void {
        var to_remove = std.ArrayList(u32).init(this.map.allocator);
        defer to_remove.deinit();

        var iter = this.map.iterator();

        while (iter.next()) |entry| {
            if (entry.key_ptr.* >= start and entry.key_ptr.* < end) {
                to_remove.append(entry.key_ptr.*) catch continue;
            }
        }

        for (to_remove.items) |pc| {
            _ = this.map.remove(pc);
        }
    }

    pub inline fn count(this: *const BlockCache) usize {
        return this.map.count();
    }
};
