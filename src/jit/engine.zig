const std = @import("std");

const jit = @import("../jit.zig");
const BlockCache = @import("block_cache.zig").BlockCache;
const CodeArena = @import("code_arena.zig").CodeArena;
const compiler = @import("compiler.zig");
const EngineConfig = @import("engine_config.zig").EngineConfig;

pub fn Engine(comptime config: EngineConfig) type {
    return struct {
        const Self = @This();

        const Compiler = compiler.Compiler(.current, config);
        const offsets = config.callbacks.get_offsets();

        arena: CodeArena,
        compiler: Compiler,
        cache: BlockCache,

        pub inline fn init(allocator: std.mem.Allocator) !Self {
            return .{
                .arena = try CodeArena.init(config.jit.code_arena_size),
                .compiler = Compiler.init(),
                .cache = BlockCache.init(allocator),
            };
        }

        pub inline fn deinit(this: *Self) void {
            this.cache.deinit();
            this.compiler.deinit();
            this.arena.deinit();
        }

        pub inline fn step(this: *Self, cpu: *anyopaque) !EngineConfig.State {
            const pc = readPC(cpu);

            const block = this.cache.lookup(pc) orelse blk: {
                const func = try this.compileWithRetry(cpu, pc);
                const entry = BlockCache.Entry{ .func = func, .start_pc = pc };

                try this.cache.insert(pc, entry);

                break :blk entry;
            };

            const result_code = block.func(cpu);

            return @enumFromInt(result_code);
        }

        pub inline fn run(this: *Self, cpu: *anyopaque, max_cycles: u64) !EngineConfig.State {
            const start_cycle = readCycle(cpu);
            const target_cycle = start_cycle +| max_cycles;

            while (readCycle(cpu) < target_cycle) {
                const result = try this.step(cpu);

                if (result != .ok) {
                    return result;
                }
            }

            return .ok;
        }

        pub inline fn invalidate(this: *Self) void {
            this.cache.invalidateAll();
            this.arena.reset();
        }

        pub inline fn invalidateRange(this: *Self, start: u32, end: u32) void {
            this.cache.invalidateRange(start, end);
        }

        pub inline fn stats(this: *const Self) struct {
            blocks_cached: usize,
            code_bytes_used: usize,
            code_bytes_total: usize,
        } {
            return .{
                .blocks_cached = this.cache.count(),
                .code_bytes_used = this.arena.usedBytes(),
                .code_bytes_total = this.arena.totalBytes(),
            };
        }

        inline fn compileWithRetry(this: *Self, cpu: *anyopaque, pc: u32) !CodeArena.BlockFn {
            return this.compiler.compileBlock(&this.arena, cpu, pc) catch |err| {
                if (err == error.OutOfCodeMemory) {
                    this.arena.reset();
                    this.cache.invalidateAll();

                    return this.compiler.compileBlock(&this.arena, cpu, pc);
                }

                return err;
            };
        }

        inline fn readPC(cpu: *anyopaque) u32 {
            const ptr: *const u32 = @ptrFromInt(@intFromPtr(cpu) + offsets.pc);

            return ptr.*;
        }

        inline fn readCycle(cpu: *anyopaque) u64 {
            const ptr: *const u64 = @ptrFromInt(@intFromPtr(cpu) + offsets.cycle);

            return ptr.*;
        }
    };
}
