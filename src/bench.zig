// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

const ondatra = @import("ondatra");

const Runner = struct {
    const State = enum {
        idle,
        pre_running,
        running,
    };

    const Recordings = struct {
        const Stats = struct {
            min: i128,
            max: i128,
            avg: f64,
            median: i128,
            std_dev: f64,
            instructions: usize,

            pub fn mips(this: Stats) f64 {
                const instr_f: f64 = @floatFromInt(this.instructions);
                const avg_sec = this.avg / 1_000_000_000.0;

                return (instr_f / avg_sec) / 1_000_000.0;
            }

            pub fn mipsFromTime(this: Stats, time_ns: i128) f64 {
                const instr_f: f64 = @floatFromInt(this.instructions);
                const time_sec = @as(f64, @floatFromInt(time_ns)) / 1_000_000_000.0;

                return (instr_f / time_sec) / 1_000_000.0;
            }
        };

        pos: usize = 0,
        begin: i128 = 0,
        instructions: usize = 0,
        samples: []i128,

        pub fn init(allocator: std.mem.Allocator, samples_count: usize) !Recordings {
            const samples = try allocator.alloc(i128, samples_count);
            @memset(samples, 0);

            return .{
                .samples = samples,
            };
        }

        pub fn stats(this: *Recordings, allocator: std.mem.Allocator) Stats {
            var valid_count: usize = 0;

            for (this.samples) |sample| {
                if (sample != 0) valid_count += 1;
            }

            if (valid_count == 0) {
                return .{
                    .min = 0,
                    .max = 0,
                    .avg = 0,
                    .median = 0,
                    .std_dev = 0,
                    .instructions = this.instructions,
                };
            }

            var sorted: std.ArrayList(i128) = .empty;
            defer sorted.deinit(allocator);

            for (this.samples) |sample| {
                if (sample != 0) {
                    sorted.append(allocator, sample) catch continue;
                }
            }

            std.mem.sort(i128, sorted.items, {}, std.sort.asc(i128));

            var sum: i128 = 0;
            var min: i128 = std.math.maxInt(i128);
            var max: i128 = std.math.minInt(i128);

            for (sorted.items) |sample| {
                sum +|= sample;
                min = @min(min, sample);
                max = @max(max, sample);
            }

            const count_f: f64 = @floatFromInt(valid_count);
            const avg: f64 = @as(f64, @floatFromInt(sum)) / count_f;

            const median = if (valid_count % 2 == 1)
                sorted.items[valid_count / 2]
            else
                @divFloor(sorted.items[valid_count / 2 - 1] + sorted.items[valid_count / 2], 2);

            var variance_sum: f64 = 0;

            for (sorted.items) |sample| {
                const diff = @as(f64, @floatFromInt(sample)) - avg;

                variance_sum += diff * diff;
            }

            const std_dev = @sqrt(variance_sum / count_f);

            return .{
                .min = min,
                .max = max,
                .avg = avg,
                .median = median,
                .std_dev = std_dev,
                .instructions = this.instructions,
            };
        }

        pub fn deinit(this: *Recordings, allocator: std.mem.Allocator) void {
            allocator.free(this.samples);
        }
    };

    pub const Error = error{ BenchmarkFailed, AlreadyRunning, NotRunning, EndWithoutBegin, OutOfMemory };

    state: State = .idle,
    recordings: ?Recordings = null,

    pub inline fn init() Runner {
        return .{};
    }

    pub inline fn begin(this: *Runner) Error!void {
        const timestamp = std.time.nanoTimestamp();

        switch (this.state) {
            .idle => return Error.NotRunning,
            .pre_running => return,
            .running => {
                std.debug.assert(this.recordings != null);

                this.recordings.?.begin = timestamp;

                return;
            },
        }
    }

    pub inline fn end(this: *Runner, instructions: usize) Error!void {
        const timestamp = std.time.nanoTimestamp();

        switch (this.state) {
            .idle => return Error.NotRunning,
            .pre_running => return,
            .running => {
                std.debug.assert(this.recordings != null);

                var r: *Recordings = &this.recordings.?;

                if (r.begin == 0) {
                    return Error.EndWithoutBegin;
                }

                r.instructions = instructions;
                r.samples[r.pos] = timestamp - r.begin;
                r.pos +%= 1;
                r.begin = 0;

                return;
            },
        }
    }

    pub fn run(this: *Runner, allocator: std.mem.Allocator, benchmark: Benchmark) Error!void {
        if (this.state != .idle) {
            return Error.AlreadyRunning;
        }

        if (this.recordings) |*state| {
            state.deinit(allocator);
            this.recordings = null;
        }

        this.state = .pre_running;
        errdefer this.state = .idle;

        this.recordings = try .init(allocator, benchmark.config.runs);

        defer {
            this.recordings.?.deinit(allocator);
            this.recordings = null;
        }

        for (0..benchmark.config.pre_runs) |_| {
            if (!benchmark.func(allocator, this)) {
                std.debug.print("A benchmark '{s}' failed!\n", .{benchmark.name});

                return Error.BenchmarkFailed;
            }
        }

        this.state = .running;

        for (0..benchmark.config.runs) |_| {
            if (!benchmark.func(allocator, this)) {
                std.debug.print("A benchmark '{s}' failed!\n", .{benchmark.name});

                return Error.BenchmarkFailed;
            }
        }

        this.state = .idle;

        const stats = this.recordings.?.stats(allocator);

        std.debug.print("\n+{s:-^108}+\n", .{benchmark.name});
        std.debug.print("|{s: ^10}|{s: ^12}|{s: ^12}|{s: ^12}|{s: ^12}|{s: ^12}|{s: ^10}|{s: ^10}|{s: ^10}|\n", .{
            "instr", "min", "max", "avg", "median", "std_dev", "MIPS avg", "MIPS min", "MIPS max",
        });
        std.debug.print("|{s:-^10}|{s:-^12}|{s:-^12}|{s:-^12}|{s:-^12}|{s:-^12}|{s:-^10}|{s:-^10}|{s:-^10}|\n", .{
            "", "", "", "", "", "", "", "", "",
        });
        std.debug.print("|{d: ^10}|{D: ^12}|{D: ^12}|{D: ^12}|{D: ^12}|{d: ^12.2}|{d: ^10.1}|{d: ^10.1}|{d: ^10.1}|\n", .{
            stats.instructions,
            @as(i64, @truncate(stats.min)),
            @as(i64, @truncate(stats.max)),
            @as(i64, @intFromFloat(stats.avg)),
            @as(i64, @truncate(stats.median)),
            stats.std_dev / 1000.0,
            stats.mips(),
            stats.mipsFromTime(stats.max),
            stats.mipsFromTime(stats.min),
        });
        std.debug.print("+{s:-^108}+\n\n", .{"-"});
    }
};

const Config = struct {
    pre_runs: usize = 1024,
    runs: usize = 2048,
};

const BenchmarkFunc = fn (allocator: std.mem.Allocator, r: *Runner) bool;

const Benchmark = struct {
    pub const Func = fn (allocator: std.mem.Allocator, r: *Runner) bool;

    name: []const u8,
    config: Config = .{},
    func: *const Func,
};

pub fn main() !void {
    var alloc: std.heap.DebugAllocator(.{}) = .init;
    defer _ = alloc.deinit();

    const benchs = [_]Benchmark{
        .{ .name = "fibbonacci_compilant", .func = fibbonacciCompilantBenchmark },
        .{ .name = "fibbonacci_fast", .func = fibbonacciFastBenchmark },
        .{ .name = "floatMinMaxAbs_compilant", .func = floatMinMaxAbsCompilantBenchmark },
        .{ .name = "floatMinMaxAbs_fast", .func = floatMinMaxAbsFastBenchmark },
        .{ .name = "floatArithmetic_compilant", .func = floatArithmeticCompilantBenchmark },
        .{ .name = "floatArithmetic_fast", .func = floatArithmeticFastBenchmark },
        .{ .name = "floatSqrtFma_compilant", .func = floatSqrtFmaCompilantBenchmark },
        .{ .name = "floatSqrtFma_fast", .func = floatSqrtFmaFastBenchmark },
    };
    var runner: Runner = .init();

    for (benchs) |bench| {
        try runner.run(alloc.allocator(), bench);
    }
}

/// Like `.fast` but with enabled counters of course!
const FAST: ondatra.cpu.Config.Runtime = .{
    .enable_pmp = false,
    .enable_pmp_m = false,
    .enable_memory_alignment = false,
    .enable_privilege = false,
    .enable_csr_checks = false,
    .enable_interrupts = false,
    .enable_branch_alignment = false,
    .enable_fpu_flags = false,
    .timer_ticks_per_step = 0,
};

const fibbonacciCompilantBenchmark = MakeBenchmark("fibbonacci.bin", .compliant);
const fibbonacciFastBenchmark = MakeBenchmark("fibbonacci.bin", FAST);

const floatMinMaxAbsCompilantBenchmark = MakeBenchmark("float_minmax_abs.bin", .compliant);
const floatMinMaxAbsFastBenchmark = MakeBenchmark("float_minmax_abs.bin", FAST);

const floatArithmeticCompilantBenchmark = MakeBenchmark("float_arithmetic.bin", .compliant);
const floatArithmeticFastBenchmark = MakeBenchmark("float_arithmetic.bin", FAST);

const floatSqrtFmaCompilantBenchmark = MakeBenchmark("float_sqrt_fma.bin", .compliant);
const floatSqrtFmaFastBenchmark = MakeBenchmark("float_sqrt_fma.bin", FAST);

fn MakeBenchmark(comptime program: []const u8, comptime config: ondatra.cpu.Config.Runtime) Benchmark.Func {
    return struct {
        fn func(allocator: std.mem.Allocator, r: *Runner) bool {
            const PROGRAM = @embedFile(program);

            const State = struct {
                const Cpu = ondatra.cpu.Cpu(.{
                    .hooks = .{
                        .ecall = ecall,
                    },
                    .runtime = config,
                    .compile = .fast_execution,
                });

                over: bool = false,
                cpu: Cpu,

                inline fn ecall(ctx: *anyopaque, cause: ondatra.arch.Registers.Mcause.Exception) ondatra.cpu.Config.Hooks.Action {
                    _ = cause;

                    const this: *Cpu = @ptrCast(@alignCast(ctx));
                    const state: *@This() = @fieldParentPtr("cpu", this);

                    state.over = true;

                    return .skip;
                }
            };

            var ram = std.mem.zeroes([std.math.pow(usize, 2, 12)]u8);
            var state: State = .{
                .cpu = .init(&ram),
            };

            state.cpu.registers.mstatus.fs = 0b01;
            state.cpu.loadElf(allocator, PROGRAM, 0) catch |err| {
                std.debug.print("failed to load the program: {t}\n", .{err});

                return false;
            };

            std.mem.doNotOptimizeAway(&state);
            std.mem.doNotOptimizeAway(&state.cpu);
            std.mem.doNotOptimizeAway(&ram);

            r.begin() catch unreachable;

            while (!state.over) {
                const step_state = state.cpu.step();
                std.mem.doNotOptimizeAway(&step_state);

                switch (step_state) {
                    .ok => continue,
                    .trap => |i| {
                        std.debug.print("unexpected trap: {any}\n", .{i.cause});

                        return false;
                    },
                    .halt => {
                        std.debug.print("unexpected halt\n", .{});

                        return false;
                    },
                }
            }

            r.end(state.cpu.registers.instret) catch unreachable;

            return true;
        }
    }.func;
}
