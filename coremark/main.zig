const std = @import("std");
const ondatra = @import("ondatra");

const SYS_EXIT = 0;
const SYS_PUTCHAR = 1;
const SYS_GET_TIME = 2;

const RAM_START: u32 = 0x80000000;
var STDERR_BUFFER: [std.math.pow(usize, 2, 20)]u8 = undefined;

const Host = struct {
    const Cpu = ondatra.cpu.Cpu(.{
        .hooks = .{
            .isMmio = isMmio,
            .readTranslate = readTranslate,
            .writeTranslate = readTranslate,
            .ecall = ecall,
        },
        .compile = .fast_execution,
        .runtime = .compliant,
    });

    cpu: Cpu,
    stderr_writer: std.fs.File.Writer,
    start_timestamp: i128,

    pub fn init(allocator: std.mem.Allocator) !Host {
        const ram: []u8 = try allocator.alloc(u8, std.math.pow(usize, 2, 24));
        const cpu: Cpu = .init(ram);
        const writer = std.fs.File.stderr().writer(&STDERR_BUFFER);

        return .{
            .cpu = cpu,
            .stderr_writer = writer,
            .start_timestamp = 0,
        };
    }

    pub fn deinit(this: *Host, allocator: std.mem.Allocator) void {
        this.stderr_writer.interface.flush() catch {};

        allocator.free(this.cpu.ram);
    }

    inline fn ecall(
        ctx: *anyopaque,
        cause: ondatra.arch.Registers.Mcause.Exception,
    ) ondatra.cpu.Config.Hooks.Action {
        _ = cause;

        const cpu: *Cpu = @ptrCast(@alignCast(ctx));
        const this: *Host = @alignCast(@fieldParentPtr("cpu", cpu));

        const syscall_num = cpu.registers.common[17]; // a7
        const arg0 = cpu.registers.common[10]; // a0

        switch (syscall_num) {
            SYS_EXIT => {
                std.debug.print("\n[Host] Program exited with code: {}\n", .{@as(i32, @bitCast(arg0))});
                std.debug.print("[Host] Total cycles: {}\n", .{cpu.registers.cycle});

                return .halt;
            },
            SYS_PUTCHAR => {
                const char: u8 = @bitCast(@as(i8, @truncate(arg0)));
                this.stderr_writer.interface.writeByte(char) catch unreachable;

                return .skip;
            },
            SYS_GET_TIME => {
                const now = std.time.nanoTimestamp();
                const elapsed_ns: i64 = @intCast(now - this.start_timestamp);

                cpu.registers.common[10] = @truncate(elapsed_ns); // a0 = lo
                cpu.registers.common[11] = @truncate(elapsed_ns >> 32); // a1 = hi

                return .skip;
            },
            else => {
                std.debug.print("[Host] Unknown syscall: {}\n", .{syscall_num});

                return .skip;
            },
        }
    }

    inline fn isMmio(ctx: *anyopaque, address: u32) bool {
        _ = ctx;

        return address < RAM_START;
    }

    inline fn readTranslate(ctx: *anyopaque, address: u32) u32 {
        _ = ctx;

        return address -% RAM_START;
    }

    inline fn writeTranslate(ctx: *anyopaque, address: u32) u32 {
        _ = ctx;

        return address -% RAM_START;
    }
};

pub fn main() !void {
    const COREMARK_GUEST = @embedFile("coremark_guest.bin");

    var alloc: std.heap.DebugAllocator(.{}) = .init;
    defer _ = alloc.deinit();

    var host: Host = try .init(alloc.allocator());
    defer host.deinit(alloc.allocator());

    try host.cpu.loadElf(alloc.allocator(), COREMARK_GUEST, RAM_START);

    const start_time = std.time.nanoTimestamp();
    host.start_timestamp = start_time;

    run: while (true) {
        switch (host.cpu.run(std.math.maxInt(usize))) {
            .ok => continue,
            .halt => {
                break :run;
            },
            .trap => |trap| {
                std.debug.print("[Host] Unexpected trap: {any}\n", .{trap});

                return;
            },
        }
    }
}
