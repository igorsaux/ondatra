const std = @import("std");
const builtin = @import("builtin");

const jit = @import("../jit.zig");
const EngineConfig = @import("engine_config.zig").EngineConfig;

pub const Arch = enum {
    aarch64,
    x86_64,
    current,
};

pub inline fn Compiler(comptime arch: Arch, comptime config: EngineConfig) type {
    return switch (arch) {
        .aarch64 => @import("compiler/aarch64.zig").Compiler(config),
        .x86_64 => @import("compiler/x86_64.zig").Compiler(config),
        .current => return switch (builtin.cpu.arch) {
            .aarch64 => @import("compiler/aarch64.zig").Compiler(config),
            .x86_64 => @import("compiler/x86_64.zig").Compiler(config),
            else => @compileError("Unsupported architecture " ++ builtin.cpu.arch),
        },
    };
}
