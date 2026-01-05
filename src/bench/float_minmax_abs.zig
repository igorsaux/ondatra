// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const crt0 = @import("env/crt0.zig");
const riscv32 = @import("env/riscv32.zig");

export fn main() void {
    var result_f32: f32 = 0.0;
    var result_f64: f64 = 0.0;

    var i: i32 = -50;

    while (i <= 50) : (i += 1) {
        const x_f32: f32 = @floatFromInt(i);
        const y_f32: f32 = @floatFromInt(i * 2 - 25);
        const x_f64: f64 = @floatFromInt(i);
        const y_f64: f64 = @floatFromInt(i * 2 - 25);

        const min_f32 = @min(x_f32, y_f32);
        const max_f32 = @max(x_f32, y_f32);
        const abs_f32 = @abs(x_f32);

        result_f32 += min_f32 + max_f32 + abs_f32;

        const min_f64 = @min(x_f64, y_f64);
        const max_f64 = @max(x_f64, y_f64);
        const abs_f64 = @abs(x_f64);

        result_f64 += min_f64 + max_f64 + abs_f64;

        result_f32 += -abs_f32;
        result_f64 += -abs_f64;
    }

    const result: u32 = @intFromFloat(@abs(result_f32) + @as(f32, @floatCast(@abs(result_f64))));
    _ = riscv32.syscall1(1, result);
}

comptime {
    _ = crt0;
}
