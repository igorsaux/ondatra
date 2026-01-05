// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const crt0 = @import("env/crt0.zig");
const riscv32 = @import("env/riscv32.zig");

export fn main() void {
    var sum_f32: f32 = 0.0;
    var sum_f64: f64 = 0.0;

    var i: u32 = 1;

    while (i <= 50) : (i += 1) {
        const x_f32: f32 = @floatFromInt(i);
        const x_f64: f64 = @floatFromInt(i);

        const sqrt_f32 = @sqrt(x_f32);
        const sqrt_f64 = @sqrt(x_f64);

        sum_f32 = @mulAdd(f32, sqrt_f32, x_f32, sum_f32);
        sum_f64 = @mulAdd(f64, sqrt_f64, x_f64, sum_f64);
    }

    const result: u32 = @intFromFloat(sum_f32 + @as(f32, @floatCast(sum_f64)));
    _ = riscv32.syscall1(1, result);
}

comptime {
    _ = crt0;
}
