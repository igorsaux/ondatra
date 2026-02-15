// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const crt0 = @import("env/crt0.zig");
const riscv32 = @import("env/riscv32.zig");

export fn main() void {
    var sum_f32: f32 = 0.0;

    var i: u32 = 1;

    while (i <= 500) : (i += 1) {
        const x_f32: f32 = @floatFromInt(i);
        const sqrt_f32 = @sqrt(x_f32);

        sum_f32 = @mulAdd(f32, sqrt_f32, x_f32, sum_f32);
    }

    const result: u32 = @intFromFloat(sum_f32);
    _ = riscv32.syscall1(1, result);
}

comptime {
    _ = crt0;
}
