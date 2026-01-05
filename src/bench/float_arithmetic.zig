// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const crt0 = @import("env/crt0.zig");
const riscv32 = @import("env/riscv32.zig");

export fn main() void {
    var a: f32 = 1.5;
    var b: f32 = 2.5;
    var c: f64 = 3.5;
    var d: f64 = 4.5;

    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        a = a + b;
        b = a - b;
        a = a * b;
        b = a / b;

        c = c + d;
        d = c - d;
        c = c * d;
        d = c / d;
    }

    const result: u32 = @intFromFloat(a + @as(f32, @floatCast(c)));
    _ = riscv32.syscall1(1, result);
}

comptime {
    _ = crt0;
}
