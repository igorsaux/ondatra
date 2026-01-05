// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const crt0 = @import("env/crt0.zig");
const riscv32 = @import("env/riscv32.zig");

fn fibonacciRecursive(n: u32) u32 {
    if (n <= 1) {
        return n;
    }

    return fibonacciRecursive(n - 1) + fibonacciRecursive(n - 2);
}

export fn main() void {
    const n = 10;
    const result = fibonacciRecursive(n);

    _ = riscv32.syscall1(1, result);
}

comptime {
    _ = crt0;
}
