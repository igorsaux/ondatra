// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

var stack: [std.math.pow(usize, 2, 10)]u8 align(16) linksection(".bss") = undefined;

extern fn main() void;

export fn _start() callconv(.naked) noreturn {
    asm volatile (
        \\ la sp, %[stack_start]
        \\ j %[main]
        :
        : [stack_start] "i" (&@as([*]align(16) u8, @ptrCast(&stack))[stack.len]),
          [main] "i" (&main),
    );

    while (true) {}
}
