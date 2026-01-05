// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

pub inline fn syscall0(number: u32) u32 {
    return asm volatile ("ecall"
        : [ret] "={a0}" (-> u32),
        : [number] "{a7}" (number),
        : .{ .memory = true });
}

pub inline fn syscall1(number: u32, a0: u32) u32 {
    return asm volatile ("ecall"
        : [ret] "={a0}" (-> u32),
        : [number] "{a7}" (number),
          [arg0] "{a0}" (a0),
        : .{ .memory = true });
}

pub inline fn syscall2(number: u32, a0: u32, a1: u32) u32 {
    return asm volatile ("ecall"
        : [ret] "={a0}" (-> u32),
        : [number] "{a7}" (number),
          [arg0] "{a0}" (a0),
          [arg1] "{a1}" (a1),
        : .{ .memory = true });
}

pub inline fn syscall3(number: u32, a0: u32, a1: u32, a2: u32) u32 {
    return asm volatile ("ecall"
        : [ret] "={a0}" (-> u32),
        : [number] "{a7}" (number),
          [arg0] "{a0}" (a0),
          [arg1] "{a1}" (a1),
          [arg2] "{a2}" (a2),
        : .{ .memory = true });
}

pub inline fn syscall4(number: u32, a0: u32, a1: u32, a2: u32, a3: u32) u32 {
    return asm volatile ("ecall"
        : [ret] "={a0}" (-> u32),
        : [number] "{a7}" (number),
          [arg0] "{a0}" (a0),
          [arg1] "{a1}" (a1),
          [arg2] "{a2}" (a2),
          [arg3] "{a3}" (a3),
        : .{ .memory = true });
}

pub inline fn syscall5(number: u32, a0: u32, a1: u32, a2: u32, a3: u32, a4: u32) u32 {
    return asm volatile ("ecall"
        : [ret] "={a0}" (-> u32),
        : [number] "{a7}" (number),
          [arg0] "{a0}" (a0),
          [arg1] "{a1}" (a1),
          [arg2] "{a2}" (a2),
          [arg3] "{a3}" (a3),
          [arg4] "{a4}" (a4),
        : .{ .memory = true });
}

pub inline fn syscall6(number: u32, a0: u32, a1: u32, a2: u32, a3: u32, a4: u32, a5: u32) u32 {
    return asm volatile ("ecall"
        : [ret] "={a0}" (-> u32),
        : [number] "{a7}" (number),
          [arg0] "{a0}" (a0),
          [arg1] "{a1}" (a1),
          [arg2] "{a2}" (a2),
          [arg3] "{a3}" (a3),
          [arg4] "{a4}" (a4),
          [arg5] "{a5}" (a5),
        : .{ .memory = true });
}
