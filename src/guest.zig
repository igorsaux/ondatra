// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const arch = @import("arch.zig");

pub const Csr = struct {
    pub inline fn read(comptime csr: arch.Registers.Csr) u32 {
        return asm volatile ("csrr %[ret], %[csr]"
            : [ret] "=r" (-> u32),
            : [csr] "i" (@intFromEnum(csr)),
            : .{ .memory = true });
    }

    pub inline fn write(comptime csr: arch.Registers.Csr, value: u32) void {
        asm volatile ("csrw %[csr], %[val]"
            :
            : [csr] "i" (@intFromEnum(csr)),
              [val] "r" (value),
            : .{ .memory = true });
    }

    pub inline fn set(comptime csr: arch.Registers.Csr, mask: u32) void {
        asm volatile ("csrs %[csr], %[mask]"
            :
            : [csr] "i" (@intFromEnum(csr)),
              [mask] "r" (mask),
            : .{ .memory = true });
    }

    pub inline fn clear(comptime csr: arch.Registers.Csr, mask: u32) void {
        asm volatile ("csrc %[csr], %[mask]"
            :
            : [csr] "i" (@intFromEnum(csr)),
              [mask] "r" (mask),
            : .{ .memory = true });
    }

    pub inline fn readWrite(comptime csr: arch.Registers.Csr, value: u32) u32 {
        return asm volatile ("csrrw %[ret], %[csr], %[val]"
            : [ret] "=r" (-> u32),
            : [csr] "i" (@intFromEnum(csr)),
              [val] "r" (value),
            : .{ .memory = true });
    }

    pub inline fn readSet(comptime csr: arch.Registers.Csr, mask: u32) u32 {
        return asm volatile ("csrrs %[ret], %[csr], %[mask]"
            : [ret] "=r" (-> u32),
            : [csr] "i" (@intFromEnum(csr)),
              [mask] "r" (mask),
            : .{ .memory = true });
    }

    pub inline fn readClear(comptime csr: arch.Registers.Csr, mask: u32) u32 {
        return asm volatile ("csrrc %[ret], %[csr], %[mask]"
            : [ret] "=r" (-> u32),
            : [csr] "i" (@intFromEnum(csr)),
              [mask] "r" (mask),
            : .{ .memory = true });
    }
};

pub const Mstatus = struct {
    pub const FsState = enum(u2) {
        off = 0b00,
        initial = 0b01,
        clean = 0b10,
        dirty = 0b11,
    };

    // Bit masks
    pub const SIE: u32 = 1 << 1;
    pub const MIE: u32 = 1 << 3;
    pub const SPIE: u32 = 1 << 5;
    pub const UBE: u32 = 1 << 6;
    pub const MPIE: u32 = 1 << 7;
    pub const SPP: u32 = 1 << 8;
    pub const VS: u32 = 0b11 << 9;
    pub const MPP: u32 = 0b11 << 11;
    pub const FS: u32 = 0b11 << 13;
    pub const XS: u32 = 0b11 << 15;
    pub const MPRV: u32 = 1 << 17;
    pub const SUM: u32 = 1 << 18;
    pub const MXR: u32 = 1 << 19;
    pub const TVM: u32 = 1 << 20;
    pub const TW: u32 = 1 << 21;
    pub const TSR: u32 = 1 << 22;
    pub const SD: u32 = 1 << 31;

    // Bit shifts
    pub const VS_SHIFT: u5 = 9;
    pub const MPP_SHIFT: u5 = 11;
    pub const FS_SHIFT: u5 = 13;
    pub const XS_SHIFT: u5 = 15;

    pub inline fn read() arch.Registers.Mstatus {
        return @bitCast(Csr.read(.mstatus));
    }

    pub inline fn write(value: arch.Registers.Mstatus) void {
        Csr.write(.mstatus, @bitCast(value));
    }

    pub inline fn raw() u32 {
        return Csr.read(.mstatus);
    }

    pub inline fn writeRaw(value: u32) void {
        Csr.write(.mstatus, value);
    }

    pub inline fn getFs() FsState {
        return @enumFromInt(read().fs);
    }

    pub inline fn setFs(state: FsState) void {
        var val = read();
        val.fs = @intFromEnum(state);
        write(val);
    }

    pub inline fn enableFpu() void {
        setFs(.initial);
    }

    pub inline fn disableFpu() void {
        setFs(.off);
    }

    pub inline fn isFpuEnabled() bool {
        return getFs() != .off;
    }

    pub inline fn isFpuDirty() bool {
        return getFs() == .dirty;
    }

    pub inline fn markFpuDirty() void {
        setFs(.dirty);
    }

    pub inline fn markFpuClean() void {
        setFs(.clean);
    }

    pub inline fn getMie() bool {
        return read().mie;
    }

    pub inline fn setMie() void {
        Csr.set(.mstatus, MIE);
    }

    pub inline fn clearMie() void {
        Csr.clear(.mstatus, MIE);
    }

    // MPIE - Machine Previous Interrupt Enable
    pub inline fn getMpie() bool {
        return read().mpie;
    }

    pub inline fn setMpie() void {
        Csr.set(.mstatus, MPIE);
    }

    pub inline fn clearMpie() void {
        Csr.clear(.mstatus, MPIE);
    }

    // MPP - Machine Previous Privilege
    pub inline fn getMpp() arch.PrivilegeLevel {
        return @enumFromInt(read().mpp);
    }

    pub inline fn setMpp(mode: arch.PrivilegeLevel) void {
        var val = read();

        val.mpp = @intFromEnum(mode);
        write(val);
    }

    // MPRV - Modify Privilege
    pub inline fn getMprv() bool {
        return read().mprv;
    }

    pub inline fn setMprv() void {
        Csr.set(.mstatus, MPRV);
    }

    pub inline fn clearMprv() void {
        Csr.clear(.mstatus, MPRV);
    }

    // TW - Timeout Wait (trap WFI from lower privilege)
    pub inline fn getTw() bool {
        return read().tw;
    }

    pub inline fn setTw() void {
        Csr.set(.mstatus, TW);
    }

    pub inline fn clearTw() void {
        Csr.clear(.mstatus, TW);
    }

    pub inline fn getSd() bool {
        return read().sd;
    }

    pub inline fn initWithFpu() void {
        write(.{
            .mie = false,
            .mpie = false,
            .mpp = @intFromEnum(arch.PrivilegeLevel.machine),
            .fs = @intFromEnum(FsState.initial),
        });
    }

    pub inline fn prepareUserModeWithFpu() void {
        var val = read();
        val.mpp = @intFromEnum(arch.PrivilegeLevel.user);
        val.mpie = true;
        val.fs = @intFromEnum(FsState.initial);

        write(val);
    }
};

pub const Mie = struct {
    // Bit masks
    pub const MSIE: u32 = 1 << 3;
    pub const MTIE: u32 = 1 << 7;
    pub const MEIE: u32 = 1 << 11;

    pub inline fn read() arch.Registers.Mie {
        return @bitCast(Csr.read(.mie));
    }

    pub inline fn write(value: arch.Registers.Mie) void {
        Csr.write(.mie, @bitCast(value));
    }

    pub inline fn raw() u32 {
        return Csr.read(.mie);
    }

    pub inline fn writeRaw(value: u32) void {
        Csr.write(.mie, value);
    }

    // MSIE - Machine Software Interrupt Enable
    pub inline fn getMsie() bool {
        return read().msie;
    }

    pub inline fn setMsie() void {
        Csr.set(.mie, MSIE);
    }

    pub inline fn clearMsie() void {
        Csr.clear(.mie, MSIE);
    }

    // MTIE - Machine Timer Interrupt Enable
    pub inline fn getMtie() bool {
        return read().mtie;
    }

    pub inline fn setMtie() void {
        Csr.set(.mie, MTIE);
    }

    pub inline fn clearMtie() void {
        Csr.clear(.mie, MTIE);
    }

    // MEIE - Machine External Interrupt Enable
    pub inline fn getMeie() bool {
        return read().meie;
    }

    pub inline fn setMeie() void {
        Csr.set(.mie, MEIE);
    }

    pub inline fn clearMeie() void {
        Csr.clear(.mie, MEIE);
    }

    // Enable all machine interrupts
    pub inline fn enableAll() void {
        Csr.set(.mie, MSIE | MTIE | MEIE);
    }

    // Disable all machine interrupts
    pub inline fn disableAll() void {
        Csr.clear(.mie, MSIE | MTIE | MEIE);
    }
};

pub const Mip = struct {
    // Bit masks
    pub const MSIP: u32 = 1 << 3;
    pub const MTIP: u32 = 1 << 7;
    pub const MEIP: u32 = 1 << 11;

    pub inline fn read() arch.Registers.Mip {
        return @bitCast(Csr.read(.mip));
    }

    pub inline fn raw() u32 {
        return Csr.read(.mip);
    }

    // Note: Most MIP bits are read-only, set by hardware

    pub inline fn getMsip() bool {
        return read().msip;
    }

    pub inline fn getMtip() bool {
        return read().mtip;
    }

    pub inline fn getMeip() bool {
        return read().meip;
    }

    pub inline fn setMsip() void {
        Csr.set(.mip, MSIP);
    }

    pub inline fn clearMsip() void {
        Csr.clear(.mip, MSIP);
    }

    pub inline fn anyPending() bool {
        return (raw() & (MSIP | MTIP | MEIP)) != 0;
    }
};

pub const Mtvec = struct {
    pub const Value = packed struct(u32) {
        mode: u2,
        base: u30,

        pub fn address(self: Value) u32 {
            return @as(u32, self.base) << 2;
        }
    };

    pub inline fn read() Value {
        return @bitCast(Csr.read(.mtvec));
    }

    pub inline fn write(value: Value) void {
        Csr.write(.mtvec, @bitCast(value));
    }

    pub inline fn raw() u32 {
        return Csr.read(.mtvec);
    }

    pub inline fn writeRaw(value: u32) void {
        Csr.write(.mtvec, value);
    }

    pub inline fn getBase() u32 {
        return read().address();
    }

    pub inline fn getMode() arch.Registers.Mtvec.Mode {
        return @enumFromInt(read().mode);
    }

    pub inline fn setDirect(base: u32) void {
        write(.{
            .mode = @intFromEnum(arch.Registers.Mtvec.Mode.direct),
            .base = @truncate(base >> 2),
        });
    }

    pub inline fn setVectored(base: u32) void {
        write(.{
            .mode = @intFromEnum(arch.Registers.Mtvec.Mode.vectored),
            .base = @truncate(base >> 2),
        });
    }
};

pub const Mepc = struct {
    pub inline fn read() u32 {
        return Csr.read(.mepc);
    }

    pub inline fn write(value: u32) void {
        Csr.write(.mepc, value);
    }

    pub inline fn get() u32 {
        return read();
    }

    pub inline fn set(pc: u32) void {
        write(pc);
    }

    // Advance PC to next instruction (for exception handling)
    pub inline fn advance(instruction_len: u32) void {
        write(read() + instruction_len);
    }

    pub inline fn advance2() void {
        advance(2);
    }

    pub inline fn advance4() void {
        advance(4);
    }
};

pub const Mcause = struct {
    pub inline fn read() arch.Registers.Mcause {
        return @bitCast(Csr.read(.mcause));
    }

    pub inline fn write(value: arch.Registers.Mcause) void {
        Csr.write(.mcause, @bitCast(value));
    }

    pub inline fn raw() u32 {
        return Csr.read(.mcause);
    }

    pub inline fn writeRaw(value: u32) void {
        Csr.write(.mcause, value);
    }

    pub inline fn isInterrupt() bool {
        return read().interrupt;
    }

    pub inline fn isException() bool {
        return !read().interrupt;
    }

    pub inline fn getCode() u31 {
        return read().code;
    }

    pub inline fn getExceptionCode() arch.Registers.Mcause.Exception {
        return @enumFromInt(read().code);
    }

    pub inline fn getInterruptCode() arch.Registers.Mcause.Interrupt {
        return @enumFromInt(read().code);
    }

    pub inline fn setException(code: arch.Registers.Mcause.Exception) void {
        write(.{
            .code = @intFromEnum(code),
            .interrupt = false,
        });
    }

    pub inline fn setInterrupt(code: arch.Registers.Mcause.Interrupt) void {
        write(.{
            .code = @intFromEnum(code),
            .interrupt = true,
        });
    }
};

pub const Mtval = struct {
    pub inline fn read() u32 {
        return Csr.read(.mtval);
    }

    pub inline fn write(value: u32) void {
        Csr.write(.mtval, value);
    }

    pub inline fn get() u32 {
        return read();
    }

    pub inline fn set(value: u32) void {
        write(value);
    }

    // For address-related exceptions (misaligned, access fault, page fault)
    pub inline fn getFaultingAddress() u32 {
        return read();
    }

    // For illegal instruction exception
    pub inline fn getIllegalInstruction() u32 {
        return read();
    }
};

pub const Mscratch = struct {
    pub inline fn read() u32 {
        return Csr.read(.mscratch);
    }

    pub inline fn write(value: u32) void {
        Csr.write(.mscratch, value);
    }

    pub inline fn get() u32 {
        return read();
    }

    pub inline fn set(value: u32) void {
        write(value);
    }

    // Swap with register (useful for trap entry)
    pub inline fn swap(value: u32) u32 {
        return Csr.readWrite(.mscratch, value);
    }
};

pub const Misa = struct {
    pub const Value = packed struct(u32) {
        extensions: u26,
        _reserved: u4 = 0,
        mxl: u2, // Machine XLEN (1=32, 2=64, 3=128)
    };

    pub const Extension = enum(u5) {
        A = 0, // Atomic
        B = 1, // Bit manipulation
        C = 2, // Compressed
        D = 3, // Double-precision FP
        E = 4, // RV32E base
        F = 5, // Single-precision FP
        G = 6, // Reserved
        H = 7, // Hypervisor
        I = 8, // RV32I/64I/128I base
        J = 9, // Reserved
        K = 10, // Reserved
        L = 11, // Reserved
        M = 12, // Integer Multiply/Divide
        N = 13, // User-level interrupts
        O = 14, // Reserved
        P = 15, // Packed-SIMD
        Q = 16, // Quad-precision FP
        R = 17, // Reserved
        S = 18, // Supervisor mode
        T = 19, // Reserved
        U = 20, // User mode
        V = 21, // Vector
        W = 22, // Reserved
        X = 23, // Non-standard extensions
        Y = 24, // Reserved
        Z = 25, // Reserved
    };

    pub inline fn read() Value {
        return @bitCast(Csr.read(.misa));
    }

    pub inline fn raw() u32 {
        return Csr.read(.misa);
    }

    pub inline fn hasExtension(ext: Extension) bool {
        return (read().extensions & (@as(u26, 1) << @intFromEnum(ext))) != 0;
    }

    pub inline fn hasAtomic() bool {
        return hasExtension(.A);
    }

    pub inline fn hasCompressed() bool {
        return hasExtension(.C);
    }

    pub inline fn hasMultiply() bool {
        return hasExtension(.M);
    }

    pub inline fn hasFloat() bool {
        return hasExtension(.F);
    }

    pub inline fn hasDouble() bool {
        return hasExtension(.D);
    }

    pub inline fn hasUserMode() bool {
        return hasExtension(.U);
    }

    pub inline fn hasSupervisorMode() bool {
        return hasExtension(.S);
    }

    pub inline fn getXlen() u2 {
        return read().mxl;
    }
};

pub const Mvendorid = struct {
    pub inline fn read() u32 {
        return Csr.read(.mvendorid);
    }
};

pub const Marchid = struct {
    pub inline fn read() u32 {
        return Csr.read(.marchid);
    }
};

pub const Mimpid = struct {
    pub inline fn read() u32 {
        return Csr.read(.mimpid);
    }
};

pub const Mhartid = struct {
    pub inline fn read() u32 {
        return Csr.read(.mhartid);
    }
};

pub const Mcounteren = struct {
    pub const CY: u32 = 1 << 0;
    pub const TM: u32 = 1 << 1;
    pub const IR: u32 = 1 << 2;

    pub inline fn read() arch.Registers.Mcounteren {
        return @bitCast(Csr.read(.mcounteren));
    }

    pub inline fn write(value: arch.Registers.Mcounteren) void {
        Csr.write(.mcounteren, @bitCast(value));
    }

    pub inline fn raw() u32 {
        return Csr.read(.mcounteren);
    }

    pub inline fn writeRaw(value: u32) void {
        Csr.write(.mcounteren, value);
    }

    // Enable U-mode access to cycle counter
    pub inline fn enableCycle() void {
        Csr.set(.mcounteren, CY);
    }

    pub inline fn disableCycle() void {
        Csr.clear(.mcounteren, CY);
    }

    // Enable U-mode access to time
    pub inline fn enableTime() void {
        Csr.set(.mcounteren, TM);
    }

    pub inline fn disableTime() void {
        Csr.clear(.mcounteren, TM);
    }

    // Enable U-mode access to instret
    pub inline fn enableInstret() void {
        Csr.set(.mcounteren, IR);
    }

    pub inline fn disableInstret() void {
        Csr.clear(.mcounteren, IR);
    }

    // Enable all counters for U-mode
    pub inline fn enableAll() void {
        Csr.set(.mcounteren, CY | TM | IR);
    }

    pub inline fn disableAll() void {
        Csr.clear(.mcounteren, CY | TM | IR);
    }
};

pub const Mcycle = struct {
    pub inline fn read() u32 {
        return Csr.read(.mcycle);
    }

    pub inline fn write(value: u32) void {
        Csr.write(.mcycle, value);
    }

    pub inline fn readHigh() u32 {
        return Csr.read(.mcycleh);
    }

    pub inline fn writeHigh(value: u32) void {
        Csr.write(.mcycleh, value);
    }

    // Read full 64-bit value (handles rollover)
    pub inline fn read64() u64 {
        while (true) {
            const hi1 = readHigh();
            const lo = read();
            const hi2 = readHigh();

            if (hi1 == hi2) {
                return (@as(u64, hi1) << 32) | lo;
            }
        }
    }

    pub inline fn write64(value: u64) void {
        writeHigh(@truncate(value >> 32));
        write(@truncate(value));
    }
};

pub const Minstret = struct {
    pub inline fn read() u32 {
        return Csr.read(.minstret);
    }

    pub inline fn write(value: u32) void {
        Csr.write(.minstret, value);
    }

    pub inline fn readHigh() u32 {
        return Csr.read(.minstreth);
    }

    pub inline fn writeHigh(value: u32) void {
        Csr.write(.minstreth, value);
    }

    pub inline fn read64() u64 {
        while (true) {
            const hi1 = readHigh();
            const lo = read();
            const hi2 = readHigh();

            if (hi1 == hi2) {
                return (@as(u64, hi1) << 32) | lo;
            }
        }
    }

    pub inline fn write64(value: u64) void {
        writeHigh(@truncate(value >> 32));
        write(@truncate(value));
    }
};

pub const Pmp = struct {
    // Read pmpcfg registers
    pub inline fn readCfg0() u32 {
        return Csr.read(.pmpcfg0);
    }

    pub inline fn readCfg1() u32 {
        return Csr.read(.pmpcfg1);
    }

    pub inline fn readCfg2() u32 {
        return Csr.read(.pmpcfg2);
    }

    pub inline fn readCfg3() u32 {
        return Csr.read(.pmpcfg3);
    }

    pub inline fn writeCfg0(value: u32) void {
        Csr.write(.pmpcfg0, value);
    }

    pub inline fn writeCfg1(value: u32) void {
        Csr.write(.pmpcfg1, value);
    }

    pub inline fn writeCfg2(value: u32) void {
        Csr.write(.pmpcfg2, value);
    }

    pub inline fn writeCfg3(value: u32) void {
        Csr.write(.pmpcfg3, value);
    }

    // Get config for specific entry (0-15)
    pub inline fn getConfig(index: u4) arch.Registers.PmpCfg {
        const cfg_reg = index >> 2;
        const byte_idx = index & 0b11;

        const raw = switch (cfg_reg) {
            0 => readCfg0(),
            1 => readCfg1(),
            2 => readCfg2(),
            3 => readCfg3(),
        };

        return @bitCast(@as(u8, @truncate(raw >> (@as(u5, byte_idx) * 8))));
    }

    // Set config for specific entry (0-15)
    pub inline fn setConfig(index: u4, config: arch.Registers.PmpCfg) void {
        const cfg_reg = index >> 2;
        const byte_idx: u5 = index & 0b11;
        const shift = byte_idx * 8;
        const mask = ~(@as(u32, 0xFF) << shift);
        const new_val = @as(u32, @as(u8, @bitCast(config))) << shift;

        switch (cfg_reg) {
            0 => writeCfg0((readCfg0() & mask) | new_val),
            1 => writeCfg1((readCfg1() & mask) | new_val),
            2 => writeCfg2((readCfg2() & mask) | new_val),
            3 => writeCfg3((readCfg3() & mask) | new_val),
        }
    }

    // Address register operations
    pub inline fn readAddr(comptime index: u4) u32 {
        const addr = comptime @as(arch.Registers.Csr, @enumFromInt(@intFromEnum(arch.Registers.Csr.pmpaddr0) + index));

        return Csr.read(addr);
    }

    pub inline fn writeAddr(comptime index: u4, value: u32) void {
        const addr = comptime @as(arch.Registers.Csr, @enumFromInt(@intFromEnum(arch.Registers.Csr.pmpaddr0) + index));

        Csr.write(addr, value);
    }

    pub inline fn napotAddr(base: u32, size: u32) u32 {
        return (base >> 2) | ((size >> 3) - 1);
    }

    pub fn configureNapot(
        comptime index: u4,
        base: u32,
        size: u32,
        config: arch.Registers.PmpCfg,
    ) void {
        writeAddr(index, napotAddr(base, size));

        var cfg = config;
        cfg.a = .napot;

        setConfig(index, cfg);
    }

    pub fn configureTor(
        comptime index: u4,
        top: u32,
        config: arch.Registers.PmpCfg,
    ) void {
        writeAddr(index, top >> 2);

        var cfg = config;
        cfg.a = .tor;

        setConfig(index, cfg);
    }
};

pub const Cycle = struct {
    pub inline fn read() u32 {
        return Csr.read(.cycle);
    }

    pub inline fn readHigh() u32 {
        return Csr.read(.cycleh);
    }

    pub inline fn read64() u64 {
        while (true) {
            const hi1 = readHigh();
            const lo = read();
            const hi2 = readHigh();

            if (hi1 == hi2) {
                return (@as(u64, hi1) << 32) | lo;
            }
        }
    }
};

pub const Time = struct {
    pub inline fn read() u32 {
        return Csr.read(.time);
    }

    pub inline fn readHigh() u32 {
        return Csr.read(.timeh);
    }

    pub inline fn read64() u64 {
        while (true) {
            const hi1 = readHigh();
            const lo = read();
            const hi2 = readHigh();

            if (hi1 == hi2) {
                return (@as(u64, hi1) << 32) | lo;
            }
        }
    }
};

pub const Instret = struct {
    pub inline fn read() u32 {
        return Csr.read(.instret);
    }

    pub inline fn readHigh() u32 {
        return Csr.read(.instreth);
    }

    pub inline fn read64() u64 {
        while (true) {
            const hi1 = readHigh();
            const lo = read();
            const hi2 = readHigh();

            if (hi1 == hi2) {
                return (@as(u64, hi1) << 32) | lo;
            }
        }
    }
};

pub inline fn wfi() void {
    asm volatile ("wfi" ::: .{ .memory = true });
}

pub inline fn mret() noreturn {
    asm volatile ("mret" ::: .{ .memory = true });
    unreachable;
}

pub inline fn ecall() void {
    asm volatile ("ecall" ::: .{ .memory = true });
}

pub inline fn ebreak() void {
    asm volatile ("ebreak" ::: .{ .memory = true });
}

pub inline fn fence() void {
    asm volatile ("fence" ::: .{ .memory = true });
}

pub inline fn fenceI() void {
    asm volatile ("fence.i" ::: .{ .memory = true });
}

// Disable interrupts and return previous state
pub inline fn disableInterrupts() bool {
    const prev = Mstatus.getMie();
    Mstatus.clearMie();

    return prev;
}

// Restore interrupt state
pub inline fn restoreInterrupts(prev: bool) void {
    if (prev) {
        Mstatus.setMie();
    }
}

pub const Fcsr = struct {
    pub const Value = packed struct(u32) {
        /// Accrued exception flags
        fflags: arch.Registers.Fcsr = .{},
        frm: arch.Registers.Fcsr.RoundingMode = .rne,
        _reserved: u24 = 0,
    };

    // Bit positions and masks
    pub const FFLAGS_MASK: u32 = 0x1F;
    pub const FRM_MASK: u32 = 0x07 << 5;
    pub const FRM_SHIFT: u5 = 5;

    pub inline fn read() Value {
        return @bitCast(Csr.read(.fcsr));
    }

    pub inline fn write(value: Value) void {
        Csr.write(.fcsr, @bitCast(value));
    }

    pub inline fn raw() u32 {
        return Csr.read(.fcsr);
    }

    pub inline fn writeRaw(value: u32) void {
        Csr.write(.fcsr, value);
    }

    pub inline fn getRoundingMode() arch.Registers.Fcsr.RoundingMode {
        return read().frm;
    }

    pub inline fn setRoundingMode(mode: arch.Registers.Fcsr.RoundingMode) void {
        var val = read();
        val.frm = mode;

        write(val);
    }

    /// Set rounding mode and return previous
    pub inline fn swapRoundingMode(mode: arch.Registers.Fcsr.RoundingMode) arch.Registers.Fcsr.RoundingMode {
        const prev = read();

        var val = prev;
        val.frm = mode;

        write(val);

        return prev.frm;
    }

    pub inline fn getFlags() arch.Registers.Fcsr {
        return read().fflags;
    }

    pub inline fn setFlags(flags: arch.Registers.Fcsr) void {
        var val = read();

        val.fflags = flags;
        write(val);
    }

    pub inline fn clearFlags() void {
        Csr.clear(.fcsr, FFLAGS_MASK);
    }

    /// Read flags and clear them atomically
    pub inline fn readAndClearFlags() arch.Registers.Fcsr {
        const prev = Csr.readClear(.fcsr, FFLAGS_MASK);

        return @bitCast(@as(u5, @truncate(prev)));
    }

    pub inline fn isInexact() bool {
        return getFlags().nx;
    }

    pub inline fn isUnderflow() bool {
        return getFlags().uf;
    }

    pub inline fn isOverflow() bool {
        return getFlags().of;
    }

    pub inline fn isDivideByZero() bool {
        return getFlags().dz;
    }

    pub inline fn isInvalidOperation() bool {
        return getFlags().nv;
    }

    pub inline fn hasAnyException() bool {
        return getFlags().any();
    }

    /// Initialize FCSR to default state
    pub inline fn init() void {
        write(.{
            .fflags = .{},
            .frm = .rne,
        });
    }
};

pub const Fflags = struct {
    pub inline fn read() arch.Registers.Fcsr {
        return @bitCast(@as(u5, @truncate(Csr.read(.fflags))));
    }

    pub inline fn write(flags: arch.Registers.Fcsr) void {
        Csr.write(.fflags, @as(u5, @bitCast(flags)));
    }

    pub inline fn raw() u5 {
        return @truncate(Csr.read(.fflags));
    }

    pub inline fn writeRaw(value: u5) void {
        Csr.write(.fflags, value);
    }

    pub inline fn clear() void {
        Csr.write(.fflags, 0);
    }

    /// Read and clear atomically
    pub inline fn readAndClear() arch.Registers.Fcsr {
        const prev = Csr.readClear(.fflags, arch.Registers.Fcsr.ALL);
        return @bitCast(@as(u5, @truncate(prev)));
    }

    /// Set specific flag
    pub inline fn raise(comptime flag: enum { nx, uf, of, dz, nv }) void {
        const mask: u32 = switch (flag) {
            .nx => arch.Registers.Fcsr.NX,
            .uf => arch.Registers.Fcsr.UF,
            .of => arch.Registers.Fcsr.OF,
            .dz => arch.Registers.Fcsr.DZ,
            .nv => arch.Registers.Fcsr.NV,
        };

        Csr.set(.fflags, mask);
    }

    /// Check specific flag
    pub inline fn isSet(comptime flag: enum { nx, uf, of, dz, nv }) bool {
        return @field(read(), @tagName(flag));
    }
};

pub const Frm = struct {
    pub inline fn read() arch.Registers.Fcsr.RoundingMode {
        return @enumFromInt(@as(u3, @truncate(Csr.read(.frm))));
    }

    pub inline fn write(mode: arch.Registers.Fcsr.RoundingMode) void {
        Csr.write(.frm, @intFromEnum(mode));
    }

    pub inline fn raw() u3 {
        return @truncate(Csr.read(.frm));
    }

    pub inline fn writeRaw(value: u3) void {
        Csr.write(.frm, value);
    }

    /// Common rounding mode setters
    pub inline fn setRoundToNearest() void {
        write(.rne);
    }

    pub inline fn setRoundToZero() void {
        write(.rtz);
    }

    pub inline fn setRoundDown() void {
        write(.rdn);
    }

    pub inline fn setRoundUp() void {
        write(.rup);
    }

    /// Check current mode
    pub inline fn isRoundToNearest() bool {
        return read() == .rne;
    }

    pub inline fn isRoundToZero() bool {
        return read() == .rtz;
    }
};
