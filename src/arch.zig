// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

pub const ENDIAN: std.builtin.Endian = .little;

pub const FloatHelpers = struct {
    pub inline fn isSignalingNanF32(val: f32) bool {
        const bits: u32 = @bitCast(val);
        const exp = (bits >> 23) & 0xFF;
        const frac = bits & 0x7FFFFF;

        // sNaN: exp=0xFF, frac!=0, MSB of frac = 0
        return exp == 0xFF and frac != 0 and (frac & 0x400000) == 0;
    }

    pub inline fn isSignalingNanF64(val: f64) bool {
        const bits: u64 = @bitCast(val);
        const exp = (bits >> 52) & 0x7FF;
        const frac = bits & 0xFFFFFFFFFFFFF;

        // sNaN: exp=0x7FF, frac!=0, MSB of frac = 0
        return exp == 0x7FF and frac != 0 and (frac & 0x8000000000000) == 0;
    }

    pub inline fn isQuietNanF32(val: f32) bool {
        const bits: u32 = @bitCast(val);
        const exp = (bits >> 23) & 0xFF;
        const frac = bits & 0x7FFFFF;

        return exp == 0xFF and frac != 0 and (frac & 0x400000) != 0;
    }

    pub inline fn isQuietNanF64(val: f64) bool {
        const bits: u64 = @bitCast(val);
        const exp = (bits >> 52) & 0x7FF;
        const frac = bits & 0xFFFFFFFFFFFFF;

        return exp == 0x7FF and frac != 0 and (frac & 0x8000000000000) != 0;
    }

    pub inline fn canonicalNanF32() f32 {
        return @bitCast(@as(u32, 0x7FC00000)); // Quiet NaN
    }

    pub inline fn canonicalNanF64() f64 {
        return @bitCast(@as(u64, 0x7FF8000000000000)); // Quiet NaN
    }

    pub inline fn isSubnormalF32(val: f32) bool {
        const bits: u32 = @bitCast(val);
        const exp = (bits >> 23) & 0xFF;
        const frac = bits & 0x7FFFFF;

        return exp == 0 and frac != 0;
    }

    pub inline fn isSubnormalF64(val: f64) bool {
        const bits: u64 = @bitCast(val);
        const exp = (bits >> 52) & 0x7FF;
        const frac = bits & 0xFFFFFFFFFFFFF;

        return exp == 0 and frac != 0;
    }

    pub inline fn isNegativeZeroF32(val: f32) bool {
        return @as(u32, @bitCast(val)) == 0x80000000;
    }

    pub inline fn isNegativeZeroF64(val: f64) bool {
        return @as(u64, @bitCast(val)) == 0x8000000000000000;
    }

    pub inline fn isPositiveZeroF32(val: f32) bool {
        return @as(u32, @bitCast(val)) == 0x00000000;
    }

    pub inline fn isPositiveZeroF64(val: f64) bool {
        return @as(u64, @bitCast(val)) == 0x0000000000000000;
    }

    /// Round to Nearest, ties to Even (IEEE 754 default rounding mode)
    pub inline fn roundToNearestEvenF32(val: f32) f32 {
        if (@abs(val) >= 8388608.0 or std.math.isNan(val) or std.math.isInf(val)) {
            return val;
        }

        const floor_val = @floor(val);
        const ceil_val = @ceil(val);

        if (floor_val == ceil_val) {
            return val;
        }

        const diff_to_floor = val - floor_val;
        const diff_to_ceil = ceil_val - val;

        if (diff_to_floor < diff_to_ceil) {
            return floor_val;
        } else if (diff_to_ceil < diff_to_floor) {
            return ceil_val;
        } else {
            const is_floor_even = @mod(floor_val, 2.0) == 0.0;

            return if (is_floor_even) floor_val else ceil_val;
        }
    }

    /// Round to Nearest, ties to Even for f64
    pub inline fn roundToNearestEvenF64(val: f64) f64 {
        if (@abs(val) >= 4503599627370496.0 or std.math.isNan(val) or std.math.isInf(val)) {
            return val;
        }

        const floor_val = @floor(val);
        const ceil_val = @ceil(val);

        if (floor_val == ceil_val) {
            return val;
        }

        const diff_to_floor = val - floor_val;
        const diff_to_ceil = ceil_val - val;

        if (diff_to_floor < diff_to_ceil) {
            return floor_val;
        } else if (diff_to_ceil < diff_to_floor) {
            return ceil_val;
        } else {
            const is_floor_even = @mod(floor_val, 2.0) == 0.0;

            return if (is_floor_even) floor_val else ceil_val;
        }
    }
};

pub const PrivilegeLevel = enum(u2) {
    user = 0b00,
    // supervisor = 0b01, // Not implemented
    machine = 0b11,
    _,

    pub inline fn sanitize(level: PrivilegeLevel) PrivilegeLevel {
        return switch (level) {
            .user => .user,
            .machine => .machine,
            _ => .machine, // Invalid values default to M-mode
        };
    }
};

pub const Registers = struct {
    pub const Csr = enum(u12) {
        pub const Error = error{
            IllegalInstruction, // Privilege violation or invalid CSR
        };

        // User-level CSRs (0x000-0x0FF)
        fflags = 0x001,
        frm = 0x002,
        fcsr = 0x003,
        // User Counter/Timers (0xC00-0xC7F) - read-only
        cycle = 0xC00,
        time = 0xC01,
        instret = 0xC02,
        cycleh = 0xC80,
        timeh = 0xC81,
        instreth = 0xC82,
        // Machine Information (0xF11-0xF14) - read-only
        mvendorid = 0xF11,
        marchid = 0xF12,
        mimpid = 0xF13,
        mhartid = 0xF14,
        // Machine Trap Setup (0x300-0x306)
        mstatus = 0x300,
        misa = 0x301,
        mie = 0x304,
        mtvec = 0x305,
        mcounteren = 0x306,
        // Machine Trap Handling (0x340-0x344)
        mscratch = 0x340,
        mepc = 0x341,
        mcause = 0x342,
        mtval = 0x343,
        mip = 0x344,
        // Machine Counter/Timers (0xB00-0xB82)
        mcycle = 0xB00,
        minstret = 0xB02,
        mcycleh = 0xB80,
        minstreth = 0xB82,
        // PMP Configuration (0x3A0-0x3A3)
        pmpcfg0 = 0x3A0,
        pmpcfg1 = 0x3A1,
        pmpcfg2 = 0x3A2,
        pmpcfg3 = 0x3A3,
        // PMP Address (0x3B0-0x3BF)
        pmpaddr0 = 0x3B0,
        pmpaddr1 = 0x3B1,
        pmpaddr2 = 0x3B2,
        pmpaddr3 = 0x3B3,
        pmpaddr4 = 0x3B4,
        pmpaddr5 = 0x3B5,
        pmpaddr6 = 0x3B6,
        pmpaddr7 = 0x3B7,
        pmpaddr8 = 0x3B8,
        pmpaddr9 = 0x3B9,
        pmpaddr10 = 0x3BA,
        pmpaddr11 = 0x3BB,
        pmpaddr12 = 0x3BC,
        pmpaddr13 = 0x3BD,
        pmpaddr14 = 0x3BE,
        pmpaddr15 = 0x3BF,
        _,

        pub inline fn getRequiredPrivilege(csr: Csr) PrivilegeLevel {
            const addr = @intFromEnum(csr);
            const priv_bits: u2 = @truncate(addr >> 8);

            return switch (priv_bits) {
                0b00, 0b01 => .user,
                0b10, 0b11 => .machine,
            };
        }

        pub inline fn isReadOnly(csr: Csr) bool {
            const addr = @intFromEnum(csr);
            const rw_bits: u2 = @truncate(addr >> 10);

            return rw_bits == 0b11;
        }
    };

    pub const Mstatus = packed struct(u32) {
        _reserved0: u1 = 0,
        sie: bool = false, // S-mode interrupt enable (not used)
        _reserved2: u1 = 0,
        mie: bool = false, // M-mode interrupt enable
        _reserved4: u1 = 0,
        spie: bool = false, // S-mode previous interrupt enable (not used)
        ube: bool = false, // U-mode big-endian
        mpie: bool = false, // M-mode previous interrupt enable
        spp: u1 = 0, // S-mode previous privilege (not used)
        vs: u2 = 0, // Vector extension state
        mpp: PrivilegeLevel = .machine, // M-mode previous privilege
        fs: u2 = 0, // Floating-point state
        xs: u2 = 0, // Extension state
        mprv: bool = false, // Modify privilege for loads/stores
        sum: bool = false, // Supervisor User Memory access (not used)
        mxr: bool = false, // Make executable readable
        tvm: bool = false, // Trap Virtual Memory (not used)
        tw: bool = false, // Timeout Wait
        tsr: bool = false, // Trap SRET (not used)
        _reserved23_30: u8 = 0,
        sd: bool = false, // State dirty summary

        // WPRI mask: bits that must preserve value on write
        pub const WPRI_MASK: u32 = 0x007F_E1E5;
        // Writable bits mask for M+U system
        pub const WRITE_MASK: u32 = 0x0000_1888; // MIE, MPIE, MPP

        pub inline fn updateSD(this: *Mstatus) void {
            this.sd = (this.fs == 0b11) or (this.xs == 0b11) or (this.vs == 0b11);
        }
    };

    pub const Mtvec = packed struct(u32) {
        mode: Mode = .direct,
        base: u30 = 0,

        pub const Mode = enum(u2) {
            direct = 0,
            vectored = 1,
            _,
        };

        pub inline fn getAddress(this: Mtvec, cause: u31, is_interrupt: bool) u32 {
            const base_addr = @as(u32, this.base) << 2;

            return switch (this.mode) {
                .direct => base_addr,
                .vectored => if (is_interrupt) base_addr +% (@as(u32, cause) * 4) else base_addr,
                _ => base_addr,
            };
        }
    };

    pub const Mcause = packed struct(u32) {
        code: u31 = 0,
        interrupt: bool = false,

        pub const Exception = enum(u31) {
            instruction_address_misaligned = 0,
            instruction_access_fault = 1,
            illegal_instruction = 2,
            breakpoint = 3,
            load_address_misaligned = 4,
            load_access_fault = 5,
            store_address_misaligned = 6,
            store_access_fault = 7,
            ecall_from_u = 8,
            ecall_from_m = 11,
        };

        pub const Interrupt = enum(u31) {
            machine_software = 3,
            machine_timer = 7,
            machine_external = 11,
        };

        pub inline fn fromException(code: Exception) Mcause {
            return .{ .code = @intFromEnum(code), .interrupt = false };
        }

        pub inline fn fromInterrupt(code: Interrupt) Mcause {
            return .{ .code = @intFromEnum(code), .interrupt = true };
        }
    };

    pub const Mie = packed struct(u32) {
        _reserved0: u3 = 0,
        msie: bool = false, // M-mode software interrupt enable
        _reserved4: u3 = 0,
        mtie: bool = false, // M-mode timer interrupt enable
        _reserved8: u3 = 0,
        meie: bool = false, // M-mode external interrupt enable
        _reserved12: u20 = 0,
    };

    pub const Mip = packed struct(u32) {
        _reserved0: u3 = 0,
        msip: bool = false, // M-mode software interrupt pending
        _reserved4: u3 = 0,
        mtip: bool = false, // M-mode timer interrupt pending
        _reserved8: u3 = 0,
        meip: bool = false, // M-mode external interrupt pending
        _reserved12: u20 = 0,

        // Writable bits (MSIP can be written, MTIP/MEIP are external)
        pub const WRITE_MASK: u32 = 0x00000008;
    };

    pub const Mcounteren = packed struct(u32) {
        cy: bool = false, // cycle counter enable for U-mode
        tm: bool = false, // time counter enable for U-mode
        ir: bool = false, // instret counter enable for U-mode
        _reserved: u29 = 0,
    };

    pub const PmpCfg = packed struct(u8) {
        r: bool = false, // Read permission
        w: bool = false, // Write permission
        x: bool = false, // Execute permission
        a: AddressMode = .off, // Address matching mode
        _reserved: u2 = 0,
        l: bool = false, // Lock bit

        pub const AddressMode = enum(u2) {
            off = 0, // Disabled
            tor = 1, // Top of Range
            na4 = 2, // Naturally aligned 4-byte
            napot = 3, // Naturally aligned power-of-2
        };

        pub inline fn isLocked(this: PmpCfg) bool {
            return this.l;
        }

        pub inline fn isEnabled(this: PmpCfg) bool {
            return this.a != .off;
        }
    };

    pub const Pmp = struct {
        pub const NUM_REGIONS: usize = 16;

        pub const AccessType = enum { read, write, execute };

        pub const MatchResult = enum {
            no_match,
            match_allowed,
            match_denied,
        };

        pub inline fn getRange(cfg: PmpCfg, addr: u32, prev_addr: u32) struct { start: u34, end: u34 } {
            return switch (cfg.a) {
                .off => .{ .start = 0, .end = 0 },
                .tor => .{
                    .start = @as(u34, prev_addr) << 2,
                    .end = @as(u34, addr) << 2,
                },
                .na4 => .{
                    .start = @as(u34, addr) << 2,
                    .end = (@as(u34, addr) << 2) + 4,
                },
                .napot => blk: {
                    // Find the lowest zero bit to determine range size
                    const trailing_ones = @ctz(~addr);
                    const range_size: u34 = @as(u34, 8) << trailing_ones;
                    const base = (@as(u34, addr) & ~(range_size / 4 - 1)) << 2;

                    break :blk .{ .start = base, .end = base + range_size };
                },
            };
        }

        pub inline fn checkAccess(cfg: PmpCfg, addr: u32, prev_addr: u32, access_addr: u32, access_type: AccessType) MatchResult {
            if (cfg.a == .off) {
                return .no_match;
            }

            const range = getRange(cfg, addr, prev_addr);
            const check_addr: u34 = access_addr;

            if (check_addr >= range.start and check_addr < range.end) {
                const allowed = switch (access_type) {
                    .read => cfg.r,
                    .write => cfg.w,
                    .execute => cfg.x,
                };

                return if (allowed) .match_allowed else .match_denied;
            }

            return .no_match;
        }
    };

    pub const Fcsr = packed struct(u32) {
        pub const RoundingMode = enum(u3) {
            rne = 0b000, // Round to Nearest, ties to Even
            rtz = 0b001, // Round towards Zero
            rdn = 0b010, // Round Down (towards -∞)
            rup = 0b011, // Round Up (towards +∞)
            rmm = 0b100, // Round to Nearest, ties to Max Magnitude
            _reserved5 = 0b101,
            _reserved6 = 0b110,
            dyn = 0b111, // Dynamic (use frm from fcsr)
        };

        // Exception flags (fflags) - bits 4:0
        nx: bool = false, // Inexact
        uf: bool = false, // Underflow
        of: bool = false, // Overflow
        dz: bool = false, // Division by Zero
        nv: bool = false, // Invalid Operation
        // Rounding mode (frm) - bits 7:5
        frm: RoundingMode = .rne,
        _reserved: u24 = 0,

        pub inline fn getFflags(this: Fcsr) u5 {
            return @truncate(@as(u32, @bitCast(this)));
        }

        pub inline fn setFflags(this: *Fcsr, flags: u5) void {
            const val: u32 = @bitCast(this.*);

            this.* = @bitCast((val & ~@as(u32, 0x1F)) | flags);
        }

        pub inline fn clearFlags(this: *Fcsr) void {
            this.nx = false;
            this.uf = false;
            this.of = false;
            this.dz = false;
            this.nv = false;
        }

        pub inline fn getEffectiveRm(this: *Fcsr, rm: u3) Fcsr.RoundingMode {
            const mode: Fcsr.RoundingMode = @enumFromInt(rm);

            return if (mode == .dyn) this.frm else mode;
        }
    };

    pub const COMMON_REGISTERS: usize = 32;
    pub const FLOAT_REGISTERS: usize = 32;

    common: [COMMON_REGISTERS]i32 = std.mem.zeroes([COMMON_REGISTERS]i32),
    float: [FLOAT_REGISTERS]u64 = std.mem.zeroes([FLOAT_REGISTERS]u64),
    fcsr: Fcsr = .{},
    cycle: u64 = 0,
    instret: u64 = 0,
    pc: u32 = 0,
    privilege: PrivilegeLevel = .machine,
    mstatus: Mstatus = .{},
    mie: Mie = .{},
    mtvec: Mtvec = .{},
    mscratch: u32 = 0,
    mepc: u32 = 0,
    mcause: Mcause = .{},
    mtval: u32 = 0,
    mip: Mip = .{},
    mcounteren: Mcounteren = .{},
    pmpcfg: [4]u32 = std.mem.zeroes([4]u32),
    pmpaddr: [Pmp.NUM_REGIONS]u32 = std.mem.zeroes([Pmp.NUM_REGIONS]u32),
    mvendorid: u32 = 0,
    marchid: u32 = 0,
    mimpid: u32 = 0x0001_0000,
    mhartid: u32 = 0,

    pub const MISA_VALUE: u32 = blk: {
        const mxl: u32 = 0b01 << 30; // XLEN = 32
        const i: u32 = 1 << 8; // Base integer ISA
        const m: u32 = 1 << 12; // Integer multiply/divide
        const a: u32 = 0 << 0; // Atomic
        const f: u32 = 1 << 5; // Single-precision float
        const d: u32 = 1 << 3; // Double-precision float
        const c: u32 = 0 << 2; // Compressed
        const u: u32 = 1 << 20; // User mode

        break :blk mxl | i | m | a | f | d | c | u;
    };

    pub inline fn get(this: *Registers, n: u8) i32 {
        if (n == 0) {
            return 0;
        }

        return this.common[n];
    }

    pub inline fn set(this: *Registers, n: u8, value: i32) void {
        if (n == 0) {
            return;
        }

        this.common[n] = value;
    }

    pub inline fn getF32(this: *Registers, n: u8) f32 {
        const bits = this.float[n];

        if ((bits >> 32) != 0xFFFFFFFF) {
            return std.math.nan(f32);
        }

        return @bitCast(@as(u32, @truncate(bits)));
    }

    pub inline fn setF32(this: *Registers, n: u8, value: f32) void {
        // NaN-boxing: upper 32 bits set to 1 for single-precision
        this.float[n] = 0xFFFFFFFF00000000 | @as(u64, @as(u32, @bitCast(value)));
    }

    pub inline fn getF64(this: *Registers, n: u8) f64 {
        return @bitCast(this.float[n]);
    }

    pub inline fn setF64(this: *Registers, n: u8, value: f64) void {
        this.float[n] = @bitCast(value);
    }

    pub inline fn canAccessCsr(csr: Csr, priv: PrivilegeLevel) bool {
        const required = csr.getRequiredPrivilege();

        return @intFromEnum(priv) >= @intFromEnum(required);
    }

    inline fn canAccessCounter(this: *Registers, csr: Csr, priv: PrivilegeLevel) bool {
        if (priv == .machine) return true;

        return switch (csr) {
            .cycle, .cycleh => this.mcounteren.cy,
            .time, .timeh => this.mcounteren.tm,
            .instret, .instreth => this.mcounteren.ir,
            else => true,
        };
    }

    pub inline fn getPmpCfg(this: *Registers, index: usize) PmpCfg {
        std.debug.assert(index < Pmp.NUM_REGIONS);

        const cfg_reg = index / 4;
        const cfg_offset: u5 = @intCast((index % 4) * 8);

        return @bitCast(@as(u8, @truncate(this.pmpcfg[cfg_reg] >> cfg_offset)));
    }

    pub inline fn setPmpCfg(this: *Registers, index: usize, cfg: PmpCfg) void {
        std.debug.assert(index < Pmp.NUM_REGIONS);

        const current = this.getPmpCfg(index);

        if (current.isLocked()) {
            return;
        }

        const cfg_reg = index / 4;
        const cfg_offset: u5 = @intCast((index % 4) * 8);
        const mask: u32 = @as(u32, 0xFF) << cfg_offset;

        this.pmpcfg[cfg_reg] = (this.pmpcfg[cfg_reg] & ~mask) | (@as(u8, @bitCast(cfg)) << cfg_offset);
    }

    pub inline fn checkPmpAccess(this: *Registers, addr: u32, access_type: Pmp.AccessType, priv: PrivilegeLevel) bool {
        // M-mode without MPRV bypasses PMP unless L bit is set
        if (priv == .machine and !this.mstatus.mprv) {
            // Still check locked entries
            var matched_locked = false;
            var prev_addr: u32 = 0;

            inline for (0..Pmp.NUM_REGIONS) |i| {
                const cfg = this.getPmpCfg(i);
                const pmpaddr = this.pmpaddr[i];

                if (cfg.isLocked()) {
                    const result = Pmp.checkAccess(cfg, pmpaddr, prev_addr, addr, access_type);

                    if (result == .match_denied) {
                        return false;
                    }

                    if (result == .match_allowed) {
                        matched_locked = true;
                    }
                }

                prev_addr = pmpaddr;
            }

            return true;
        }

        // U-mode or M-mode with MPRV must pass PMP check
        var prev_addr: u32 = 0;

        inline for (0..Pmp.NUM_REGIONS) |i| {
            const cfg = this.getPmpCfg(i);
            const pmpaddr = this.pmpaddr[i];

            const result = Pmp.checkAccess(cfg, pmpaddr, prev_addr, addr, access_type);

            switch (result) {
                .match_allowed => return true,
                .match_denied => return false,
                .no_match => {},
            }

            prev_addr = pmpaddr;
        }

        // No PMP entry matched - denied for U-mode, allowed for M-mode
        return priv == .machine;
    }

    pub inline fn readCsr(this: *Registers, csr: Csr, priv: PrivilegeLevel) Csr.Error!u32 {
        if (!canAccessCsr(csr, priv)) {
            return Csr.Error.IllegalInstruction;
        }

        if (!this.canAccessCounter(csr, priv)) {
            return Csr.Error.IllegalInstruction;
        }

        return switch (csr) {
            // User floating-point CSRs
            .fflags => @as(u32, this.fcsr.getFflags()),
            .frm => @as(u32, @intFromEnum(this.fcsr.frm)),
            .fcsr => @as(u32, @bitCast(this.fcsr)) & 0xFF,
            // User counters (also accessible from M-mode)
            .cycle, .time => @truncate(this.cycle),
            .cycleh, .timeh => @truncate(this.cycle >> 32),
            .instret => @truncate(this.instret),
            .instreth => @truncate(this.instret >> 32),
            // Machine information (read-only)
            .mvendorid => this.mvendorid,
            .marchid => this.marchid,
            .mimpid => this.mimpid,
            .mhartid => this.mhartid,
            .misa => MISA_VALUE,
            // Machine trap setup
            .mstatus => @bitCast(this.mstatus),
            .mie => @bitCast(this.mie),
            .mtvec => @bitCast(this.mtvec),
            .mcounteren => @bitCast(this.mcounteren),
            // Machine trap handling
            .mscratch => this.mscratch,
            .mepc => this.mepc,
            .mcause => @bitCast(this.mcause),
            .mtval => this.mtval,
            .mip => @bitCast(this.mip),
            // Machine counters
            .mcycle => @truncate(this.cycle),
            .mcycleh => @truncate(this.cycle >> 32),
            .minstret => @truncate(this.instret),
            .minstreth => @truncate(this.instret >> 32),
            // PMP configuration
            .pmpcfg0 => this.pmpcfg[0],
            .pmpcfg1 => this.pmpcfg[1],
            .pmpcfg2 => this.pmpcfg[2],
            .pmpcfg3 => this.pmpcfg[3],
            // PMP addresses
            .pmpaddr0 => this.pmpaddr[0],
            .pmpaddr1 => this.pmpaddr[1],
            .pmpaddr2 => this.pmpaddr[2],
            .pmpaddr3 => this.pmpaddr[3],
            .pmpaddr4 => this.pmpaddr[4],
            .pmpaddr5 => this.pmpaddr[5],
            .pmpaddr6 => this.pmpaddr[6],
            .pmpaddr7 => this.pmpaddr[7],
            .pmpaddr8 => this.pmpaddr[8],
            .pmpaddr9 => this.pmpaddr[9],
            .pmpaddr10 => this.pmpaddr[10],
            .pmpaddr11 => this.pmpaddr[11],
            .pmpaddr12 => this.pmpaddr[12],
            .pmpaddr13 => this.pmpaddr[13],
            .pmpaddr14 => this.pmpaddr[14],
            .pmpaddr15 => this.pmpaddr[15],
            else => 0, // Unknown CSR reads as 0
        };
    }

    pub inline fn writeCsr(this: *Registers, csr: Csr, value: u32, priv: PrivilegeLevel) Csr.Error!void {
        if (!canAccessCsr(csr, priv)) {
            return Csr.Error.IllegalInstruction;
        }

        if (csr.isReadOnly()) {
            return Csr.Error.IllegalInstruction;
        }

        switch (csr) {
            // User floating-point CSRs
            .fflags => this.fcsr.setFflags(@truncate(value)),
            .frm => this.fcsr.frm = @enumFromInt(@as(u3, @truncate(value))),
            .fcsr => {
                const masked = value & 0xFF;
                this.fcsr = @bitCast(masked);
            },
            // Machine trap setup
            .mstatus => {
                const mpp_bits: u2 = @truncate(value >> 11);
                const valid_mpp: u2 = switch (mpp_bits) {
                    @intFromEnum(PrivilegeLevel.user) => @intFromEnum(PrivilegeLevel.user),
                    @intFromEnum(PrivilegeLevel.machine) => @intFromEnum(PrivilegeLevel.machine),
                    else => @intFromEnum(PrivilegeLevel.machine), // Default to M-mode for invalid values
                };

                const sanitized_value = (value & ~@as(u32, 0x1800)) | (@as(u32, valid_mpp) << 11);

                // Apply write mask
                const current: u32 = @bitCast(this.mstatus);
                const new_val = (current & ~Mstatus.WRITE_MASK) | (sanitized_value & Mstatus.WRITE_MASK);

                this.mstatus = @bitCast(new_val);
                this.mstatus.updateSD();
            },
            .mie => this.mie = @bitCast(value & 0x888), // Only valid bits
            .mtvec => {
                var new_tvec: Mtvec = @bitCast(value);

                // Validate mode
                if (@intFromEnum(new_tvec.mode) > 1) {
                    new_tvec.mode = .direct;
                }

                this.mtvec = new_tvec;
            },
            .mcounteren => this.mcounteren = @bitCast(value & 0x7),
            // Machine trap handling
            .mscratch => this.mscratch = value,
            .mepc => this.mepc = value & ~@as(u32, 0x3), // Align to 4 bytes
            .mcause => this.mcause = @bitCast(value),
            .mtval => this.mtval = value,
            .mip => {
                // Only MSIP is writable
                const current: u32 = @bitCast(this.mip);

                this.mip = @bitCast((current & ~Mip.WRITE_MASK) | (value & Mip.WRITE_MASK));
            },
            // Machine counters (writable in M-mode)
            .mcycle => this.cycle = (this.cycle & 0xFFFFFFFF_00000000) | value,
            .mcycleh => this.cycle = (this.cycle & 0x00000000_FFFFFFFF) | (@as(u64, value) << 32),
            .minstret => this.instret = (this.instret & 0xFFFFFFFF_00000000) | value,
            .minstreth => this.instret = (this.instret & 0x00000000_FFFFFFFF) | (@as(u64, value) << 32),
            // PMP configuration (respects lock bits)
            .pmpcfg0 => this.writePmpcfg(0, value),
            .pmpcfg1 => this.writePmpcfg(1, value),
            .pmpcfg2 => this.writePmpcfg(2, value),
            .pmpcfg3 => this.writePmpcfg(3, value),
            // PMP addresses (respects lock bits)
            .pmpaddr0 => this.writePmpaddr(0, value),
            .pmpaddr1 => this.writePmpaddr(1, value),
            .pmpaddr2 => this.writePmpaddr(2, value),
            .pmpaddr3 => this.writePmpaddr(3, value),
            .pmpaddr4 => this.writePmpaddr(4, value),
            .pmpaddr5 => this.writePmpaddr(5, value),
            .pmpaddr6 => this.writePmpaddr(6, value),
            .pmpaddr7 => this.writePmpaddr(7, value),
            .pmpaddr8 => this.writePmpaddr(8, value),
            .pmpaddr9 => this.writePmpaddr(9, value),
            .pmpaddr10 => this.writePmpaddr(10, value),
            .pmpaddr11 => this.writePmpaddr(11, value),
            .pmpaddr12 => this.writePmpaddr(12, value),
            .pmpaddr13 => this.writePmpaddr(13, value),
            .pmpaddr14 => this.writePmpaddr(14, value),
            .pmpaddr15 => this.writePmpaddr(15, value),
            // Read-only or user counters - ignore writes
            else => {},
        }
    }

    pub inline fn readCsrUnchecked(this: *Registers, csr: Csr) u32 {
        return switch (csr) {
            .fflags => @as(u32, this.fcsr.getFflags()),
            .frm => @as(u32, @intFromEnum(this.fcsr.frm)),
            .fcsr => @as(u32, @bitCast(this.fcsr)) & 0xFF,
            .cycle, .time => @truncate(this.cycle),
            .cycleh, .timeh => @truncate(this.cycle >> 32),
            .instret => @truncate(this.instret),
            .instreth => @truncate(this.instret >> 32),
            .mstatus => @bitCast(this.mstatus),
            .mie => @bitCast(this.mie),
            .mtvec => @bitCast(this.mtvec),
            .mcounteren => @bitCast(this.mcounteren),
            .mscratch => this.mscratch,
            .mepc => this.mepc,
            .mcause => @bitCast(this.mcause),
            .mtval => this.mtval,
            .mip => @bitCast(this.mip),
            .mcycle => @truncate(this.cycle),
            .mcycleh => @truncate(this.cycle >> 32),
            .minstret => @truncate(this.instret),
            .minstreth => @truncate(this.instret >> 32),
            else => 0,
        };
    }

    pub inline fn writeCsrUnchecked(this: *Registers, csr: Csr, value: u32) void {
        switch (csr) {
            .fflags => this.fcsr.setFflags(@truncate(value)),
            .frm => this.fcsr.frm = @enumFromInt(@as(u3, @truncate(value))),
            .fcsr => this.fcsr = @bitCast(value & 0xFF),
            .mstatus => {
                const new_val = (@as(u32, @bitCast(this.mstatus)) & ~Mstatus.WRITE_MASK) |
                    (value & Mstatus.WRITE_MASK);
                this.mstatus = @bitCast(new_val);
            },
            .mie => this.mie = @bitCast(value & 0x888),
            .mtvec => this.mtvec = @bitCast(value),
            .mcounteren => this.mcounteren = @bitCast(value & 0x7),
            .mscratch => this.mscratch = value,
            .mepc => this.mepc = value & ~@as(u32, 0x3),
            .mcause => this.mcause = @bitCast(value),
            .mtval => this.mtval = value,
            .mip => {
                const current: u32 = @bitCast(this.mip);
                this.mip = @bitCast((current & ~Mip.WRITE_MASK) | (value & Mip.WRITE_MASK));
            },
            .mcycle => this.cycle = (this.cycle & 0xFFFFFFFF_00000000) | value,
            .mcycleh => this.cycle = (this.cycle & 0x00000000_FFFFFFFF) | (@as(u64, value) << 32),
            .minstret => this.instret = (this.instret & 0xFFFFFFFF_00000000) | value,
            .minstreth => this.instret = (this.instret & 0x00000000_FFFFFFFF) | (@as(u64, value) << 32),
            else => {},
        }
    }

    pub inline fn writePmpcfg(this: *Registers, index: usize, value: u32) void {
        var result: u32 = 0;

        for (0..4) |i| {
            const entry_idx = index * 4 + i;
            const current_cfg = this.getPmpCfg(entry_idx);
            const new_cfg: PmpCfg = @bitCast(@as(u8, @truncate(value >> @intCast(i * 8))));

            if (!current_cfg.isLocked()) {
                result |= @as(u8, @bitCast(new_cfg)) << @intCast(i * 8);
            } else {
                result |= @as(u8, @bitCast(current_cfg)) << @intCast(i * 8);
            }
        }

        this.pmpcfg[index] = result;
    }

    pub inline fn writePmpaddr(this: *Registers, index: usize, value: u32) void {
        const cfg = this.getPmpCfg(index);

        if (cfg.isLocked()) {
            return;
        }

        // Also check if next entry is locked and uses TOR mode
        if (index < Pmp.NUM_REGIONS - 1) {
            const next_cfg = this.getPmpCfg(index + 1);

            if (next_cfg.isLocked() and next_cfg.a == .tor) {
                return;
            }
        }

        this.pmpaddr[index] = value;
    }

    pub inline fn getAbiName(n: u8) []const u8 {
        return switch (n) {
            0 => "x0",
            1 => "ra",
            2 => "sp",
            3 => "gp",
            4 => "tp",
            5 => "t0",
            6 => "t1",
            7 => "t2",
            8 => "s0",
            9 => "s1",
            10 => "a0",
            11 => "a1",
            12 => "a2",
            13 => "a3",
            14 => "a4",
            15 => "a5",
            16 => "a6",
            17 => "a7",
            18 => "s2",
            19 => "s3",
            20 => "s4",
            21 => "s5",
            22 => "s6",
            23 => "s7",
            24 => "s8",
            25 => "s9",
            26 => "s10",
            27 => "s11",
            28 => "t3",
            29 => "t4",
            30 => "t5",
            31 => "t6",
            else => "BAD",
        };
    }

    pub inline fn getFloatAbiName(n: u8) []const u8 {
        return switch (n) {
            0 => "ft0",
            1 => "ft1",
            2 => "ft2",
            3 => "ft3",
            4 => "ft4",
            5 => "ft5",
            6 => "ft6",
            7 => "ft7",
            8 => "fs0",
            9 => "fs1",
            10 => "fa0",
            11 => "fa1",
            12 => "fa2",
            13 => "fa3",
            14 => "fa4",
            15 => "fa5",
            16 => "fa6",
            17 => "fa7",
            18 => "fs2",
            19 => "fs3",
            20 => "fs4",
            21 => "fs5",
            22 => "fs6",
            23 => "fs7",
            24 => "fs8",
            25 => "fs9",
            26 => "fs10",
            27 => "fs11",
            28 => "ft8",
            29 => "ft9",
            30 => "ft10",
            31 => "ft11",
            else => "BAD",
        };
    }
};

pub const Instruction = union(enum) {
    pub const DecodeError = error{ UnknownInstruction, BadRegister };

    // RV32I
    lui: struct { rd: u8, imm: i20 },
    auipc: struct { rd: u8, imm: i20 },
    jal: struct { rd: u8, imm: i20 },
    jalr: struct { rd: u8, rs1: u8, imm: i12 },
    beq: struct { rs1: u8, rs2: u8, imm: i12 },
    bne: struct { rs1: u8, rs2: u8, imm: i12 },
    blt: struct { rs1: u8, rs2: u8, imm: i12 },
    bge: struct { rs1: u8, rs2: u8, imm: i12 },
    bltu: struct { rs1: u8, rs2: u8, imm: i12 },
    bgeu: struct { rs1: u8, rs2: u8, imm: i12 },
    lb: struct { rd: u8, rs1: u8, imm: i12 },
    lh: struct { rd: u8, rs1: u8, imm: i12 },
    lw: struct { rd: u8, rs1: u8, imm: i12 },
    lbu: struct { rd: u8, rs1: u8, imm: i12 },
    lhu: struct { rd: u8, rs1: u8, imm: i12 },
    sb: struct { rs1: u8, rs2: u8, imm: i12 },
    sh: struct { rs1: u8, rs2: u8, imm: i12 },
    sw: struct { rs1: u8, rs2: u8, imm: i12 },
    addi: struct { rd: u8, rs1: u8, imm: i12 },
    slti: struct { rd: u8, rs1: u8, imm: i12 },
    sltiu: struct { rd: u8, rs1: u8, imm: i12 },
    xori: struct { rd: u8, rs1: u8, imm: i12 },
    ori: struct { rd: u8, rs1: u8, imm: i12 },
    andi: struct { rd: u8, rs1: u8, imm: i12 },
    slli: struct { rd: u8, rs1: u8, shamt: u5 },
    srli: struct { rd: u8, rs1: u8, shamt: u5 },
    srai: struct { rd: u8, rs1: u8, shamt: u5 },
    add: struct { rd: u8, rs1: u8, rs2: u8 },
    sub: struct { rd: u8, rs1: u8, rs2: u8 },
    sll: struct { rd: u8, rs1: u8, rs2: u8 },
    slt: struct { rd: u8, rs1: u8, rs2: u8 },
    sltu: struct { rd: u8, rs1: u8, rs2: u8 },
    xor: struct { rd: u8, rs1: u8, rs2: u8 },
    srl: struct { rd: u8, rs1: u8, rs2: u8 },
    sra: struct { rd: u8, rs1: u8, rs2: u8 },
    @"or": struct { rd: u8, rs1: u8, rs2: u8 },
    @"and": struct { rd: u8, rs1: u8, rs2: u8 },
    fence: void,
    ecall: void,
    ebreak: void,
    // RV32M
    mul: struct { rd: u8, rs1: u8, rs2: u8 },
    mulh: struct { rd: u8, rs1: u8, rs2: u8 },
    mulhsu: struct { rd: u8, rs1: u8, rs2: u8 },
    mulhu: struct { rd: u8, rs1: u8, rs2: u8 },
    div: struct { rd: u8, rs1: u8, rs2: u8 },
    divu: struct { rd: u8, rs1: u8, rs2: u8 },
    rem: struct { rd: u8, rs1: u8, rs2: u8 },
    remu: struct { rd: u8, rs1: u8, rs2: u8 },
    // RV32F
    flw: struct { rd: u8, rs1: u8, imm: i12 },
    fsw: struct { rs1: u8, rs2: u8, imm: i12 },
    fmadd_s: struct { rd: u8, rs1: u8, rs2: u8, rs3: u8, rm: u3 },
    fmsub_s: struct { rd: u8, rs1: u8, rs2: u8, rs3: u8, rm: u3 },
    fnmsub_s: struct { rd: u8, rs1: u8, rs2: u8, rs3: u8, rm: u3 },
    fnmadd_s: struct { rd: u8, rs1: u8, rs2: u8, rs3: u8, rm: u3 },
    fadd_s: struct { rd: u8, rs1: u8, rs2: u8, rm: u3 },
    fsub_s: struct { rd: u8, rs1: u8, rs2: u8, rm: u3 },
    fmul_s: struct { rd: u8, rs1: u8, rs2: u8, rm: u3 },
    fdiv_s: struct { rd: u8, rs1: u8, rs2: u8, rm: u3 },
    fsqrt_s: struct { rd: u8, rs1: u8, rm: u3 },
    fsgnj_s: struct { rd: u8, rs1: u8, rs2: u8 },
    fsgnjn_s: struct { rd: u8, rs1: u8, rs2: u8 },
    fsgnjx_s: struct { rd: u8, rs1: u8, rs2: u8 },
    fmin_s: struct { rd: u8, rs1: u8, rs2: u8 },
    fmax_s: struct { rd: u8, rs1: u8, rs2: u8 },
    fcvt_w_s: struct { rd: u8, rs1: u8, rm: u3 },
    fcvt_wu_s: struct { rd: u8, rs1: u8, rm: u3 },
    fmv_x_w: struct { rd: u8, rs1: u8 },
    feq_s: struct { rd: u8, rs1: u8, rs2: u8 },
    flt_s: struct { rd: u8, rs1: u8, rs2: u8 },
    fle_s: struct { rd: u8, rs1: u8, rs2: u8 },
    fclass_s: struct { rd: u8, rs1: u8 },
    fcvt_s_w: struct { rd: u8, rs1: u8, rm: u3 },
    fcvt_s_wu: struct { rd: u8, rs1: u8, rm: u3 },
    fmv_w_x: struct { rd: u8, rs1: u8 },
    // RV32D
    fld: struct { rd: u8, rs1: u8, imm: i12 },
    fsd: struct { rs1: u8, rs2: u8, imm: i12 },
    fmadd_d: struct { rd: u8, rs1: u8, rs2: u8, rs3: u8, rm: u3 },
    fmsub_d: struct { rd: u8, rs1: u8, rs2: u8, rs3: u8, rm: u3 },
    fnmsub_d: struct { rd: u8, rs1: u8, rs2: u8, rs3: u8, rm: u3 },
    fnmadd_d: struct { rd: u8, rs1: u8, rs2: u8, rs3: u8, rm: u3 },
    fadd_d: struct { rd: u8, rs1: u8, rs2: u8, rm: u3 },
    fsub_d: struct { rd: u8, rs1: u8, rs2: u8, rm: u3 },
    fmul_d: struct { rd: u8, rs1: u8, rs2: u8, rm: u3 },
    fdiv_d: struct { rd: u8, rs1: u8, rs2: u8, rm: u3 },
    fsqrt_d: struct { rd: u8, rs1: u8, rm: u3 },
    fsgnj_d: struct { rd: u8, rs1: u8, rs2: u8 },
    fsgnjn_d: struct { rd: u8, rs1: u8, rs2: u8 },
    fsgnjx_d: struct { rd: u8, rs1: u8, rs2: u8 },
    fmin_d: struct { rd: u8, rs1: u8, rs2: u8 },
    fmax_d: struct { rd: u8, rs1: u8, rs2: u8 },
    fcvt_s_d: struct { rd: u8, rs1: u8, rm: u3 },
    fcvt_d_s: struct { rd: u8, rs1: u8, rm: u3 },
    feq_d: struct { rd: u8, rs1: u8, rs2: u8 },
    flt_d: struct { rd: u8, rs1: u8, rs2: u8 },
    fle_d: struct { rd: u8, rs1: u8, rs2: u8 },
    fclass_d: struct { rd: u8, rs1: u8 },
    fcvt_w_d: struct { rd: u8, rs1: u8, rm: u3 },
    fcvt_wu_d: struct { rd: u8, rs1: u8, rm: u3 },
    fcvt_d_w: struct { rd: u8, rs1: u8, rm: u3 },
    fcvt_d_wu: struct { rd: u8, rs1: u8, rm: u3 },
    // Zicsr
    csrrw: struct { rd: u8, rs1: u8, csr: u12 },
    csrrs: struct { rd: u8, rs1: u8, csr: u12 },
    csrrc: struct { rd: u8, rs1: u8, csr: u12 },
    csrrwi: struct { rd: u8, uimm: u5, csr: u12 },
    csrrsi: struct { rd: u8, uimm: u5, csr: u12 },
    csrrci: struct { rd: u8, uimm: u5, csr: u12 },
    // Zifencei
    fence_i: void,
    // Zba
    sh1add: struct { rd: u8, rs1: u8, rs2: u8 },
    sh2add: struct { rd: u8, rs1: u8, rs2: u8 },
    sh3add: struct { rd: u8, rs1: u8, rs2: u8 },
    // Zbb
    andn: struct { rd: u8, rs1: u8, rs2: u8 },
    orn: struct { rd: u8, rs1: u8, rs2: u8 },
    xnor: struct { rd: u8, rs1: u8, rs2: u8 },
    clz: struct { rd: u8, rs1: u8 },
    ctz: struct { rd: u8, rs1: u8 },
    cpop: struct { rd: u8, rs1: u8 },
    max: struct { rd: u8, rs1: u8, rs2: u8 },
    maxu: struct { rd: u8, rs1: u8, rs2: u8 },
    min: struct { rd: u8, rs1: u8, rs2: u8 },
    minu: struct { rd: u8, rs1: u8, rs2: u8 },
    sext_b: struct { rd: u8, rs1: u8 },
    sext_h: struct { rd: u8, rs1: u8 },
    zext_h: struct { rd: u8, rs1: u8 },
    rol: struct { rd: u8, rs1: u8, rs2: u8 },
    ror: struct { rd: u8, rs1: u8, rs2: u8 },
    rori: struct { rd: u8, rs1: u8, shamt: u5 },
    orc_b: struct { rd: u8, rs1: u8 },
    rev8: struct { rd: u8, rs1: u8 },
    // Privileged
    mret: void,
    wfi: void,

    inline fn decodeOpcode(from: u32) u7 {
        return @truncate(from);
    }

    inline fn encodeOpcode(opcode: u7) u32 {
        return opcode;
    }

    inline fn decodeRd(from: u32) u5 {
        return @truncate(from >> 7);
    }

    inline fn encodeRd(rd: u8) u32 {
        return @as(u32, rd & 0x1F) << 7;
    }

    inline fn decodeFunct3(from: u32) u3 {
        return @truncate(from >> 12);
    }

    inline fn encodeFunct3(funct3: u3) u32 {
        return @as(u32, funct3) << 12;
    }

    inline fn decodeRs1(from: u32) u5 {
        return @truncate(from >> 15);
    }

    inline fn encodeRs1(rs1: u8) u32 {
        return @as(u32, rs1 & 0x1F) << 15;
    }

    inline fn decodeRs2(from: u32) u5 {
        return @truncate(from >> 20);
    }

    inline fn encodeRs2(rs2: u8) u32 {
        return @as(u32, rs2 & 0x1F) << 20;
    }

    inline fn decodeRs3(from: u32) u5 {
        return @truncate(from >> 27);
    }

    inline fn encodeRs3(rs3: u8) u32 {
        return @as(u32, rs3 & 0x1F) << 27;
    }

    inline fn decodeFunct7(from: u32) u7 {
        return @truncate(from >> 25);
    }

    inline fn encodeFunct7(funct7: u7) u32 {
        return @as(u32, funct7) << 25;
    }

    inline fn decodeFmt(from: u32) u2 {
        return @truncate(from >> 25);
    }

    inline fn encodeFmt(fmt: u2) u32 {
        return @as(u32, fmt) << 25;
    }

    inline fn decodeCsr(from: u32) u12 {
        return @truncate(from >> 20);
    }

    inline fn encodeCsr(csr: u12) u32 {
        return @as(u32, csr) << 20;
    }

    inline fn toRegisterChecked(from: u32) error{BadRegister}!u8 {
        if (from >= Registers.COMMON_REGISTERS) {
            return DecodeError.BadRegister;
        }

        return @as(u8, @truncate(from));
    }

    const Immediate = enum { i, s, b, u, j };

    inline fn decodeImmediate(from: u32, comptime ty: Immediate) i32 {
        const sfrom = @as(i32, @bitCast(from));

        return switch (ty) {
            // I-type: inst[31:20] -> imm[11:0]
            .i => sfrom >> 20,
            // S-type: inst[31:25] -> imm[11:5], inst[11:7] -> imm[4:0]
            .s => (sfrom >> 25) << 5 | @as(i32, @bitCast((from >> 7) & 0x1F)),
            // B-type: inst[31|7|30:25|11:8] -> imm[12|11|10:5|4:1]
            .b => (sfrom >> 31) << 12 |
                @as(i32, @bitCast((from >> 7) & 0x01)) << 11 |
                @as(i32, @bitCast((from >> 25) & 0x3F)) << 5 |
                @as(i32, @bitCast((from >> 8) & 0x0F)) << 1,
            // U-type: inst[31:12] -> imm[31:12]
            .u => sfrom >> 12,
            // J-type: inst[31|19:12|20|30:21] -> imm[20|19:12|11|10:1]
            .j => (sfrom >> 31) << 20 |
                @as(i32, @bitCast((from >> 12) & 0xFF)) << 12 |
                @as(i32, @bitCast((from >> 20) & 0x01)) << 11 |
                @as(i32, @bitCast((from >> 21) & 0x3FF)) << 1,
        };
    }

    inline fn encodeImmediate(imm: i32, comptime ty: Immediate) u32 {
        const raw = @as(u32, @bitCast(imm));

        return switch (ty) {
            // I-type: imm[11:0] -> inst[31:20]
            .i => (raw & 0xFFF) << 20,
            // S-type: imm[11:5] -> inst[31:25], imm[4:0] -> inst[11:7]
            .s => ((raw >> 5) & 0x7F) << 25 |
                ((raw >> 0) & 0x1F) << 7,
            // B-type: imm[12|10:5|4:1|11] -> inst[31|30:25|11:8|7]
            .b => ((raw >> 12) & 0x01) << 31 |
                ((raw >> 11) & 0x01) << 7 |
                ((raw >> 5) & 0x3F) << 25 |
                ((raw >> 1) & 0x0F) << 8,
            // U-type: imm[31:12] -> inst[31:12]
            .u => (raw & 0xFFFFF) << 12,
            // J-type: imm[20|10:1|11|19:12] -> inst[31|30:21|20|19:12]
            .j => ((raw >> 20) & 0x01) << 31 |
                ((raw >> 12) & 0xFF) << 12 |
                ((raw >> 11) & 0x01) << 20 |
                ((raw >> 1) & 0x3FF) << 21,
        };
    }

    pub inline fn decode(from: u32) DecodeError!Instruction {
        @setEvalBranchQuota(std.math.maxInt(u32));

        const opcode = decodeOpcode(from);
        const funct3 = decodeFunct3(from);
        const funct7 = decodeFunct7(from);

        return switch (opcode) {
            0b0110111 => return .{
                .lui = .{
                    .rd = try toRegisterChecked(decodeRd(from)),
                    .imm = @truncate(decodeImmediate(from, .u)),
                },
            },
            0b0010111 => return .{
                .auipc = .{
                    .rd = try toRegisterChecked(decodeRd(from)),
                    .imm = @truncate(decodeImmediate(from, .u)),
                },
            },
            0b1101111 => return .{
                .jal = .{
                    .rd = try toRegisterChecked(decodeRd(from)),
                    .imm = @truncate(decodeImmediate(from, .j)),
                },
            },
            0b1100111 => return .{
                .jalr = .{
                    .rd = try toRegisterChecked(decodeRd(from)),
                    .rs1 = try toRegisterChecked(decodeRs1(from)),
                    .imm = @truncate(decodeImmediate(from, .i)),
                },
            },
            0b1100011 => switch (funct3) {
                0b000 => return .{
                    .beq = .{
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .rs2 = try toRegisterChecked(decodeRs2(from)),
                        .imm = @truncate(decodeImmediate(from, .b)),
                    },
                },
                0b001 => return .{
                    .bne = .{
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .rs2 = try toRegisterChecked(decodeRs2(from)),
                        .imm = @truncate(decodeImmediate(from, .b)),
                    },
                },
                0b100 => return .{
                    .blt = .{
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .rs2 = try toRegisterChecked(decodeRs2(from)),
                        .imm = @truncate(decodeImmediate(from, .b)),
                    },
                },
                0b101 => return .{
                    .bge = .{
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .rs2 = try toRegisterChecked(decodeRs2(from)),
                        .imm = @truncate(decodeImmediate(from, .b)),
                    },
                },
                0b110 => return .{
                    .bltu = .{
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .rs2 = try toRegisterChecked(decodeRs2(from)),
                        .imm = @truncate(decodeImmediate(from, .b)),
                    },
                },
                0b111 => return .{
                    .bgeu = .{
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .rs2 = try toRegisterChecked(decodeRs2(from)),
                        .imm = @truncate(decodeImmediate(from, .b)),
                    },
                },
                else => return DecodeError.UnknownInstruction,
            },
            0b0000011 => switch (funct3) {
                0b000 => return .{
                    .lb = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                0b001 => return .{
                    .lh = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                0b010 => return .{
                    .lw = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                0b100 => return .{
                    .lbu = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                0b101 => return .{
                    .lhu = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                else => return DecodeError.UnknownInstruction,
            },
            0b0100011 => switch (funct3) {
                0b000 => return .{
                    .sb = .{
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .rs2 = try toRegisterChecked(decodeRs2(from)),
                        .imm = @truncate(decodeImmediate(from, .s)),
                    },
                },
                0b001 => return .{
                    .sh = .{
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .rs2 = try toRegisterChecked(decodeRs2(from)),
                        .imm = @truncate(decodeImmediate(from, .s)),
                    },
                },
                0b010 => return .{
                    .sw = .{
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .rs2 = try toRegisterChecked(decodeRs2(from)),
                        .imm = @truncate(decodeImmediate(from, .s)),
                    },
                },
                else => return DecodeError.UnknownInstruction,
            },
            0b0010011 => switch (funct3) {
                0b000 => return .{
                    .addi = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                0b010 => return .{
                    .slti = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                0b011 => return .{
                    .sltiu = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                0b100 => return .{
                    .xori = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                0b110 => return .{
                    .ori = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                0b111 => return .{
                    .andi = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                0b001 => switch (funct7) {
                    0b0000000 => .{
                        .slli = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .shamt = @truncate(decodeRs2(from)),
                        },
                    },
                    0b0110000 => switch (decodeRs2(from)) {
                        0b00000 => .{
                            .clz = .{
                                .rd = try toRegisterChecked(decodeRd(from)),
                                .rs1 = try toRegisterChecked(decodeRs1(from)),
                            },
                        },
                        0b00001 => .{
                            .ctz = .{
                                .rd = try toRegisterChecked(decodeRd(from)),
                                .rs1 = try toRegisterChecked(decodeRs1(from)),
                            },
                        },
                        0b00010 => .{
                            .cpop = .{
                                .rd = try toRegisterChecked(decodeRd(from)),
                                .rs1 = try toRegisterChecked(decodeRs1(from)),
                            },
                        },
                        0b00100 => .{
                            .sext_b = .{
                                .rd = try toRegisterChecked(decodeRd(from)),
                                .rs1 = try toRegisterChecked(decodeRs1(from)),
                            },
                        },
                        0b00101 => .{
                            .sext_h = .{
                                .rd = try toRegisterChecked(decodeRd(from)),
                                .rs1 = try toRegisterChecked(decodeRs1(from)),
                            },
                        },
                        else => DecodeError.UnknownInstruction,
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b101 => switch (funct7) {
                    0b0000000 => .{
                        .srli = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .shamt = @truncate(decodeRs2(from)),
                        },
                    },
                    0b0100000 => .{
                        .srai = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .shamt = @truncate(decodeRs2(from)),
                        },
                    },
                    0b0110000 => .{
                        .rori = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .shamt = @truncate(decodeRs2(from)),
                        },
                    },
                    else => switch (decodeCsr(from)) {
                        0x287 => .{
                            .orc_b = .{
                                .rd = try toRegisterChecked(decodeRd(from)),
                                .rs1 = try toRegisterChecked(decodeRs1(from)),
                            },
                        },
                        // REV8 encoding for RV32: imm[11:0] = 0x698
                        0x698 => .{
                            .rev8 = .{
                                .rd = try toRegisterChecked(decodeRd(from)),
                                .rs1 = try toRegisterChecked(decodeRs1(from)),
                            },
                        },
                        else => DecodeError.UnknownInstruction,
                    },
                },
            },
            0b0110011 => switch (funct3) {
                0b000 => switch (funct7) {
                    0b0000000 => .{
                        .add = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0100000 => .{
                        .sub = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000001 => .{
                        .mul = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b001 => switch (funct7) {
                    0b0000000 => .{
                        .sll = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000001 => .{
                        .mulh = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0110000 => .{
                        .rol = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b010 => switch (funct7) {
                    0b0000000 => .{
                        .slt = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000001 => .{
                        .mulhsu = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0010000 => .{
                        .sh1add = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b011 => switch (funct7) {
                    0b0000000 => .{
                        .sltu = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000001 => .{
                        .mulhu = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b100 => switch (funct7) {
                    0b0000000 => .{
                        .xor = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000001 => .{
                        .div = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0100000 => .{
                        .xnor = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000101 => .{
                        .min = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0010000 => .{
                        .sh2add = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000100 => if (decodeRs2(from) == 0) .{
                        .zext_h = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                        },
                    } else DecodeError.UnknownInstruction,
                    else => DecodeError.UnknownInstruction,
                },
                0b101 => switch (funct7) {
                    0b0000000 => .{
                        .srl = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0100000 => .{
                        .sra = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000001 => .{
                        .divu = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0110000 => .{
                        .ror = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000101 => .{
                        .minu = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b110 => switch (funct7) {
                    0b0000000 => .{
                        .@"or" = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000001 => .{
                        .rem = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0100000 => .{
                        .orn = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000101 => .{
                        .max = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0010000 => .{
                        .sh3add = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b111 => switch (funct7) {
                    0b0000000 => .{
                        .@"and" = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000001 => .{
                        .remu = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0100000 => .{
                        .andn = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    0b0000101 => .{
                        .maxu = .{
                            .rd = try toRegisterChecked(decodeRd(from)),
                            .rs1 = try toRegisterChecked(decodeRs1(from)),
                            .rs2 = try toRegisterChecked(decodeRs2(from)),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
            },
            0b0001111 => switch (funct3) {
                0b000 => .{ .fence = {} },
                0b001 => .{ .fence_i = {} },
                else => DecodeError.UnknownInstruction,
            },
            0b1110011 => switch (funct3) {
                0b000 => switch (decodeRs2(from)) {
                    0b00000 => .{ .ecall = {} },
                    0b00001 => .{ .ebreak = {} },
                    0b00010 => .{ .mret = {} },
                    0b00101 => .{ .wfi = {} },
                    else => DecodeError.UnknownInstruction,
                },
                0b001 => .{
                    .csrrw = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .csr = decodeCsr(from),
                    },
                },
                0b010 => .{
                    .csrrs = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .csr = decodeCsr(from),
                    },
                },
                0b011 => .{
                    .csrrc = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .rs1 = try toRegisterChecked(decodeRs1(from)),
                        .csr = decodeCsr(from),
                    },
                },
                0b101 => .{
                    .csrrwi = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .uimm = decodeRs1(from),
                        .csr = decodeCsr(from),
                    },
                },
                0b110 => .{
                    .csrrsi = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .uimm = decodeRs1(from),
                        .csr = decodeCsr(from),
                    },
                },
                0b111 => .{
                    .csrrci = .{
                        .rd = try toRegisterChecked(decodeRd(from)),
                        .uimm = decodeRs1(from),
                        .csr = decodeCsr(from),
                    },
                },
                else => DecodeError.UnknownInstruction,
            },
            0b0000111 => switch (funct3) {
                0b010 => .{
                    .flw = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                0b011 => .{
                    .fld = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .imm = @truncate(decodeImmediate(from, .i)),
                    },
                },
                else => DecodeError.UnknownInstruction,
            },
            0b0100111 => switch (funct3) {
                0b010 => .{
                    .fsw = .{
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .imm = @truncate(decodeImmediate(from, .s)),
                    },
                },
                0b011 => .{
                    .fsd = .{
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .imm = @truncate(decodeImmediate(from, .s)),
                    },
                },
                else => DecodeError.UnknownInstruction,
            },
            0b1000011 => switch (decodeFmt(from)) {
                0b00 => .{
                    .fmadd_s = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rs3 = decodeRs3(from),
                        .rm = funct3,
                    },
                },
                0b01 => .{
                    .fmadd_d = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rs3 = decodeRs3(from),
                        .rm = funct3,
                    },
                },
                else => DecodeError.UnknownInstruction,
            },
            0b1000111 => switch (decodeFmt(from)) {
                0b00 => .{
                    .fmsub_s = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rs3 = decodeRs3(from),
                        .rm = funct3,
                    },
                },
                0b01 => .{
                    .fmsub_d = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rs3 = decodeRs3(from),
                        .rm = funct3,
                    },
                },
                else => DecodeError.UnknownInstruction,
            },
            0b1001011 => switch (decodeFmt(from)) {
                0b00 => .{
                    .fnmsub_s = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rs3 = decodeRs3(from),
                        .rm = funct3,
                    },
                },
                0b01 => .{
                    .fnmsub_d = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rs3 = decodeRs3(from),
                        .rm = funct3,
                    },
                },
                else => DecodeError.UnknownInstruction,
            },
            0b1001111 => switch (decodeFmt(from)) {
                0b00 => .{
                    .fnmadd_s = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rs3 = decodeRs3(from),
                        .rm = funct3,
                    },
                },
                0b01 => .{
                    .fnmadd_d = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rs3 = decodeRs3(from),
                        .rm = funct3,
                    },
                },
                else => DecodeError.UnknownInstruction,
            },
            0b1010011 => switch (funct7) {
                0b0000000 => .{
                    .fadd_s = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rm = funct3,
                    },
                },
                0b0000100 => .{
                    .fsub_s = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rm = funct3,
                    },
                },
                0b0001000 => .{
                    .fmul_s = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rm = funct3,
                    },
                },
                0b0001100 => .{
                    .fdiv_s = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rm = funct3,
                    },
                },
                0b0101100 => .{
                    .fsqrt_s = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rm = funct3,
                    },
                },
                0b0010000 => switch (funct3) {
                    0b000 => .{
                        .fsgnj_s = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    0b001 => .{
                        .fsgnjn_s = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    0b010 => .{
                        .fsgnjx_s = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b0010100 => switch (funct3) {
                    0b000 => .{
                        .fmin_s = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    0b001 => .{
                        .fmax_s = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b1100000 => switch (decodeRs2(from)) {
                    0b00000 => .{
                        .fcvt_w_s = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rm = funct3,
                        },
                    },
                    0b00001 => .{
                        .fcvt_wu_s = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rm = funct3,
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b1110000 => switch (funct3) {
                    0b000 => .{
                        .fmv_x_w = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                        },
                    },
                    0b001 => .{
                        .fclass_s = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b1010000 => switch (funct3) {
                    0b010 => .{
                        .feq_s = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    0b001 => .{
                        .flt_s = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    0b000 => .{
                        .fle_s = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b1101000 => switch (decodeRs2(from)) {
                    0b00000 => .{
                        .fcvt_s_w = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rm = funct3,
                        },
                    },
                    0b00001 => .{
                        .fcvt_s_wu = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rm = funct3,
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b1111000 => .{
                    .fmv_w_x = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                    },
                },
                0b0000001 => .{
                    .fadd_d = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rm = funct3,
                    },
                },
                0b0000101 => .{
                    .fsub_d = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rm = funct3,
                    },
                },
                0b0001001 => .{
                    .fmul_d = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rm = funct3,
                    },
                },
                0b0001101 => .{
                    .fdiv_d = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rs2 = decodeRs2(from),
                        .rm = funct3,
                    },
                },
                0b0101101 => .{
                    .fsqrt_d = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rm = funct3,
                    },
                },
                0b0010001 => switch (funct3) {
                    0b000 => .{
                        .fsgnj_d = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    0b001 => .{
                        .fsgnjn_d = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    0b010 => .{
                        .fsgnjx_d = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b0010101 => switch (funct3) {
                    0b000 => .{
                        .fmin_d = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    0b001 => .{
                        .fmax_d = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b0100000 => .{
                    .fcvt_s_d = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rm = funct3,
                    },
                },
                0b0100001 => .{
                    .fcvt_d_s = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                        .rm = funct3,
                    },
                },
                0b1010001 => switch (funct3) {
                    0b010 => .{
                        .feq_d = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    0b001 => .{
                        .flt_d = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    0b000 => .{
                        .fle_d = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rs2 = decodeRs2(from),
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b1110001 => .{
                    .fclass_d = .{
                        .rd = decodeRd(from),
                        .rs1 = decodeRs1(from),
                    },
                },
                0b1100001 => switch (decodeRs2(from)) {
                    0b00000 => .{
                        .fcvt_w_d = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rm = funct3,
                        },
                    },
                    0b00001 => .{
                        .fcvt_wu_d = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rm = funct3,
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                0b1101001 => switch (decodeRs2(from)) {
                    0b00000 => .{
                        .fcvt_d_w = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rm = funct3,
                        },
                    },
                    0b00001 => .{
                        .fcvt_d_wu = .{
                            .rd = decodeRd(from),
                            .rs1 = decodeRs1(from),
                            .rm = funct3,
                        },
                    },
                    else => DecodeError.UnknownInstruction,
                },
                else => DecodeError.UnknownInstruction,
            },
            else => return DecodeError.UnknownInstruction,
        };
    }

    pub inline fn encode(this: Instruction) u32 {
        return switch (this) {
            .lui => |i| encodeOpcode(0b0110111) |
                encodeRd(i.rd) |
                encodeImmediate(i.imm, .u),
            .auipc => |i| encodeOpcode(0b0010111) |
                encodeRd(i.rd) |
                encodeImmediate(i.imm, .u),
            .jal => |i| encodeOpcode(0b1101111) |
                encodeRd(i.rd) |
                encodeImmediate(i.imm, .j),
            .jalr => |i| encodeOpcode(0b1100111) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .beq => |i| encodeOpcode(0b1100011) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeImmediate(i.imm, .b),
            .bne => |i| encodeOpcode(0b1100011) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeImmediate(i.imm, .b),
            .blt => |i| encodeOpcode(0b1100011) |
                encodeFunct3(0b100) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeImmediate(i.imm, .b),
            .bge => |i| encodeOpcode(0b1100011) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeImmediate(i.imm, .b),
            .bltu => |i| encodeOpcode(0b1100011) |
                encodeFunct3(0b110) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeImmediate(i.imm, .b),
            .bgeu => |i| encodeOpcode(0b1100011) |
                encodeFunct3(0b111) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeImmediate(i.imm, .b),
            .lb => |i| encodeOpcode(0b0000011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .lh => |i| encodeOpcode(0b0000011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .lw => |i| encodeOpcode(0b0000011) |
                encodeRd(i.rd) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .lbu => |i| encodeOpcode(0b0000011) |
                encodeRd(i.rd) |
                encodeFunct3(0b100) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .lhu => |i| encodeOpcode(0b0000011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .sb => |i| encodeOpcode(0b0100011) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeImmediate(i.imm, .s),
            .sh => |i| encodeOpcode(0b0100011) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeImmediate(i.imm, .s),
            .sw => |i| encodeOpcode(0b0100011) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeImmediate(i.imm, .s),
            .addi => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .slti => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .sltiu => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b011) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .xori => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b100) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .ori => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b110) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .andi => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b111) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .slli => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.shamt),
            .srli => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeRs2(i.shamt) | encodeFunct7(0b0000000),
            .srai => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeRs2(i.shamt) | encodeFunct7(0b0100000),
            .add => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000000),
            .sub => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0100000),
            .sll => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000000),
            .slt => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000000),
            .sltu => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b011) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000000),
            .xor => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b100) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000000),
            .srl => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000000),
            .sra => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0100000),
            .@"or" => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b110) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000000),
            .@"and" => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b111) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000000),
            .fence => encodeOpcode(0b0001111),
            .ecall => encodeOpcode(0b1110011) |
                encodeFunct3(0) |
                encodeRd(0) |
                encodeRs1(0) |
                encodeImmediate(0, .i),
            .ebreak => encodeOpcode(0b1110011) |
                encodeFunct3(0) |
                encodeRd(0) |
                encodeRs1(0) |
                encodeImmediate(1, .i),
            .mul => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000001),
            .mulh => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000001),
            .mulhsu => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000001),
            .mulhu => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b011) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000001),
            .div => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b100) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000001),
            .divu => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000001),
            .rem => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b110) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000001),
            .remu => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b111) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000001),
            .flw => |i| encodeOpcode(0b0000111) |
                encodeRd(i.rd) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .fsw => |i| encodeOpcode(0b0100111) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeImmediate(i.imm, .s),
            .fmadd_s => |i| encodeOpcode(0b1000011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeRs3(i.rs3) |
                encodeFmt(0b00),
            .fmsub_s => |i| encodeOpcode(0b1000111) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeRs3(i.rs3) |
                encodeFmt(0b00),
            .fnmsub_s => |i| encodeOpcode(0b1001011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeRs3(i.rs3) |
                encodeFmt(0b00),
            .fnmadd_s => |i| encodeOpcode(0b1001111) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeRs3(i.rs3) |
                encodeFmt(0b00),
            .fadd_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000000),
            .fsub_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000100),
            .fmul_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0001000),
            .fdiv_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0001100),
            .fsqrt_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeFunct7(0b0101100),
            .fsgnj_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010000),
            .fsgnjn_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010000),
            .fsgnjx_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010000),
            .fmin_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010100),
            .fmax_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010100),
            .fcvt_w_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeFunct7(0b1100000),
            .fcvt_wu_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(1) |
                encodeFunct7(0b1100000),
            .fmv_x_w => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeFunct7(0b1110000),
            .feq_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b1010000),
            .flt_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b1010000),
            .fle_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b1010000),
            .fclass_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeFunct7(0b1110000),
            .fcvt_s_w => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeFunct7(0b1101000),
            .fcvt_s_wu => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(1) |
                encodeFunct7(0b1101000),
            .fmv_w_x => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeFunct7(0b1111000),
            .fld => |i| encodeOpcode(0b0000111) |
                encodeRd(i.rd) |
                encodeFunct3(0b011) |
                encodeRs1(i.rs1) |
                encodeImmediate(i.imm, .i),
            .fsd => |i| encodeOpcode(0b0100111) |
                encodeFunct3(0b011) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeImmediate(i.imm, .s),
            .fmadd_d => |i| encodeOpcode(0b1000011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeRs3(i.rs3) |
                encodeFmt(0b01),
            .fmsub_d => |i| encodeOpcode(0b1000111) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeRs3(i.rs3) |
                encodeFmt(0b01),
            .fnmsub_d => |i| encodeOpcode(0b1001011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeRs3(i.rs3) |
                encodeFmt(0b01),
            .fnmadd_d => |i| encodeOpcode(0b1001111) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeRs3(i.rs3) |
                encodeFmt(0b01),
            .fadd_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000001),
            .fsub_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000101),
            .fmul_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0001001),
            .fdiv_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0001101),
            .fsqrt_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeFunct7(0b0101101),
            .fsgnj_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010001),
            .fsgnjn_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010001),
            .fsgnjx_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010001),
            .fmin_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010101),
            .fmax_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010101),
            .fcvt_s_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(1) | encodeFunct7(0b0100000),
            .fcvt_d_s => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeFunct7(0b0100001),
            .feq_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b1010001),
            .flt_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b1010001),
            .fle_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b000) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b1010001),
            .fclass_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeFunct7(0b1110001),
            .fcvt_w_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeFunct7(0b1100001),
            .fcvt_wu_d => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(1) |
                encodeFunct7(0b1100001),
            .fcvt_d_w => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeFunct7(0b1101001),
            .fcvt_d_wu => |i| encodeOpcode(0b1010011) |
                encodeRd(i.rd) |
                encodeFunct3(i.rm) |
                encodeRs1(i.rs1) |
                encodeRs2(1) |
                encodeFunct7(0b1101001),
            .csrrw => |i| encodeOpcode(0b1110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeCsr(i.csr),
            .csrrs => |i| encodeOpcode(0b1110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeCsr(i.csr),
            .csrrc => |i| encodeOpcode(0b1110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b011) |
                encodeRs1(i.rs1) |
                encodeCsr(i.csr),
            .csrrwi => |i| encodeOpcode(0b1110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.uimm) |
                encodeCsr(i.csr),
            .csrrsi => |i| encodeOpcode(0b1110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b110) |
                encodeRs1(i.uimm) |
                encodeCsr(i.csr),
            .csrrci => |i| encodeOpcode(0b1110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b111) |
                encodeRs1(i.uimm) |
                encodeCsr(i.csr),
            .fence_i => encodeOpcode(0b0001111) | encodeFunct3(0b001),
            .sh1add => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b010) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010000),
            .sh2add => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b100) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010000),
            .sh3add => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b110) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0010000),
            .andn => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b111) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0100000),
            .orn => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b110) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0100000),
            .xnor => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b100) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0100000),
            .max => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b110) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000101),
            .maxu => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b111) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000101),
            .min => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b100) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000101),
            .minu => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0000101),
            .rol => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0110000),
            .ror => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeRs2(i.rs2) |
                encodeFunct7(0b0110000),
            .zext_h => |i| encodeOpcode(0b0110011) |
                encodeRd(i.rd) |
                encodeFunct3(0b100) |
                encodeRs1(i.rs1) |
                encodeRs2(0) |
                encodeFunct7(0b0000100),
            .clz => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeCsr(0x600), // 0b0110000_00000
            .ctz => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeCsr(0x601), // 0b0110000_00001
            .cpop => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeCsr(0x602), // 0b0110000_00010
            .sext_b => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeCsr(0x604), // 0b0110000_00100
            .sext_h => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b001) |
                encodeRs1(i.rs1) |
                encodeCsr(0x605), // 0b0110000_00101
            .rori => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeRs2(i.shamt) |
                encodeFunct7(0b0110000),
            .orc_b => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeCsr(0x287),
            .rev8 => |i| encodeOpcode(0b0010011) |
                encodeRd(i.rd) |
                encodeFunct3(0b101) |
                encodeRs1(i.rs1) |
                encodeCsr(0x698),
            .mret => encodeOpcode(0b1110011) |
                encodeFunct7(0b0011000) |
                encodeRs2(0b00010),
            .wfi => encodeOpcode(0b1110011) |
                encodeFunct7(0b0001000) |
                encodeRs2(0b00101),
        };
    }

    pub inline fn format(this: Instruction, writer: anytype) !void {
        switch (this) {
            .lui => |i| try writer.print("lui {s}, {d}", .{ Registers.getAbiName(i.rd), i.imm }),
            .auipc => |i| try writer.print("auipc {s}, {d}", .{ Registers.getAbiName(i.rd), i.imm }),
            .jal => |i| try writer.print("jal {s}, {d}", .{ Registers.getAbiName(i.rd), i.imm }),
            .jalr => |i| try writer.print("jalr {s}, {s}, {d}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), i.imm }),
            .beq => |i| try writer.print("beq {s}, {s}, {d}", .{ Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2), i.imm }),
            .bne => |i| try writer.print("bne {s}, {s}, {d}", .{ Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2), i.imm }),
            .blt => |i| try writer.print("blt {s}, {s}, {d}", .{ Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2), i.imm }),
            .bge => |i| try writer.print("bge {s}, {s}, {d}", .{ Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2), i.imm }),
            .bltu => |i| try writer.print("bltu {s}, {s}, {d}", .{ Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2), i.imm }),
            .bgeu => |i| try writer.print("bgeu {s}, {s}, {d}", .{ Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2), i.imm }),
            .lb => |i| try writer.print("lb {s}, {d}({s})", .{ Registers.getAbiName(i.rd), i.imm, Registers.getAbiName(i.rs1) }),
            .lh => |i| try writer.print("lh {s}, {d}({s})", .{ Registers.getAbiName(i.rd), i.imm, Registers.getAbiName(i.rs1) }),
            .lw => |i| try writer.print("lw {s}, {d}({s})", .{ Registers.getAbiName(i.rd), i.imm, Registers.getAbiName(i.rs1) }),
            .lbu => |i| try writer.print("lbu {s}, {d}({s})", .{ Registers.getAbiName(i.rd), i.imm, Registers.getAbiName(i.rs1) }),
            .lhu => |i| try writer.print("lhu {s}, {d}({s})", .{ Registers.getAbiName(i.rd), i.imm, Registers.getAbiName(i.rs1) }),
            .sb => |i| try writer.print("sb {s}, {d}({s})", .{ Registers.getAbiName(i.rs2), i.imm, Registers.getAbiName(i.rs1) }),
            .sh => |i| try writer.print("sh {s}, {d}({s})", .{ Registers.getAbiName(i.rs2), i.imm, Registers.getAbiName(i.rs1) }),
            .sw => |i| try writer.print("sw {s}, {d}({s})", .{ Registers.getAbiName(i.rs2), i.imm, Registers.getAbiName(i.rs1) }),
            .addi => |i| try writer.print("addi {s}, {s}, {d}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), i.imm }),
            .slti => |i| try writer.print("slti {s}, {s}, {d}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), i.imm }),
            .sltiu => |i| try writer.print("sltiu {s}, {s}, {d}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), i.imm }),
            .xori => |i| try writer.print("xori {s}, {s}, {d}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), i.imm }),
            .ori => |i| try writer.print("ori {s}, {s}, {d}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), i.imm }),
            .andi => |i| try writer.print("andi {s}, {s}, {d}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), i.imm }),
            .slli => |i| try writer.print("slli {s}, {s}, {d}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), i.shamt }),
            .srli => |i| try writer.print("srli {s}, {s}, {d}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), i.shamt }),
            .srai => |i| try writer.print("srai {s}, {s}, {d}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), i.shamt }),
            .add => |i| try writer.print("add {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .sub => |i| try writer.print("sub {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .sll => |i| try writer.print("sll {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .slt => |i| try writer.print("slt {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .sltu => |i| try writer.print("sltu {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .xor => |i| try writer.print("xor {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .srl => |i| try writer.print("srl {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .sra => |i| try writer.print("sra {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .@"or" => |i| try writer.print("or {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .@"and" => |i| try writer.print("and {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .fence => try writer.print("fence", .{}),
            .ecall => try writer.print("ecall", .{}),
            .ebreak => try writer.print("ebreak", .{}),
            .mul => |i| try writer.print("mul {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .mulh => |i| try writer.print("mulh {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .mulhsu => |i| try writer.print("mulhsu {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .mulhu => |i| try writer.print("mulhu {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .div => |i| try writer.print("div {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .divu => |i| try writer.print("divu {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .rem => |i| try writer.print("rem {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .remu => |i| try writer.print("remu {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .flw => |i| try writer.print("flw {s}, {d}({s})", .{ Registers.getFloatAbiName(i.rd), i.imm, Registers.getAbiName(i.rs1) }),
            .fsw => |i| try writer.print("fsw {s}, {d}({s})", .{ Registers.getFloatAbiName(i.rs2), i.imm, Registers.getAbiName(i.rs1) }),
            .fmadd_s => |i| try writer.print("fmadd.s {s}, {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2), Registers.getFloatAbiName(i.rs3) }),
            .fmsub_s => |i| try writer.print("fmsub.s {s}, {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2), Registers.getFloatAbiName(i.rs3) }),
            .fnmsub_s => |i| try writer.print("fnmsub.s {s}, {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2), Registers.getFloatAbiName(i.rs3) }),
            .fnmadd_s => |i| try writer.print("fnmadd.s {s}, {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2), Registers.getFloatAbiName(i.rs3) }),
            .fadd_s => |i| try writer.print("fadd.s {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fsub_s => |i| try writer.print("fsub.s {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fmul_s => |i| try writer.print("fmul.s {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fdiv_s => |i| try writer.print("fdiv.s {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fsqrt_s => |i| try writer.print("fsqrt.s {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1) }),
            .fsgnj_s => |i| try writer.print("fsgnj.s {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fsgnjn_s => |i| try writer.print("fsgnjn.s {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fsgnjx_s => |i| try writer.print("fsgnjx.s {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fmin_s => |i| try writer.print("fmin.s {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fmax_s => |i| try writer.print("fmax.s {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fcvt_w_s => |i| try writer.print("fcvt.w.s {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1) }),
            .fcvt_wu_s => |i| try writer.print("fcvt.wu.s {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1) }),
            .fmv_x_w => |i| try writer.print("fmv.x.w {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1) }),
            .feq_s => |i| try writer.print("feq.s {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .flt_s => |i| try writer.print("flt.s {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fle_s => |i| try writer.print("fle.s {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fclass_s => |i| try writer.print("fclass.s {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1) }),
            .fcvt_s_w => |i| try writer.print("fcvt.s.w {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .fcvt_s_wu => |i| try writer.print("fcvt.s.wu {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .fmv_w_x => |i| try writer.print("fmv.w.x {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .fld => |i| try writer.print("fld {s}, {d}({s})", .{ Registers.getFloatAbiName(i.rd), i.imm, Registers.getAbiName(i.rs1) }),
            .fsd => |i| try writer.print("fsd {s}, {d}({s})", .{ Registers.getFloatAbiName(i.rs2), i.imm, Registers.getAbiName(i.rs1) }),
            .fmadd_d => |i| try writer.print("fmadd.d {s}, {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2), Registers.getFloatAbiName(i.rs3) }),
            .fmsub_d => |i| try writer.print("fmsub.d {s}, {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2), Registers.getFloatAbiName(i.rs3) }),
            .fnmsub_d => |i| try writer.print("fnmsub.d {s}, {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2), Registers.getFloatAbiName(i.rs3) }),
            .fnmadd_d => |i| try writer.print("fnmadd.d {s}, {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2), Registers.getFloatAbiName(i.rs3) }),
            .fadd_d => |i| try writer.print("fadd.d {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fsub_d => |i| try writer.print("fsub.d {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fmul_d => |i| try writer.print("fmul.d {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fdiv_d => |i| try writer.print("fdiv.d {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fsqrt_d => |i| try writer.print("fsqrt.d {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1) }),
            .fsgnj_d => |i| try writer.print("fsgnj.d {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fsgnjn_d => |i| try writer.print("fsgnjn.d {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fsgnjx_d => |i| try writer.print("fsgnjx.d {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fmin_d => |i| try writer.print("fmin.d {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fmax_d => |i| try writer.print("fmax.d {s}, {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fcvt_s_d => |i| try writer.print("fcvt.s.d {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1) }),
            .fcvt_d_s => |i| try writer.print("fcvt.d.s {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getFloatAbiName(i.rs1) }),
            .feq_d => |i| try writer.print("feq.d {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .flt_d => |i| try writer.print("flt.d {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fle_d => |i| try writer.print("fle.d {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1), Registers.getFloatAbiName(i.rs2) }),
            .fclass_d => |i| try writer.print("fclass.d {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1) }),
            .fcvt_w_d => |i| try writer.print("fcvt.w.d {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1) }),
            .fcvt_wu_d => |i| try writer.print("fcvt.wu.d {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getFloatAbiName(i.rs1) }),
            .fcvt_d_w => |i| try writer.print("fcvt.d.w {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .fcvt_d_wu => |i| try writer.print("fcvt.d.wu {s}, {s}", .{ Registers.getFloatAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .csrrw => |i| try writer.print("csrrw {s}, 0x{x:0>3}, {s}", .{ Registers.getAbiName(i.rd), i.csr, Registers.getAbiName(i.rs1) }),
            .csrrs => |i| try writer.print("csrrs {s}, 0x{x:0>3}, {s}", .{ Registers.getAbiName(i.rd), i.csr, Registers.getAbiName(i.rs1) }),
            .csrrc => |i| try writer.print("csrrc {s}, 0x{x:0>3}, {s}", .{ Registers.getAbiName(i.rd), i.csr, Registers.getAbiName(i.rs1) }),
            .csrrwi => |i| try writer.print("csrrwi {s}, 0x{x:0>3}, {d}", .{ Registers.getAbiName(i.rd), i.csr, i.uimm }),
            .csrrsi => |i| try writer.print("csrrsi {s}, 0x{x:0>3}, {d}", .{ Registers.getAbiName(i.rd), i.csr, i.uimm }),
            .csrrci => |i| try writer.print("csrrci {s}, 0x{x:0>3}, {d}", .{ Registers.getAbiName(i.rd), i.csr, i.uimm }),
            .fence_i => try writer.print("fence.i", .{}),
            .sh1add => |i| try writer.print("sh1add {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .sh2add => |i| try writer.print("sh2add {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .sh3add => |i| try writer.print("sh3add {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .andn => |i| try writer.print("andn {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .orn => |i| try writer.print("orn {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .xnor => |i| try writer.print("xnor {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .clz => |i| try writer.print("clz {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .ctz => |i| try writer.print("ctz {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .cpop => |i| try writer.print("cpop {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .max => |i| try writer.print("max {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .maxu => |i| try writer.print("maxu {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .min => |i| try writer.print("min {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .minu => |i| try writer.print("minu {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .sext_b => |i| try writer.print("sext.b {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .sext_h => |i| try writer.print("sext.h {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .zext_h => |i| try writer.print("zext.h {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .rol => |i| try writer.print("rol {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .ror => |i| try writer.print("ror {s}, {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), Registers.getAbiName(i.rs2) }),
            .rori => |i| try writer.print("rori {s}, {s}, {d}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1), i.shamt }),
            .orc_b => |i| try writer.print("orc.b {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .rev8 => |i| try writer.print("rev8 {s}, {s}", .{ Registers.getAbiName(i.rd), Registers.getAbiName(i.rs1) }),
            .mret => try writer.print("mret", .{}),
            .wfi => try writer.print("wfi", .{}),
        }
    }
};

test "Instruction opcode decode & encode" {
    const opcode: u32 = Instruction.decodeOpcode(0xaaffbb00);
    const raw: u32 = Instruction.encodeOpcode(opcode);

    try std.testing.expectEqual(opcode, Instruction.decodeOpcode(raw));
}

test "Instruction rd decode & encode" {
    const rd: u32 = Instruction.decodeRd(0xaaffbb00);
    const raw: u32 = Instruction.encodeRd(rd);

    try std.testing.expectEqual(rd, Instruction.decodeRd(raw));
}

test "Instruction funct3 decode & encode" {
    const funct3: u32 = Instruction.decodeFunct3(0xaaffbb00);
    const raw: u32 = Instruction.encodeFunct3(funct3);

    try std.testing.expectEqual(funct3, Instruction.decodeFunct3(raw));
}

test "Instruction rs1 decode & encode" {
    const rs1: u32 = Instruction.decodeRs1(0xaaffbb00);
    const raw: u32 = Instruction.encodeRs1(rs1);

    try std.testing.expectEqual(rs1, Instruction.decodeRs1(raw));
}

test "Instruction rs2 decode & encode" {
    const rs2: u32 = Instruction.decodeRs2(0xaaffbb00);
    const raw: u32 = Instruction.encodeRs2(rs2);

    try std.testing.expectEqual(rs2, Instruction.decodeRs2(raw));
}

test "Instruction funct7 decode & encode" {
    const funct7: u32 = Instruction.decodeFunct7(0xaaffbb00);
    const raw: u32 = Instruction.encodeFunct7(funct7);

    try std.testing.expectEqual(funct7, Instruction.decodeFunct7(raw));
}

test "Instruction i-immediate deocde & encode" {
    const imm: i32 = Instruction.decodeImmediate(0xaaffbb00, .i);
    const raw: u32 = Instruction.encodeImmediate(imm, .i);

    try std.testing.expectEqual(imm, Instruction.decodeImmediate(raw, .i));
}

test "Instruction s-immediate decode & encode" {
    const imm: i32 = Instruction.decodeImmediate(0xaaffbb00, .s);
    const raw: u32 = Instruction.encodeImmediate(imm, .s);

    try std.testing.expectEqual(imm, Instruction.decodeImmediate(raw, .s));
}

test "Instruction b-immediate decode & encode" {
    const imm: i32 = Instruction.decodeImmediate(0xaaffbb00, .b);
    const raw: u32 = Instruction.encodeImmediate(imm, .b);

    try std.testing.expectEqual(imm, Instruction.decodeImmediate(raw, .b));
}

test "Instruction u-immediate decode & encode" {
    const imm: i32 = Instruction.decodeImmediate(0xaaffbb00, .u);
    const raw: u32 = Instruction.encodeImmediate(imm, .u);

    try std.testing.expectEqual(imm, Instruction.decodeImmediate(raw, .u));
}

test "Instruction j-immediate decode & encode" {
    const imm: i32 = Instruction.decodeImmediate(0xaaffbb00, .j);
    const raw: u32 = Instruction.encodeImmediate(imm, .j);

    try std.testing.expectEqual(imm, Instruction.decodeImmediate(raw, .j));
}

test "Instruction addi encode & decode" {
    const expected: Instruction = .{ .addi = .{ .rd = 1, .rs1 = 2, .imm = 12 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction slti encode & decode" {
    const expected: Instruction = .{ .slti = .{ .rd = 1, .rs1 = 2, .imm = 12 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sltiu encode & decode" {
    const expected: Instruction = .{ .sltiu = .{ .rd = 1, .rs1 = 2, .imm = 12 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction ori encode & decode" {
    const expected: Instruction = .{ .ori = .{ .rd = 1, .rs1 = 2, .imm = 12 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction andi encode & decode" {
    const expected: Instruction = .{ .andi = .{ .rd = 1, .rs1 = 2, .imm = 12 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction lui encode & decode" {
    const expected: Instruction = .{ .lui = .{ .rd = 1, .imm = 0x12345 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction auipc encode & decode" {
    const expected: Instruction = .{ .auipc = .{ .rd = 2, .imm = 0x67890 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction jal encode & decode" {
    const expected: Instruction = .{ .jal = .{ .rd = 3, .imm = 100 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction jalr encode & decode" {
    const expected: Instruction = .{ .jalr = .{ .rd = 4, .rs1 = 5, .imm = -20 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction beq encode & decode" {
    const expected: Instruction = .{ .beq = .{ .rs1 = 6, .rs2 = 7, .imm = 50 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction bne encode & decode" {
    const expected: Instruction = .{ .bne = .{ .rs1 = 8, .rs2 = 9, .imm = -30 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction blt encode & decode" {
    const expected: Instruction = .{ .blt = .{ .rs1 = 10, .rs2 = 11, .imm = 24 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction bge encode & decode" {
    const expected: Instruction = .{ .bge = .{ .rs1 = 12, .rs2 = 13, .imm = -16 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction bltu encode & decode" {
    const expected: Instruction = .{ .bltu = .{ .rs1 = 14, .rs2 = 15, .imm = 40 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction bgeu encode & decode" {
    const expected: Instruction = .{ .bgeu = .{ .rs1 = 16, .rs2 = 17, .imm = -26 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction lb encode & decode" {
    const expected: Instruction = .{ .lb = .{ .rd = 1, .rs1 = 2, .imm = 10 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction lh encode & decode" {
    const expected: Instruction = .{ .lh = .{ .rd = 3, .rs1 = 4, .imm = -5 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction lw encode & decode" {
    const expected: Instruction = .{ .lw = .{ .rd = 5, .rs1 = 6, .imm = 20 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction lbu encode & decode" {
    const expected: Instruction = .{ .lbu = .{ .rd = 7, .rs1 = 8, .imm = -10 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction lhu encode & decode" {
    const expected: Instruction = .{ .lhu = .{ .rd = 9, .rs1 = 10, .imm = 15 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sb encode & decode" {
    const expected: Instruction = .{ .sb = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sh encode & decode" {
    const expected: Instruction = .{ .sh = .{ .rs1 = 3, .rs2 = 4, .imm = -3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sw encode & decode" {
    const expected: Instruction = .{ .sw = .{ .rs1 = 5, .rs2 = 6, .imm = 12 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction xori encode & decode" {
    const expected: Instruction = .{ .xori = .{ .rd = 1, .rs1 = 2, .imm = 255 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction slli encode & decode" {
    const expected: Instruction = .{ .slli = .{ .rd = 1, .rs1 = 2, .shamt = 5 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction srli encode & decode" {
    const expected: Instruction = .{ .srli = .{ .rd = 3, .rs1 = 4, .shamt = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction srai encode & decode" {
    const expected: Instruction = .{ .srai = .{ .rd = 5, .rs1 = 6, .shamt = 7 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction add encode & decode" {
    const expected: Instruction = .{ .add = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sub encode & decode" {
    const expected: Instruction = .{ .sub = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sll encode & decode" {
    const expected: Instruction = .{ .sll = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction slt encode & decode" {
    const expected: Instruction = .{ .slt = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sltu encode & decode" {
    const expected: Instruction = .{ .sltu = .{ .rd = 7, .rs1 = 8, .rs2 = 9 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction xor encode & decode" {
    const expected: Instruction = .{ .xor = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction srl encode & decode" {
    const expected: Instruction = .{ .srl = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sra encode & decode" {
    const expected: Instruction = .{ .sra = .{ .rd = 7, .rs1 = 8, .rs2 = 9 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction or encode & decode" {
    const expected: Instruction = .{ .@"or" = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction and encode & decode" {
    const expected: Instruction = .{ .@"and" = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction mul encode & decode" {
    const expected: Instruction = .{ .mul = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction mulh encode & decode" {
    const expected: Instruction = .{ .mulh = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction mulhsu encode & decode" {
    const expected: Instruction = .{ .mulhsu = .{ .rd = 7, .rs1 = 8, .rs2 = 9 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction mulhu encode & decode" {
    const expected: Instruction = .{ .mulhu = .{ .rd = 10, .rs1 = 11, .rs2 = 12 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction div encode & decode" {
    const expected: Instruction = .{ .div = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction divu encode & decode" {
    const expected: Instruction = .{ .divu = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction rem encode & decode" {
    const expected: Instruction = .{ .rem = .{ .rd = 7, .rs1 = 8, .rs2 = 9 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction remu encode & decode" {
    const expected: Instruction = .{ .remu = .{ .rd = 10, .rs1 = 11, .rs2 = 12 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fence encode & decode" {
    const expected: Instruction = .{ .fence = {} };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction ecall encode & decode" {
    const expected: Instruction = .{ .ecall = {} };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction ebreak encode & decode" {
    const expected: Instruction = .{ .ebreak = {} };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction flw encode & decode" {
    const expected: Instruction = .{ .flw = .{ .rd = 5, .rs1 = 10, .imm = 128 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction flw negative offset encode & decode" {
    const expected: Instruction = .{ .flw = .{ .rd = 8, .rs1 = 2, .imm = -64 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsw encode & decode" {
    const expected: Instruction = .{ .fsw = .{ .rs1 = 10, .rs2 = 5, .imm = 64 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsw negative offset encode & decode" {
    const expected: Instruction = .{ .fsw = .{ .rs1 = 2, .rs2 = 8, .imm = -32 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmadd_s encode & decode" {
    const expected: Instruction = .{ .fmadd_s = .{ .rd = 1, .rs1 = 2, .rs2 = 3, .rs3 = 4, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmadd_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fmadd_s = .{ .rd = 10, .rs1 = 11, .rs2 = 12, .rs3 = 13, .rm = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmsub_s encode & decode" {
    const expected: Instruction = .{ .fmsub_s = .{ .rd = 1, .rs1 = 2, .rs2 = 3, .rs3 = 4, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmsub_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fmsub_s = .{ .rd = 15, .rs1 = 16, .rs2 = 17, .rs3 = 18, .rm = 2 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fnmsub_s encode & decode" {
    const expected: Instruction = .{ .fnmsub_s = .{ .rd = 5, .rs1 = 6, .rs2 = 7, .rs3 = 8, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fnmsub_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fnmsub_s = .{ .rd = 20, .rs1 = 21, .rs2 = 22, .rs3 = 23, .rm = 4 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fnmadd_s encode & decode" {
    const expected: Instruction = .{ .fnmadd_s = .{ .rd = 9, .rs1 = 10, .rs2 = 11, .rs3 = 12, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fnmadd_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fnmadd_s = .{ .rd = 25, .rs1 = 26, .rs2 = 27, .rs3 = 28, .rm = 1 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fadd_s encode & decode" {
    const expected: Instruction = .{ .fadd_s = .{ .rd = 1, .rs1 = 2, .rs2 = 3, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fadd_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fadd_s = .{ .rd = 10, .rs1 = 11, .rs2 = 12, .rm = 7 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsub_s encode & decode" {
    const expected: Instruction = .{ .fsub_s = .{ .rd = 4, .rs1 = 5, .rs2 = 6, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsub_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fsub_s = .{ .rd = 14, .rs1 = 15, .rs2 = 16, .rm = 2 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmul_s encode & decode" {
    const expected: Instruction = .{ .fmul_s = .{ .rd = 7, .rs1 = 8, .rs2 = 9, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmul_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fmul_s = .{ .rd = 17, .rs1 = 18, .rs2 = 19, .rm = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fdiv_s encode & decode" {
    const expected: Instruction = .{ .fdiv_s = .{ .rd = 10, .rs1 = 11, .rs2 = 12, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fdiv_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fdiv_s = .{ .rd = 20, .rs1 = 21, .rs2 = 22, .rm = 4 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsqrt_s encode & decode" {
    const expected: Instruction = .{ .fsqrt_s = .{ .rd = 1, .rs1 = 2, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsqrt_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fsqrt_s = .{ .rd = 15, .rs1 = 16, .rm = 1 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnj_s encode & decode" {
    const expected: Instruction = .{ .fsgnj_s = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnj_s same registers (fmv.s) encode & decode" {
    const expected: Instruction = .{ .fsgnj_s = .{ .rd = 5, .rs1 = 10, .rs2 = 10 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnjn_s encode & decode" {
    const expected: Instruction = .{ .fsgnjn_s = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnjn_s same registers (fneg.s) encode & decode" {
    const expected: Instruction = .{ .fsgnjn_s = .{ .rd = 8, .rs1 = 12, .rs2 = 12 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnjx_s encode & decode" {
    const expected: Instruction = .{ .fsgnjx_s = .{ .rd = 7, .rs1 = 8, .rs2 = 9 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnjx_s same registers (fabs.s) encode & decode" {
    const expected: Instruction = .{ .fsgnjx_s = .{ .rd = 10, .rs1 = 15, .rs2 = 15 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmin_s encode & decode" {
    const expected: Instruction = .{ .fmin_s = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmin_s high registers encode & decode" {
    const expected: Instruction = .{ .fmin_s = .{ .rd = 28, .rs1 = 29, .rs2 = 30 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmax_s encode & decode" {
    const expected: Instruction = .{ .fmax_s = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmax_s high registers encode & decode" {
    const expected: Instruction = .{ .fmax_s = .{ .rd = 25, .rs1 = 26, .rs2 = 27 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_w_s encode & decode" {
    const expected: Instruction = .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 2, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_w_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fcvt_w_s = .{ .rd = 10, .rs1 = 15, .rm = 1 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_wu_s encode & decode" {
    const expected: Instruction = .{ .fcvt_wu_s = .{ .rd = 3, .rs1 = 4, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_wu_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fcvt_wu_s = .{ .rd = 20, .rs1 = 25, .rm = 2 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmv_x_w encode & decode" {
    const expected: Instruction = .{ .fmv_x_w = .{ .rd = 1, .rs1 = 2 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmv_x_w high registers encode & decode" {
    const expected: Instruction = .{ .fmv_x_w = .{ .rd = 30, .rs1 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction feq_s encode & decode" {
    const expected: Instruction = .{ .feq_s = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction feq_s high registers encode & decode" {
    const expected: Instruction = .{ .feq_s = .{ .rd = 15, .rs1 = 20, .rs2 = 25 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction flt_s encode & decode" {
    const expected: Instruction = .{ .flt_s = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction flt_s high registers encode & decode" {
    const expected: Instruction = .{ .flt_s = .{ .rd = 10, .rs1 = 28, .rs2 = 29 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fle_s encode & decode" {
    const expected: Instruction = .{ .fle_s = .{ .rd = 7, .rs1 = 8, .rs2 = 9 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fle_s high registers encode & decode" {
    const expected: Instruction = .{ .fle_s = .{ .rd = 5, .rs1 = 30, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fclass_s encode & decode" {
    const expected: Instruction = .{ .fclass_s = .{ .rd = 1, .rs1 = 2 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fclass_s high registers encode & decode" {
    const expected: Instruction = .{ .fclass_s = .{ .rd = 25, .rs1 = 30 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_s_w encode & decode" {
    const expected: Instruction = .{ .fcvt_s_w = .{ .rd = 1, .rs1 = 2, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_s_w with rounding mode encode & decode" {
    const expected: Instruction = .{ .fcvt_s_w = .{ .rd = 15, .rs1 = 20, .rm = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_s_wu encode & decode" {
    const expected: Instruction = .{ .fcvt_s_wu = .{ .rd = 3, .rs1 = 4, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_s_wu with rounding mode encode & decode" {
    const expected: Instruction = .{ .fcvt_s_wu = .{ .rd = 25, .rs1 = 30, .rm = 4 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmv_w_x encode & decode" {
    const expected: Instruction = .{ .fmv_w_x = .{ .rd = 1, .rs1 = 2 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmv_w_x high registers encode & decode" {
    const expected: Instruction = .{ .fmv_w_x = .{ .rd = 31, .rs1 = 30 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fld encode & decode" {
    const expected: Instruction = .{ .fld = .{ .rd = 5, .rs1 = 10, .imm = 256 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fld negative offset encode & decode" {
    const expected: Instruction = .{ .fld = .{ .rd = 8, .rs1 = 2, .imm = -128 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsd encode & decode" {
    const expected: Instruction = .{ .fsd = .{ .rs1 = 10, .rs2 = 5, .imm = 128 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsd negative offset encode & decode" {
    const expected: Instruction = .{ .fsd = .{ .rs1 = 2, .rs2 = 8, .imm = -64 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmadd_d encode & decode" {
    const expected: Instruction = .{ .fmadd_d = .{ .rd = 1, .rs1 = 2, .rs2 = 3, .rs3 = 4, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmadd_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fmadd_d = .{ .rd = 10, .rs1 = 11, .rs2 = 12, .rs3 = 13, .rm = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmsub_d encode & decode" {
    const expected: Instruction = .{ .fmsub_d = .{ .rd = 5, .rs1 = 6, .rs2 = 7, .rs3 = 8, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmsub_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fmsub_d = .{ .rd = 15, .rs1 = 16, .rs2 = 17, .rs3 = 18, .rm = 2 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fnmsub_d encode & decode" {
    const expected: Instruction = .{ .fnmsub_d = .{ .rd = 9, .rs1 = 10, .rs2 = 11, .rs3 = 12, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fnmsub_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fnmsub_d = .{ .rd = 20, .rs1 = 21, .rs2 = 22, .rs3 = 23, .rm = 4 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fnmadd_d encode & decode" {
    const expected: Instruction = .{ .fnmadd_d = .{ .rd = 13, .rs1 = 14, .rs2 = 15, .rs3 = 16, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fnmadd_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fnmadd_d = .{ .rd = 25, .rs1 = 26, .rs2 = 27, .rs3 = 28, .rm = 1 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fadd_d encode & decode" {
    const expected: Instruction = .{ .fadd_d = .{ .rd = 1, .rs1 = 2, .rs2 = 3, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fadd_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fadd_d = .{ .rd = 10, .rs1 = 11, .rs2 = 12, .rm = 7 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsub_d encode & decode" {
    const expected: Instruction = .{ .fsub_d = .{ .rd = 4, .rs1 = 5, .rs2 = 6, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsub_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fsub_d = .{ .rd = 14, .rs1 = 15, .rs2 = 16, .rm = 2 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmul_d encode & decode" {
    const expected: Instruction = .{ .fmul_d = .{ .rd = 7, .rs1 = 8, .rs2 = 9, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmul_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fmul_d = .{ .rd = 17, .rs1 = 18, .rs2 = 19, .rm = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fdiv_d encode & decode" {
    const expected: Instruction = .{ .fdiv_d = .{ .rd = 10, .rs1 = 11, .rs2 = 12, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fdiv_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fdiv_d = .{ .rd = 20, .rs1 = 21, .rs2 = 22, .rm = 4 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsqrt_d encode & decode" {
    const expected: Instruction = .{ .fsqrt_d = .{ .rd = 1, .rs1 = 2, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsqrt_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fsqrt_d = .{ .rd = 15, .rs1 = 16, .rm = 1 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnj_d encode & decode" {
    const expected: Instruction = .{ .fsgnj_d = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnj_d same registers (fmv.d) encode & decode" {
    const expected: Instruction = .{ .fsgnj_d = .{ .rd = 5, .rs1 = 10, .rs2 = 10 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnjn_d encode & decode" {
    const expected: Instruction = .{ .fsgnjn_d = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnjn_d same registers (fneg.d) encode & decode" {
    const expected: Instruction = .{ .fsgnjn_d = .{ .rd = 8, .rs1 = 12, .rs2 = 12 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnjx_d encode & decode" {
    const expected: Instruction = .{ .fsgnjx_d = .{ .rd = 7, .rs1 = 8, .rs2 = 9 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsgnjx_d same registers (fabs.d) encode & decode" {
    const expected: Instruction = .{ .fsgnjx_d = .{ .rd = 10, .rs1 = 15, .rs2 = 15 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmin_d encode & decode" {
    const expected: Instruction = .{ .fmin_d = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmin_d high registers encode & decode" {
    const expected: Instruction = .{ .fmin_d = .{ .rd = 28, .rs1 = 29, .rs2 = 30 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmax_d encode & decode" {
    const expected: Instruction = .{ .fmax_d = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmax_d high registers encode & decode" {
    const expected: Instruction = .{ .fmax_d = .{ .rd = 25, .rs1 = 26, .rs2 = 27 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_s_d encode & decode" {
    const expected: Instruction = .{ .fcvt_s_d = .{ .rd = 1, .rs1 = 2, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_s_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fcvt_s_d = .{ .rd = 15, .rs1 = 20, .rm = 1 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_d_s encode & decode" {
    const expected: Instruction = .{ .fcvt_d_s = .{ .rd = 3, .rs1 = 4, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_d_s with rounding mode encode & decode" {
    const expected: Instruction = .{ .fcvt_d_s = .{ .rd = 25, .rs1 = 30, .rm = 7 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction feq_d encode & decode" {
    const expected: Instruction = .{ .feq_d = .{ .rd = 1, .rs1 = 2, .rs2 = 3 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction feq_d high registers encode & decode" {
    const expected: Instruction = .{ .feq_d = .{ .rd = 15, .rs1 = 20, .rs2 = 25 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction flt_d encode & decode" {
    const expected: Instruction = .{ .flt_d = .{ .rd = 4, .rs1 = 5, .rs2 = 6 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction flt_d high registers encode & decode" {
    const expected: Instruction = .{ .flt_d = .{ .rd = 10, .rs1 = 28, .rs2 = 29 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fle_d encode & decode" {
    const expected: Instruction = .{ .fle_d = .{ .rd = 7, .rs1 = 8, .rs2 = 9 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fle_d high registers encode & decode" {
    const expected: Instruction = .{ .fle_d = .{ .rd = 5, .rs1 = 30, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fclass_d encode & decode" {
    const expected: Instruction = .{ .fclass_d = .{ .rd = 1, .rs1 = 2 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fclass_d high registers encode & decode" {
    const expected: Instruction = .{ .fclass_d = .{ .rd = 25, .rs1 = 30 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_w_d encode & decode" {
    const expected: Instruction = .{ .fcvt_w_d = .{ .rd = 1, .rs1 = 2, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_w_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fcvt_w_d = .{ .rd = 10, .rs1 = 15, .rm = 1 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_wu_d encode & decode" {
    const expected: Instruction = .{ .fcvt_wu_d = .{ .rd = 3, .rs1 = 4, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_wu_d with rounding mode encode & decode" {
    const expected: Instruction = .{ .fcvt_wu_d = .{ .rd = 20, .rs1 = 25, .rm = 2 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_d_w encode & decode" {
    const expected: Instruction = .{ .fcvt_d_w = .{ .rd = 1, .rs1 = 2, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_d_w with rounding mode encode & decode" {
    const expected: Instruction = .{ .fcvt_d_w = .{ .rd = 15, .rs1 = 20, .rm = 7 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_d_wu encode & decode" {
    const expected: Instruction = .{ .fcvt_d_wu = .{ .rd = 5, .rs1 = 6, .rm = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fcvt_d_wu with rounding mode encode & decode" {
    const expected: Instruction = .{ .fcvt_d_wu = .{ .rd = 25, .rs1 = 30, .rm = 4 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction flw max positive offset encode & decode" {
    const expected: Instruction = .{ .flw = .{ .rd = 31, .rs1 = 31, .imm = 2047 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction flw max negative offset encode & decode" {
    const expected: Instruction = .{ .flw = .{ .rd = 0, .rs1 = 0, .imm = -2048 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsw max positive offset encode & decode" {
    const expected: Instruction = .{ .fsw = .{ .rs1 = 31, .rs2 = 31, .imm = 2047 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsw max negative offset encode & decode" {
    const expected: Instruction = .{ .fsw = .{ .rs1 = 0, .rs2 = 0, .imm = -2048 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmadd_s all max registers encode & decode" {
    const expected: Instruction = .{ .fmadd_s = .{ .rd = 31, .rs1 = 31, .rs2 = 31, .rs3 = 31, .rm = 7 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fmadd_d all max registers encode & decode" {
    const expected: Instruction = .{ .fmadd_d = .{ .rd = 31, .rs1 = 31, .rs2 = 31, .rs3 = 31, .rm = 7 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fld max positive offset encode & decode" {
    const expected: Instruction = .{ .fld = .{ .rd = 31, .rs1 = 31, .imm = 2047 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fld max negative offset encode & decode" {
    const expected: Instruction = .{ .fld = .{ .rd = 0, .rs1 = 0, .imm = -2048 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsd max positive offset encode & decode" {
    const expected: Instruction = .{ .fsd = .{ .rs1 = 31, .rs2 = 31, .imm = 2047 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fsd max negative offset encode & decode" {
    const expected: Instruction = .{ .fsd = .{ .rs1 = 0, .rs2 = 0, .imm = -2048 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrw all max values encode & decode" {
    const expected: Instruction = .{ .csrrw = .{ .rd = 31, .rs1 = 31, .csr = 0xFFF } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrw all zero values encode & decode" {
    const expected: Instruction = .{ .csrrw = .{ .rd = 0, .rs1 = 0, .csr = 0x000 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrs all max values encode & decode" {
    const expected: Instruction = .{ .csrrs = .{ .rd = 31, .rs1 = 31, .csr = 0xFFF } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrs all zero values encode & decode" {
    const expected: Instruction = .{ .csrrs = .{ .rd = 0, .rs1 = 0, .csr = 0x000 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrc all max values encode & decode" {
    const expected: Instruction = .{ .csrrc = .{ .rd = 31, .rs1 = 31, .csr = 0xFFF } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrc all zero values encode & decode" {
    const expected: Instruction = .{ .csrrc = .{ .rd = 0, .rs1 = 0, .csr = 0x000 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrwi all max values encode & decode" {
    const expected: Instruction = .{ .csrrwi = .{ .rd = 31, .uimm = 31, .csr = 0xFFF } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrwi all zero values encode & decode" {
    const expected: Instruction = .{ .csrrwi = .{ .rd = 0, .uimm = 0, .csr = 0x000 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrsi all max values encode & decode" {
    const expected: Instruction = .{ .csrrsi = .{ .rd = 31, .uimm = 31, .csr = 0xFFF } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrsi all zero values encode & decode" {
    const expected: Instruction = .{ .csrrsi = .{ .rd = 0, .uimm = 0, .csr = 0x000 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrci all max values encode & decode" {
    const expected: Instruction = .{ .csrrci = .{ .rd = 31, .uimm = 31, .csr = 0xFFF } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrci all zero values encode & decode" {
    const expected: Instruction = .{ .csrrci = .{ .rd = 0, .uimm = 0, .csr = 0x000 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction fence_i encode & decode" {
    const expected: Instruction = .{ .fence_i = {} };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sh1add all max registers encode & decode" {
    const expected: Instruction = .{ .sh1add = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sh1add all zero registers encode & decode" {
    const expected: Instruction = .{ .sh1add = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sh2add all max registers encode & decode" {
    const expected: Instruction = .{ .sh2add = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sh2add all zero registers encode & decode" {
    const expected: Instruction = .{ .sh2add = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sh3add all max registers encode & decode" {
    const expected: Instruction = .{ .sh3add = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sh3add all zero registers encode & decode" {
    const expected: Instruction = .{ .sh3add = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction andn all max registers encode & decode" {
    const expected: Instruction = .{ .andn = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction andn all zero registers encode & decode" {
    const expected: Instruction = .{ .andn = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction orn all max registers encode & decode" {
    const expected: Instruction = .{ .orn = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction orn all zero registers encode & decode" {
    const expected: Instruction = .{ .orn = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction xnor all max registers encode & decode" {
    const expected: Instruction = .{ .xnor = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction xnor all zero registers encode & decode" {
    const expected: Instruction = .{ .xnor = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction max all max registers encode & decode" {
    const expected: Instruction = .{ .max = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction max all zero registers encode & decode" {
    const expected: Instruction = .{ .max = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction maxu all max registers encode & decode" {
    const expected: Instruction = .{ .maxu = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction maxu all zero registers encode & decode" {
    const expected: Instruction = .{ .maxu = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction min all max registers encode & decode" {
    const expected: Instruction = .{ .min = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction min all zero registers encode & decode" {
    const expected: Instruction = .{ .min = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction minu all max registers encode & decode" {
    const expected: Instruction = .{ .minu = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction minu all zero registers encode & decode" {
    const expected: Instruction = .{ .minu = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction rol all max registers encode & decode" {
    const expected: Instruction = .{ .rol = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction rol all zero registers encode & decode" {
    const expected: Instruction = .{ .rol = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction ror all max registers encode & decode" {
    const expected: Instruction = .{ .ror = .{ .rd = 31, .rs1 = 31, .rs2 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction ror all zero registers encode & decode" {
    const expected: Instruction = .{ .ror = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction zext_h all max registers encode & decode" {
    const expected: Instruction = .{ .zext_h = .{ .rd = 31, .rs1 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction zext_h all zero registers encode & decode" {
    const expected: Instruction = .{ .zext_h = .{ .rd = 0, .rs1 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction clz all max registers encode & decode" {
    const expected: Instruction = .{ .clz = .{ .rd = 31, .rs1 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction clz all zero registers encode & decode" {
    const expected: Instruction = .{ .clz = .{ .rd = 0, .rs1 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction ctz all max registers encode & decode" {
    const expected: Instruction = .{ .ctz = .{ .rd = 31, .rs1 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction ctz all zero registers encode & decode" {
    const expected: Instruction = .{ .ctz = .{ .rd = 0, .rs1 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction cpop all max registers encode & decode" {
    const expected: Instruction = .{ .cpop = .{ .rd = 31, .rs1 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction cpop all zero registers encode & decode" {
    const expected: Instruction = .{ .cpop = .{ .rd = 0, .rs1 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sext_b all max registers encode & decode" {
    const expected: Instruction = .{ .sext_b = .{ .rd = 31, .rs1 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sext_b all zero registers encode & decode" {
    const expected: Instruction = .{ .sext_b = .{ .rd = 0, .rs1 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sext_h all max registers encode & decode" {
    const expected: Instruction = .{ .sext_h = .{ .rd = 31, .rs1 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction sext_h all zero registers encode & decode" {
    const expected: Instruction = .{ .sext_h = .{ .rd = 0, .rs1 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction rori max shamt encode & decode" {
    const expected: Instruction = .{ .rori = .{ .rd = 31, .rs1 = 31, .shamt = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction rori zero shamt encode & decode" {
    const expected: Instruction = .{ .rori = .{ .rd = 0, .rs1 = 0, .shamt = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction orc_b all max registers encode & decode" {
    const expected: Instruction = .{ .orc_b = .{ .rd = 31, .rs1 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction orc_b all zero registers encode & decode" {
    const expected: Instruction = .{ .orc_b = .{ .rd = 0, .rs1 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction rev8 all max registers encode & decode" {
    const expected: Instruction = .{ .rev8 = .{ .rd = 31, .rs1 = 31 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction rev8 all zero registers encode & decode" {
    const expected: Instruction = .{ .rev8 = .{ .rd = 0, .rs1 = 0 } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrs read fcsr encode & decode" {
    const expected: Instruction = .{ .csrrs = .{ .rd = 10, .rs1 = 0, .csr = @intFromEnum(Registers.Csr.fcsr) } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrs read cycle encode & decode" {
    const expected: Instruction = .{ .csrrs = .{ .rd = 10, .rs1 = 0, .csr = @intFromEnum(Registers.Csr.cycle) } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "Instruction csrrs read instret encode & decode" {
    const expected: Instruction = .{ .csrrs = .{ .rd = 10, .rs1 = 0, .csr = @intFromEnum(Registers.Csr.instret) } };

    const raw: u32 = expected.encode();
    const actual: Instruction = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "mret encode and decode" {
    const expected: Instruction = .mret;
    const raw: u32 = expected.encode();
    const actual = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "wfi encode and decode" {
    const expected: Instruction = .wfi;
    const raw: u32 = expected.encode();
    const actual = try Instruction.decode(raw);

    try std.testing.expectEqual(expected, actual);
    try std.testing.expectEqual(raw, actual.encode());
}

test "mstatus write preserves WPRI fields" {
    var regs = Registers{};
    regs.privilege = .machine;

    // Write with garbage in reserved fields
    try regs.writeCsr(.mstatus, 0xFFFFFFFF, regs.privilege);

    const val: u32 = try regs.readCsr(.mstatus, regs.privilege);
    // Only MIE, MPIE, MPP should be writable
    try std.testing.expectEqual(@as(u32, 0x1888), val & 0x1FFF);
}

test "mstatus.mpp only accepts valid privilege levels" {
    var regs = Registers{};
    regs.privilege = .machine;

    // Try to set MPP to invalid value (supervisor = 01)
    try regs.writeCsr(.mstatus, 0x800, regs.privilege); // MPP = 01

    // Should default to machine mode
    try std.testing.expectEqual(PrivilegeLevel.machine, regs.mstatus.mpp);
}
