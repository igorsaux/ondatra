const std = @import("std");

const arch = @import("../arch.zig");

pub const EngineConfig = struct {
    pub const State = enum(u32) { ok, trap, halt };

    pub const MemoryCallbacks = struct {
        pub const ReadResult = extern struct {
            value: u32,
            trap: u32,

            pub const ok = ReadResult{ .value = 0, .trap = 0 };

            pub inline fn success(value: u32) ReadResult {
                return .{ .value = value, .trap = 0 };
            }

            pub inline fn fail() ReadResult {
                return .{ .value = 0, .trap = 1 };
            }
        };

        pub const WriteResult = extern struct {
            trap: u32,

            pub const ok = WriteResult{ .trap = 0 };
            pub const fail = WriteResult{ .trap = 1 };
        };

        read_byte: *const fn (ctx: *anyopaque, addr: u32) callconv(.c) ReadResult,
        read_half: *const fn (ctx: *anyopaque, addr: u32) callconv(.c) ReadResult,
        read_word: *const fn (ctx: *anyopaque, addr: u32) callconv(.c) ReadResult,
        write_byte: *const fn (ctx: *anyopaque, addr: u32, value: u8) callconv(.c) WriteResult,
        write_half: *const fn (ctx: *anyopaque, addr: u32, value: u16) callconv(.c) WriteResult,
        write_word: *const fn (ctx: *anyopaque, addr: u32, value: u32) callconv(.c) WriteResult,
    };

    pub const Offsets = struct {
        regs: usize,
        pc: usize,
        cycle: usize,
        instret: usize,
        mtime: usize,
        privilege: usize,
        fcsr: usize,
        mstatus: usize,
        mip: usize,
        float: usize,
        trap_cause: usize,
        trap_tval: usize,
    };

    pub const Callbacks = struct {
        pub const CsrOp = enum(u8) { rw, rs, rc };

        pub const CsrResult = extern struct {
            value: u32,
            status: u32,

            pub inline fn success(val: u32) CsrResult {
                return .{ .value = val, .status = 0 };
            }

            pub inline fn fail() CsrResult {
                return .{ .value = 0, .status = 1 };
            }
        };

        pub const FpResult = extern struct {
            trap: u32,

            pub const ok = FpResult{ .trap = 0 };
            pub const fail = FpResult{ .trap = 1 };
        };

        pub const BinaryOpS = enum(u8) { add, sub, mul, div, min, max, sgnj, sgnjn, sgnjx };
        pub const UnaryOpS = enum(u8) { sqrt, fcvt_w_s, fcvt_wu_s, fcvt_s_w, fcvt_s_wu, fclass };
        pub const FmaOpS = enum(u8) { fmadd, fmsub, fnmadd, fnmsub };
        pub const CmpOpS = enum(u8) { eq, lt, le };
        pub const UnaryOpD = enum(u8) { sqrt, fcvt_w_d, fcvt_wu_d, fcvt_d_w, fcvt_d_wu, fcvt_s_d, fcvt_d_s, fclass };

        get_offsets: *const fn () callconv(.@"inline") Offsets,

        read_instruction: *const fn (ctx: *anyopaque, address: u32) callconv(.@"inline") ?u32,

        csr_op: *const fn (ctx: *anyopaque, csr: u32, value: u32, op: CsrOp, do_write: bool) callconv(.c) CsrResult,

        binary_s: *const fn (ctx: *anyopaque, op: BinaryOpS, rd: u8, rs1: u8, rs2: u8, rm: u8) callconv(.c) FpResult,
        unary_s: *const fn (ctx: *anyopaque, op: UnaryOpS, rd: u8, rs1: u8, rm: u8) callconv(.c) FpResult,
        fma_s: *const fn (ctx: *anyopaque, op: FmaOpS, rd: u8, rs1: u8, rs2: u8, rs3: u8, rm: u8) callconv(.c) FpResult,
        cmp_s: *const fn (ctx: *anyopaque, op: CmpOpS, rd: u8, rs1: u8, rs2: u8) callconv(.c) FpResult,

        binary_d: *const fn (ctx: *anyopaque, op: BinaryOpS, rd: u8, rs1: u8, rs2: u8, rm: u8) callconv(.c) FpResult,
        unary_d: *const fn (ctx: *anyopaque, op: UnaryOpD, rd: u8, rs1: u8, rm: u8) callconv(.c) FpResult,
        fma_d: *const fn (ctx: *anyopaque, op: FmaOpS, rd: u8, rs1: u8, rs2: u8, rs3: u8, rm: u8) callconv(.c) FpResult,
        cmp_d: *const fn (ctx: *anyopaque, op: CmpOpS, rd: u8, rs1: u8, rs2: u8) callconv(.c) FpResult,

        mret: *const fn (ctx: *anyopaque) callconv(.c) u32,
        wfi: *const fn (ctx: *anyopaque) callconv(.c) EngineConfig.State,
    };

    pub const Jit = struct {
        max_block_size: u32 = 64,
        code_arena_size: usize = 4 * 1024 * 1024,
    };

    pub const Runtime = struct {
        pub const Extensions = struct {
            m: bool = true,
            f: bool = true,
            zba: bool = true,
            zbb: bool = true,
            zicsr: bool = true,
            zicntr: bool = true,
        };

        extensions: Extensions = .{},
        enable_memory_alignment: bool = true,
        enable_pmp: bool = true,
        enable_pmp_m: bool = true,

        /// Enable CSR privilege and read-only checks.
        enable_csr_checks: bool = true,

        /// Enable branch/jump target alignment checks (4-byte for RV32I).
        enable_branch_alignment: bool = true,

        /// Enable FPU exception flags (NV, DZ, OF, UF, NX).
        /// When disabled, FCSR flags are not updated.
        enable_fpu_flags: bool = true,

        pub const compliant: Runtime = .{};

        pub const fast: Runtime = .{
            .enable_memory_alignment = false,
            .enable_pmp = false,
            .enable_pmp_m = false,
        };
    };

    pub const Hooks = struct {
        pub const Action = enum(u8) { proceed, skip, halt };

        read: ?*const fn (cpu: *anyopaque, addr: u32) callconv(.@"inline") ?u8 = null,
        write: ?*const fn (cpu: *anyopaque, addr: u32, value: u8) callconv(.@"inline") bool = null,
        ecall: ?*const fn (cpu: *anyopaque, cause: arch.Registers.Mcause.Exception) callconv(.c) Action = null,
        ebreak: ?*const fn (cpu: *anyopaque) callconv(.c) Action = null,
        wfi: ?*const fn (cpu: *anyopaque) callconv(.c) bool = null,
        instruction_cost: ?*const fn (instruction: arch.Instruction) callconv(.@"inline") usize = null,
    };

    pub const Vars = struct {
        ram_start: u32 = 0,
        timer_ticks_per_cycle: u64 = 1,
    };

    memory_callbacks: MemoryCallbacks,
    callbacks: Callbacks,
    jit: Jit,
    runtime: Runtime,
    hooks: Hooks,
    vars: Vars,
};
