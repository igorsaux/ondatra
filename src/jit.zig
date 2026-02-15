const std = @import("std");

const arch = @import("arch.zig");
const elf = @import("elf.zig");
pub const BlockCache = @import("jit/block_cache.zig").BlockCache;
pub const CodeArena = @import("jit/code_arena.zig").CodeArena;
pub const compiler = @import("jit/compiler.zig");
pub const Engine = @import("jit/engine.zig").Engine;
pub const EngineConfig = @import("jit/engine_config.zig").EngineConfig;

pub const Config = struct {
    runtime: EngineConfig.Runtime = .{},
    jit: EngineConfig.Jit = .{},
    hooks: EngineConfig.Hooks = .{},
    vars: EngineConfig.Vars = .{},
};

pub const ElfLoadError = error{ OutOfRam, NotSupported } || elf.ParseError;

pub fn Cpu(comptime config: Config) type {
    return struct {
        const Self = @This();

        pub const EngineType = Engine(.{
            .memory_callbacks = .{
                .read_byte = jitReadByte,
                .read_half = jitReadHalf,
                .read_word = jitReadWord,
                .write_byte = jitWriteByte,
                .write_half = jitWriteHalf,
                .write_word = jitWriteWord,
            },
            .callbacks = .{
                .get_offsets = jitComputeLayout,
                .read_instruction = jitReadInstruction,
                .csr_op = jitCsrOp,
                .binary_s = jitFpBinaryS,
                .unary_s = jitFpUnaryS,
                .fma_s = jitFpFmaS,
                .cmp_s = jitFpCmpS,
                .binary_d = jitFpBinaryD,
                .unary_d = jitFpUnaryD,
                .fma_d = jitFpFmaD,
                .cmp_d = jitFpCmpD,
                .mret = jitMret,
                .wfi = jitWfi,
            },
            .jit = config.jit,
            .runtime = config.runtime,
            .hooks = config.hooks,
            .vars = config.vars,
        });

        engine: EngineType,
        ram: []u8,
        registers: arch.Registers = .{},

        pub inline fn init(allocator: std.mem.Allocator, ram: []u8) !Self {
            std.debug.assert(ram.len % 4 == 0);

            return .{
                .ram = ram,
                .engine = try EngineType.init(allocator),
            };
        }

        pub inline fn deinit(this: *Self) void {
            this.engine.deinit();
        }

        pub inline fn loadElf(this: *Self, allocator: std.mem.Allocator, content: []const u8) ElfLoadError!usize {
            var file = try elf.File.parseFromSlice(allocator, content);
            defer file.deinit(allocator);

            if (file.header.ident.class != .class32) {
                return ElfLoadError.NotSupported;
            }

            if (file.header.ident.data != .lsb) {
                return ElfLoadError.NotSupported;
            }

            if (file.header.machine != .riscv) {
                return ElfLoadError.NotSupported;
            }

            if (file.header.ty != .exec and file.header.ty != .dyn) {
                return ElfLoadError.NotSupported;
            }

            const ventry = file.header.entry;
            var max_addr: u32 = 0;

            for (file.program_headers.items) |*header| {
                if (header.ty != .load) {
                    continue;
                }

                if (header.vaddr == 0 and header.filesz == 0 and header.memsz > this.ram.len) {
                    continue;
                }

                const vaddr = header.vaddr -% config.vars.ram_start;

                if (vaddr >= this.ram.len) {
                    return ElfLoadError.OutOfRam;
                }

                if (vaddr +% header.filesz > this.ram.len or vaddr +% header.memsz > this.ram.len) {
                    return ElfLoadError.OutOfRam;
                }

                if (header.filesz > 0) {
                    const file_end = header.offset + header.filesz;

                    if (file_end > content.len) {
                        return ElfLoadError.OutOfRam;
                    }

                    @memcpy(this.ram[vaddr..][0..header.filesz], content[header.offset..][0..header.filesz]);
                }

                if (header.memsz > header.filesz) {
                    const bss_start = vaddr + header.filesz;
                    const bss_size = header.memsz - header.filesz;

                    @memset(this.ram[bss_start..][0..bss_size], 0);
                }

                max_addr = @max(max_addr, vaddr + header.memsz);
            }

            this.registers.pc = ventry;

            return max_addr;
        }

        pub const MemoryError = error{
            MisalignedAddress,
            PmpViolation,
            AddressOutOfBounds,
            MmioFailed,
        };

        pub inline fn readMemory(
            this: *Self,
            address: u32,
            comptime T: type,
            comptime access: arch.Registers.Pmp.AccessType,
        ) MemoryError!T {
            const byte_len = @sizeOf(T);

            if (comptime config.runtime.enable_memory_alignment) {
                if (address % byte_len != 0) {
                    return MemoryError.MisalignedAddress;
                }
            }

            if (this.needsPmpCheck(access)) {
                if (!this.registers.checkPmpAccess(address, byte_len, access, this.registers.privilege)) {
                    return MemoryError.PmpViolation;
                }
            }

            if (address < config.vars.ram_start) {
                if (address +% byte_len > config.vars.ram_start) {
                    return MemoryError.MisalignedAddress;
                }

                if (comptime config.hooks.read != null) {
                    var dst: [byte_len]u8 = undefined;

                    inline for (0..byte_len) |i| {
                        if (config.hooks.read.?(@ptrCast(this), address +% @as(u32, @intCast(i)))) |v| {
                            dst[i] = v;
                        } else {
                            return MemoryError.MmioFailed;
                        }
                    }

                    return std.mem.toNative(T, std.mem.bytesToValue(T, &dst), arch.ENDIAN);
                }

                return MemoryError.AddressOutOfBounds;
            }

            const translated: u64 = address -| config.vars.ram_start;

            if (translated + byte_len > this.ram.len) {
                return MemoryError.AddressOutOfBounds;
            }

            const result: T = std.mem.bytesToValue(T, this.ram[translated..][0..byte_len]);
            return std.mem.toNative(T, result, arch.ENDIAN);
        }

        pub inline fn writeMemory(this: *Self, address: u32, value: anytype) MemoryError!void {
            const T = @TypeOf(value);
            const byte_len = @sizeOf(T);

            if (comptime config.runtime.enable_memory_alignment) {
                if (address % byte_len != 0) {
                    return MemoryError.MisalignedAddress;
                }
            }

            if (this.needsPmpCheck(.write)) {
                if (!this.registers.checkPmpAccess(address, byte_len, .write, this.registers.privilege)) {
                    return MemoryError.PmpViolation;
                }
            }

            if (address < config.vars.ram_start) {
                if (address +% byte_len > config.vars.ram_start) {
                    return MemoryError.MisalignedAddress;
                }

                if (comptime config.hooks.write != null) {
                    const converted = std.mem.nativeTo(T, value, arch.ENDIAN);
                    const src = std.mem.asBytes(&converted);

                    inline for (0..byte_len) |i| {
                        if (!config.hooks.write.?(@ptrCast(this), address +% @as(u32, @intCast(i)), src[i])) {
                            return MemoryError.MmioFailed;
                        }
                    }

                    return;
                }

                return MemoryError.AddressOutOfBounds;
            }

            const translated: u64 = address -| config.vars.ram_start;

            if (translated + byte_len > this.ram.len) {
                return MemoryError.AddressOutOfBounds;
            }

            const bytes = std.mem.asBytes(&std.mem.nativeTo(T, value, arch.ENDIAN));
            @memcpy(this.ram[translated..][0..byte_len], bytes);
        }

        inline fn needsPmpCheck(this: *Self, comptime access: arch.Registers.Pmp.AccessType) bool {
            if (comptime !config.runtime.enable_pmp) {
                return false;
            }

            if (comptime config.runtime.enable_pmp_m) {
                return true;
            }

            if (this.registers.privilege != .machine) {
                return true;
            }

            if (comptime access == .execute) {
                return false;
            }

            return this.registers.mstatus.mprv;
        }

        inline fn setLoadTrap(this: *Self, err: MemoryError, address: u32) void {
            this.registers.mtval = address;
            const code: arch.Registers.Mcause.Exception = switch (err) {
                MemoryError.MisalignedAddress => .load_address_misaligned,
                else => .load_access_fault,
            };

            this.registers.mcause = .fromException(code);
        }

        inline fn setStoreTrap(this: *Self, err: MemoryError, address: u32) void {
            this.registers.mtval = address;
            const code: arch.Registers.Mcause.Exception = switch (err) {
                MemoryError.MisalignedAddress => .store_address_misaligned,
                else => .store_access_fault,
            };

            this.registers.mcause = .fromException(code);
        }

        pub inline fn step(this: *Self) !EngineConfig.State {
            return this.engine.step(@ptrCast(this));
        }

        pub inline fn run(this: *Self, max_cycles: u64) !EngineConfig.State {
            return this.engine.run(@ptrCast(this), max_cycles);
        }

        pub inline fn invalidateJitCache(this: *Self) void {
            this.engine.invalidate();
        }

        pub inline fn invalidateJitCacheRange(this: *Self, start: u32, end: u32) void {
            this.engine.invalidateRange(start, end);
        }

        pub inline fn jitReadInstruction(
            ctx: *anyopaque,
            address: u32,
        ) ?u32 {
            const this: *Self = @ptrCast(@alignCast(ctx));

            return this.readMemory(address, u32, .execute) catch null;
        }

        fn jitReadByte(ctx: *anyopaque, addr: u32) callconv(.c) EngineConfig.MemoryCallbacks.ReadResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            if (this.readMemory(addr, u8, .read)) |value| {
                return .success(value);
            } else |err| {
                this.setLoadTrap(err, addr);
                return .fail();
            }
        }

        fn jitReadHalf(ctx: *anyopaque, addr: u32) callconv(.c) EngineConfig.MemoryCallbacks.ReadResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            if (this.readMemory(addr, u16, .read)) |value| {
                return .success(value);
            } else |err| {
                this.setLoadTrap(err, addr);
                return .fail();
            }
        }

        fn jitReadWord(ctx: *anyopaque, addr: u32) callconv(.c) EngineConfig.MemoryCallbacks.ReadResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            if (this.readMemory(addr, u32, .read)) |value| {
                return .success(value);
            } else |err| {
                this.setLoadTrap(err, addr);

                return .fail();
            }
        }

        fn jitWriteByte(ctx: *anyopaque, addr: u32, value: u8) callconv(.c) EngineConfig.MemoryCallbacks.WriteResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            if (this.writeMemory(addr, value)) {
                return .ok;
            } else |err| {
                this.setStoreTrap(err, addr);

                return .fail;
            }
        }

        fn jitWriteHalf(ctx: *anyopaque, addr: u32, value: u16) callconv(.c) EngineConfig.MemoryCallbacks.WriteResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            if (this.writeMemory(addr, value)) {
                return .ok;
            } else |err| {
                this.setStoreTrap(err, addr);

                return .fail;
            }
        }

        fn jitWriteWord(ctx: *anyopaque, addr: u32, value: u32) callconv(.c) EngineConfig.MemoryCallbacks.WriteResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            if (this.writeMemory(addr, value)) {
                return .ok;
            } else |err| {
                this.setStoreTrap(err, addr);

                return .fail;
            }
        }

        fn jitCsrOp(
            ctx: *anyopaque,
            csr_addr: u32,
            value: u32,
            op: EngineConfig.Callbacks.CsrOp,
            do_write: bool,
        ) callconv(.c) EngineConfig.Callbacks.CsrResult {
            const this: *Self = @ptrCast(@alignCast(ctx));
            const csr: arch.Registers.Csr = @enumFromInt(csr_addr);

            if (comptime config.runtime.enable_csr_checks) {
                const old_value = this.registers.readCsr(csr, this.registers.privilege) catch {
                    this.registers.mtval = 0;
                    this.registers.mcause = .fromException(.illegal_instruction);

                    return .fail();
                };

                if (!do_write) {
                    return .success(old_value);
                }

                const new_value = switch (op) {
                    .rw => value,
                    .rs => old_value | value,
                    .rc => old_value & ~value,
                };

                this.registers.writeCsr(csr, new_value, this.registers.privilege) catch {
                    this.registers.mtval = 0;
                    this.registers.mcause = .fromException(.illegal_instruction);

                    return .fail();
                };

                if (csr == .fflags or csr == .frm or csr == .fcsr) {
                    this.registers.mstatus.fs = 0b11;
                    this.registers.mstatus.updateSD();
                }

                return .success(old_value);
            } else {
                const old_value = this.registers.readCsrUnchecked(csr);

                if (!do_write) {
                    return .success(old_value);
                }

                const new_value = switch (op) {
                    .rw => value,
                    .rs => old_value | value,
                    .rc => old_value & ~value,
                };

                this.registers.writeCsrUnchecked(csr, new_value);

                if (csr == .fflags or csr == .frm or csr == .fcsr) {
                    this.registers.mstatus.fs = 0b11;
                    this.registers.mstatus.updateSD();
                }

                return .success(old_value);
            }
        }

        fn jitFpBinaryS(
            ctx: *anyopaque,
            op: EngineConfig.Callbacks.BinaryOpS,
            rd: u8,
            rs1: u8,
            rs2: u8,
            rm: u8,
        ) callconv(.c) EngineConfig.Callbacks.FpResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            const mode = this.getEffectiveRm(rm) orelse return .fail;
            _ = mode;

            const a = this.getF32(rs1);
            const b = this.getF32(rs2);

            var result: f32 = undefined;
            var flags: u5 = 0;

            if (comptime config.runtime.enable_fpu_flags) {
                if (arch.FloatHelpers.isSignalingNanF32(a) or arch.FloatHelpers.isSignalingNanF32(b)) {
                    flags |= arch.Registers.Fcsr.NV;
                }
            }

            switch (op) {
                .add => {
                    if (comptime config.runtime.enable_fpu_flags) {
                        // inf + (-inf) = NaN, early exit like interpreter
                        if (std.math.isInf(a) and std.math.isInf(b)) {
                            if ((a > 0) != (b > 0)) {
                                flags |= arch.Registers.Fcsr.NV;

                                const old_flags = this.registers.fcsr.getFflags();
                                this.registers.fcsr.setFflags(old_flags | flags);
                                this.setF32(rd, arch.FloatHelpers.canonicalNanF32());
                                this.markFpDirty();

                                return .ok;
                            }
                        }
                    }

                    result = a + b;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and !std.math.isInf(a) and !std.math.isInf(b)) {
                            flags |= arch.Registers.Fcsr.OF;
                            flags |= arch.Registers.Fcsr.NX;
                        }

                        if (arch.FloatHelpers.isSubnormalF32(result)) {
                            flags |= arch.Registers.Fcsr.UF;
                        }

                        // Inexact check using f64
                        if (!std.math.isNan(result) and !std.math.isInf(result)) {
                            const check: f64 = @as(f64, a) + @as(f64, b);

                            if (@as(f64, result) != check) {
                                flags |= arch.Registers.Fcsr.NX;
                            }
                        }
                    }
                },
                .sub => {
                    if (comptime config.runtime.enable_fpu_flags) {
                        // inf - inf (same sign) = NaN, early exit
                        if (std.math.isInf(a) and std.math.isInf(b) and (a > 0) == (b > 0)) {
                            flags |= arch.Registers.Fcsr.NV;

                            const old_flags = this.registers.fcsr.getFflags();
                            this.registers.fcsr.setFflags(old_flags | flags);
                            this.setF32(rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpDirty();

                            return .ok;
                        }
                    }

                    result = a - b;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and !std.math.isInf(a) and !std.math.isInf(b)) {
                            flags |= arch.Registers.Fcsr.OF;
                            flags |= arch.Registers.Fcsr.NX;
                        }

                        if (arch.FloatHelpers.isSubnormalF32(result)) {
                            flags |= arch.Registers.Fcsr.UF;
                        }

                        // Inexact check using f64
                        if (!std.math.isNan(result) and !std.math.isInf(result)) {
                            const check: f64 = @as(f64, a) - @as(f64, b);

                            if (@as(f64, result) != check) {
                                flags |= arch.Registers.Fcsr.NX;
                            }
                        }
                    }
                },
                .mul => {
                    if (comptime config.runtime.enable_fpu_flags) {
                        // 0 * inf = NaN, early exit like interpreter
                        if ((a == 0 and std.math.isInf(b)) or (std.math.isInf(a) and b == 0)) {
                            flags |= arch.Registers.Fcsr.NV;

                            const old_flags = this.registers.fcsr.getFflags();
                            this.registers.fcsr.setFflags(old_flags | flags);
                            this.setF32(rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpDirty();

                            return .ok;
                        }
                    }

                    result = a * b;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and !std.math.isInf(a) and !std.math.isInf(b)) {
                            flags |= arch.Registers.Fcsr.OF;
                            flags |= arch.Registers.Fcsr.NX;
                        }

                        if (arch.FloatHelpers.isSubnormalF32(result)) {
                            flags |= arch.Registers.Fcsr.UF;
                        }

                        // Inexact check using f64
                        if (!std.math.isNan(result) and !std.math.isInf(result) and
                            !std.math.isInf(a) and !std.math.isInf(b))
                        {
                            const check: f64 = @as(f64, a) * @as(f64, b);

                            if (@as(f64, result) != check) {
                                flags |= arch.Registers.Fcsr.NX;
                            }
                        }
                    }
                },
                .div => {
                    if (comptime config.runtime.enable_fpu_flags) {
                        if ((a == 0 and b == 0) or (std.math.isInf(a) and std.math.isInf(b))) {
                            flags |= arch.Registers.Fcsr.NV;

                            const old_flags = this.registers.fcsr.getFflags();
                            this.registers.fcsr.setFflags(old_flags | flags);
                            this.setF32(rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpDirty();

                            return .ok;
                        }

                        if (b == 0 and a != 0 and !std.math.isNan(a)) {
                            flags |= arch.Registers.Fcsr.DZ;
                        }
                    }

                    result = a / b;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and !std.math.isInf(a) and b != 0) {
                            flags |= arch.Registers.Fcsr.OF;
                            flags |= arch.Registers.Fcsr.NX;
                        }

                        if (arch.FloatHelpers.isSubnormalF32(result)) {
                            flags |= arch.Registers.Fcsr.UF;
                        }

                        if (!std.math.isNan(result) and !std.math.isInf(result) and b != 0) {
                            const check: f64 = @as(f64, a) / @as(f64, b);

                            if (@as(f64, result) != check) {
                                flags |= arch.Registers.Fcsr.NX;
                            }
                        }
                    }
                },
                .min => {
                    if (std.math.isNan(a) or std.math.isNan(b)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (arch.FloatHelpers.isSignalingNanF32(a) or arch.FloatHelpers.isSignalingNanF32(b)) {
                                flags |= arch.Registers.Fcsr.NV;
                            }
                        }

                        result = if (std.math.isNan(a) and std.math.isNan(b))
                            arch.FloatHelpers.canonicalNanF32()
                        else if (std.math.isNan(a))
                            b
                        else
                            a;
                    } else if (a == 0 and b == 0) {
                        result = if (arch.FloatHelpers.isNegativeZeroF32(a) or arch.FloatHelpers.isNegativeZeroF32(b))
                            @bitCast(@as(u32, 0x80000000))
                        else
                            @as(f32, 0.0);
                    } else {
                        result = @min(a, b);
                    }
                },
                .max => {
                    if (std.math.isNan(a) or std.math.isNan(b)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (arch.FloatHelpers.isSignalingNanF32(a) or arch.FloatHelpers.isSignalingNanF32(b)) {
                                flags |= arch.Registers.Fcsr.NV;
                            }
                        }

                        result = if (std.math.isNan(a) and std.math.isNan(b))
                            arch.FloatHelpers.canonicalNanF32()
                        else if (std.math.isNan(a))
                            b
                        else
                            a;
                    } else if (a == 0 and b == 0) {
                        result = if (arch.FloatHelpers.isNegativeZeroF32(a) and arch.FloatHelpers.isNegativeZeroF32(b))
                            @bitCast(@as(u32, 0x80000000))
                        else
                            @as(f32, 0.0);
                    } else {
                        result = @max(a, b);
                    }
                },
                .sgnj => {
                    const bits_a: u32 = @bitCast(a);
                    const bits_b: u32 = @bitCast(b);

                    result = @bitCast((bits_a & 0x7FFFFFFF) | (bits_b & 0x80000000));
                },
                .sgnjn => {
                    const bits_a: u32 = @bitCast(a);
                    const bits_b: u32 = @bitCast(b);

                    result = @bitCast((bits_a & 0x7FFFFFFF) | (~bits_b & 0x80000000));
                },
                .sgnjx => {
                    const bits_a: u32 = @bitCast(a);
                    const bits_b: u32 = @bitCast(b);

                    result = @bitCast(bits_a ^ (bits_b & 0x80000000));
                },
            }

            if (comptime config.runtime.enable_fpu_flags) {
                const old_flags = this.registers.fcsr.getFflags();

                this.registers.fcsr.setFflags(old_flags | flags);
            }

            if (std.math.isNan(result)) {
                result = arch.FloatHelpers.canonicalNanF32();
            }

            this.setF32(rd, result);
            this.markFpDirty();

            return .ok;
        }

        fn jitFpUnaryS(
            ctx: *anyopaque,
            op: EngineConfig.Callbacks.UnaryOpS,
            rd: u8,
            rs1: u8,
            rm: u8,
        ) callconv(.c) EngineConfig.Callbacks.FpResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            switch (op) {
                .sqrt => {
                    const mode = this.getEffectiveRm(rm) orelse return .fail;
                    _ = mode;

                    const a = this.getF32(rs1);
                    var flags: u5 = 0;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(a)) {
                            flags |= arch.Registers.Fcsr.NV;
                        }

                        // Negative (but not -0) → NV and early exit
                        if (a < 0 and !arch.FloatHelpers.isNegativeZeroF32(a)) {
                            flags |= arch.Registers.Fcsr.NV;

                            const old = this.registers.fcsr.getFflags();
                            this.registers.fcsr.setFflags(old | flags);
                            this.setF32(rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpDirty();

                            return .ok;
                        }
                    }

                    const result = @sqrt(a);

                    if (comptime config.runtime.enable_fpu_flags) {
                        const old = this.registers.fcsr.getFflags();

                        this.registers.fcsr.setFflags(old | flags);
                    }

                    // sqrt(-0) = -0, preserve it
                    if (arch.FloatHelpers.isNegativeZeroF32(a)) {
                        this.setF32(rd, a);
                    } else {
                        this.setF32(rd, if (std.math.isNan(result)) arch.FloatHelpers.canonicalNanF32() else result);
                    }

                    this.markFpDirty();
                },
                .fcvt_w_s => {
                    const mode = this.getEffectiveRm(rm) orelse return .fail;
                    const a = this.getF32(rs1);
                    var flags: u5 = 0;

                    const result: i32 = if (std.math.isNan(a)) blk: {
                        flags |= arch.Registers.Fcsr.NV;

                        break :blk std.math.maxInt(i32);
                    } else if (std.math.isInf(a)) blk: {
                        flags |= arch.Registers.Fcsr.NV;

                        break :blk if (a > 0) std.math.maxInt(i32) else std.math.minInt(i32);
                    } else blk: {
                        const rounded: f32 = switch (mode) {
                            .rne => arch.FloatHelpers.roundToNearestEvenF32(a),
                            .rtz => if (a >= 0) @floor(a) else @ceil(a),
                            .rdn => @floor(a),
                            .rup => @ceil(a),
                            .rmm => if (a >= 0) @floor(a + 0.5) else @ceil(a - 0.5),
                            else => arch.FloatHelpers.roundToNearestEvenF32(a),
                        };

                        if (rounded > @as(f32, @floatFromInt(std.math.maxInt(i32)))) {
                            flags |= arch.Registers.Fcsr.NV;

                            break :blk std.math.maxInt(i32);
                        } else if (rounded < @as(f32, @floatFromInt(std.math.minInt(i32)))) {
                            flags |= arch.Registers.Fcsr.NV;

                            break :blk std.math.minInt(i32);
                        } else {
                            const int_result: i32 = @intFromFloat(rounded);

                            if (comptime config.runtime.enable_fpu_flags) {
                                if (rounded != a) {
                                    flags |= arch.Registers.Fcsr.NX;
                                }
                            }

                            break :blk int_result;
                        }
                    };

                    if (comptime config.runtime.enable_fpu_flags) {
                        const old = this.registers.fcsr.getFflags();

                        this.registers.fcsr.setFflags(old | flags);
                    }

                    this.registers.set(rd, result);
                },
                .fcvt_wu_s => {
                    const mode = this.getEffectiveRm(rm) orelse return .fail;
                    const a = this.getF32(rs1);
                    var flags: u5 = 0;

                    const result: u32 = if (std.math.isNan(a)) blk: {
                        flags |= arch.Registers.Fcsr.NV;

                        break :blk std.math.maxInt(u32);
                    } else if (std.math.isInf(a)) blk: {
                        flags |= arch.Registers.Fcsr.NV;

                        break :blk if (a > 0) std.math.maxInt(u32) else 0;
                    } else blk: {
                        const rounded: f32 = switch (mode) {
                            .rne => arch.FloatHelpers.roundToNearestEvenF32(a),
                            .rtz => if (a >= 0) @floor(a) else @ceil(a),
                            .rdn => @floor(a),
                            .rup => @ceil(a),
                            .rmm => if (a >= 0) @floor(a + 0.5) else @ceil(a - 0.5),
                            else => arch.FloatHelpers.roundToNearestEvenF32(a),
                        };

                        if (rounded < 0) {
                            flags |= arch.Registers.Fcsr.NV;

                            break :blk 0;
                        } else if (rounded > @as(f32, @floatFromInt(std.math.maxInt(u32)))) {
                            flags |= arch.Registers.Fcsr.NV;

                            break :blk std.math.maxInt(u32);
                        } else {
                            const int_result: u32 = @intFromFloat(rounded);

                            if (comptime config.runtime.enable_fpu_flags) {
                                if (rounded != a) {
                                    flags |= arch.Registers.Fcsr.NX;
                                }
                            }

                            break :blk int_result;
                        }
                    };

                    if (comptime config.runtime.enable_fpu_flags) {
                        const old = this.registers.fcsr.getFflags();

                        this.registers.fcsr.setFflags(old | flags);
                    }

                    this.registers.set(rd, @bitCast(result));
                },
                .fcvt_s_w => {
                    const a = this.registers.get(rs1);
                    const result: f32 = @floatFromInt(a);

                    if (comptime config.runtime.enable_fpu_flags) {
                        const back: i64 = @intFromFloat(result);

                        if (back != @as(i64, a)) {
                            const old = this.registers.fcsr.getFflags();

                            this.registers.fcsr.setFflags(old | arch.Registers.Fcsr.NX);
                        }
                    }

                    this.setF32(rd, result);
                    this.markFpDirty();
                },
                .fcvt_s_wu => {
                    const a: u32 = @bitCast(this.registers.get(rs1));
                    const result: f32 = @floatFromInt(a);

                    if (comptime config.runtime.enable_fpu_flags) {
                        const back: i64 = @intFromFloat(result);

                        if (back != @as(i64, a)) {
                            const old = this.registers.fcsr.getFflags();

                            this.registers.fcsr.setFflags(old | arch.Registers.Fcsr.NX);
                        }
                    }

                    this.setF32(rd, result);
                    this.markFpDirty();
                },
                .fclass => {
                    const bits: u32 = @truncate(this.registers.float[rs1]);
                    const sign = (bits >> 31) != 0;
                    const exp = (bits >> 23) & 0xFF;
                    const frac = bits & 0x7FFFFF;

                    const result: u32 = if (exp == 0xFF and frac != 0)
                        if ((frac & 0x400000) != 0) (1 << 9) else (1 << 8)
                    else if (exp == 0xFF)
                        if (sign) (1 << 0) else (1 << 7)
                    else if (exp == 0 and frac == 0)
                        if (sign) (1 << 3) else (1 << 4)
                    else if (exp == 0)
                        if (sign) (1 << 2) else (1 << 5)
                    else if (sign) (1 << 1) else (1 << 6);

                    this.registers.set(rd, @bitCast(result));
                },
            }

            return .ok;
        }

        fn jitFpFmaS(
            ctx: *anyopaque,
            op: EngineConfig.Callbacks.FmaOpS,
            rd: u8,
            rs1: u8,
            rs2: u8,
            rs3: u8,
            rm: u8,
        ) callconv(.c) EngineConfig.Callbacks.FpResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            const mode = this.getEffectiveRm(rm) orelse return .fail;
            _ = mode;

            const a = this.getF32(rs1);
            const b = this.getF32(rs2);
            const c = this.getF32(rs3);

            var flags: u5 = 0;

            if (comptime config.runtime.enable_fpu_flags) {
                if (arch.FloatHelpers.isSignalingNanF32(a) or
                    arch.FloatHelpers.isSignalingNanF32(b) or
                    arch.FloatHelpers.isSignalingNanF32(c))
                {
                    flags |= arch.Registers.Fcsr.NV;
                }

                // 0 * inf or inf * 0 in the multiplication part
                if ((std.math.isInf(a) and b == 0) or (a == 0 and std.math.isInf(b))) {
                    flags |= arch.Registers.Fcsr.NV;

                    const old = this.registers.fcsr.getFflags();
                    this.registers.fcsr.setFflags(old | flags);
                    this.setF32(rd, arch.FloatHelpers.canonicalNanF32());
                    this.markFpDirty();

                    return .ok;
                }
            }

            const raw: f32 = switch (op) {
                .fmadd => @mulAdd(f32, a, b, c),
                .fmsub => @mulAdd(f32, a, b, -c),
                .fnmadd => @mulAdd(f32, -a, b, -c),
                .fnmsub => @mulAdd(f32, -a, b, c),
            };

            if (std.math.isNan(raw)) {
                if (comptime config.runtime.enable_fpu_flags) {
                    // NaN result but no NaN input → invalid operation (e.g., inf + (-inf))
                    if (!std.math.isNan(a) and !std.math.isNan(b) and !std.math.isNan(c)) {
                        flags |= arch.Registers.Fcsr.NV;
                    }
                }

                if (comptime config.runtime.enable_fpu_flags) {
                    const old = this.registers.fcsr.getFflags();

                    this.registers.fcsr.setFflags(old | flags);
                }

                this.setF32(rd, arch.FloatHelpers.canonicalNanF32());
                this.markFpDirty();

                return .ok;
            }

            if (comptime config.runtime.enable_fpu_flags) {
                // Overflow: result is inf but no input was inf
                if (std.math.isInf(raw) and !std.math.isInf(a) and !std.math.isInf(b) and !std.math.isInf(c)) {
                    flags |= arch.Registers.Fcsr.OF;
                    flags |= arch.Registers.Fcsr.NX;
                }

                if (flags != 0) {
                    const old = this.registers.fcsr.getFflags();

                    this.registers.fcsr.setFflags(old | flags);
                }
            }

            this.setF32(rd, raw);
            this.markFpDirty();

            return .ok;
        }

        fn jitFpCmpS(
            ctx: *anyopaque,
            op: EngineConfig.Callbacks.CmpOpS,
            rd: u8,
            rs1: u8,
            rs2: u8,
        ) callconv(.c) EngineConfig.Callbacks.FpResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            const a = this.getF32(rs1);
            const b = this.getF32(rs2);

            var flags: u5 = 0;

            const a_snan = arch.FloatHelpers.isSignalingNanF32(a);
            const b_snan = arch.FloatHelpers.isSignalingNanF32(b);
            const a_nan = std.math.isNan(a);
            const b_nan = std.math.isNan(b);

            const result: i32 = switch (op) {
                .eq => blk: {
                    if (comptime config.runtime.enable_fpu_flags) {
                        if (a_snan or b_snan) flags |= arch.Registers.Fcsr.NV;
                    }

                    break :blk if (a_nan or b_nan) 0 else if (a == b) 1 else 0;
                },
                .lt => blk: {
                    if (a_nan or b_nan) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            flags |= arch.Registers.Fcsr.NV;
                        }

                        break :blk 0;
                    }

                    break :blk if (a < b) 1 else 0;
                },
                .le => blk: {
                    if (a_nan or b_nan) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            flags |= arch.Registers.Fcsr.NV;
                        }

                        break :blk 0;
                    }

                    break :blk if (a <= b) 1 else 0;
                },
            };

            if (comptime config.runtime.enable_fpu_flags) {
                const old = this.registers.fcsr.getFflags();

                this.registers.fcsr.setFflags(old | flags);
            }

            this.registers.set(rd, result);

            return .ok;
        }

        fn jitFpBinaryD(
            ctx: *anyopaque,
            op: EngineConfig.Callbacks.BinaryOpS,
            rd: u8,
            rs1: u8,
            rs2: u8,
            rm: u8,
        ) callconv(.c) EngineConfig.Callbacks.FpResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            const mode = this.getEffectiveRm(rm) orelse return .fail;
            _ = mode;

            const a = this.registers.getF64(rs1);
            const b = this.registers.getF64(rs2);

            var result: f64 = undefined;
            var flags: u5 = 0;

            switch (op) {
                .add => {
                    result = a + b;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isNan(result) and (!std.math.isNan(a) and !std.math.isNan(b))) {
                            flags |= arch.Registers.Fcsr.NV;
                        }
                    }
                },
                .sub => {
                    result = a - b;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isNan(result) and (!std.math.isNan(a) and !std.math.isNan(b))) {
                            flags |= arch.Registers.Fcsr.NV;
                        }
                    }
                },
                .mul => {
                    if (comptime config.runtime.enable_fpu_flags) {
                        if ((a == 0 and std.math.isInf(b)) or (std.math.isInf(a) and b == 0)) {
                            flags |= arch.Registers.Fcsr.NV;
                        }
                    }

                    result = a * b;
                },
                .div => {
                    if (b == 0) {
                        if (a == 0 or std.math.isNan(a)) {
                            result = arch.FloatHelpers.canonicalNanF64();

                            if (comptime config.runtime.enable_fpu_flags) {
                                flags |= arch.Registers.Fcsr.NV;
                            }
                        } else {
                            result = std.math.copysign(std.math.inf(f64), a * b);

                            if (comptime config.runtime.enable_fpu_flags) {
                                flags |= arch.Registers.Fcsr.DZ;
                            }
                        }
                    } else if (std.math.isInf(a) and std.math.isInf(b)) {
                        result = arch.FloatHelpers.canonicalNanF64();

                        if (comptime config.runtime.enable_fpu_flags) {
                            flags |= arch.Registers.Fcsr.NV;
                        }
                    } else {
                        result = a / b;
                    }
                },
                .min => {
                    if (std.math.isNan(a) or std.math.isNan(b)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (arch.FloatHelpers.isSignalingNanF64(a) or arch.FloatHelpers.isSignalingNanF64(b)) {
                                flags |= arch.Registers.Fcsr.NV;
                            }
                        }

                        result = if (std.math.isNan(a) and std.math.isNan(b))
                            arch.FloatHelpers.canonicalNanF64()
                        else if (std.math.isNan(a))
                            b
                        else
                            a;
                    } else if (a == 0 and b == 0) {
                        result = if (arch.FloatHelpers.isNegativeZeroF64(a) or arch.FloatHelpers.isNegativeZeroF64(b))
                            @bitCast(@as(u64, 0x8000000000000000))
                        else
                            @as(f64, 0.0);
                    } else {
                        result = @min(a, b);
                    }
                },
                .max => {
                    if (std.math.isNan(a) or std.math.isNan(b)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (arch.FloatHelpers.isSignalingNanF64(a) or arch.FloatHelpers.isSignalingNanF64(b)) {
                                flags |= arch.Registers.Fcsr.NV;
                            }
                        }

                        result = if (std.math.isNan(a) and std.math.isNan(b))
                            arch.FloatHelpers.canonicalNanF64()
                        else if (std.math.isNan(a))
                            b
                        else
                            a;
                    } else if (a == 0 and b == 0) {
                        result = if (arch.FloatHelpers.isNegativeZeroF64(a) and arch.FloatHelpers.isNegativeZeroF64(b))
                            @bitCast(@as(u64, 0x8000000000000000))
                        else
                            @as(f64, 0.0);
                    } else {
                        result = @max(a, b);
                    }
                },
                .sgnj => {
                    const bits_a: u64 = @bitCast(a);
                    const bits_b: u64 = @bitCast(b);

                    result = @bitCast((bits_a & 0x7FFFFFFFFFFFFFFF) | (bits_b & 0x8000000000000000));
                },
                .sgnjn => {
                    const bits_a: u64 = @bitCast(a);
                    const bits_b: u64 = @bitCast(b);

                    result = @bitCast((bits_a & 0x7FFFFFFFFFFFFFFF) | (~bits_b & 0x8000000000000000));
                },
                .sgnjx => {
                    const bits_a: u64 = @bitCast(a);
                    const bits_b: u64 = @bitCast(b);

                    result = @bitCast(bits_a ^ (bits_b & 0x8000000000000000));
                },
            }

            if (comptime config.runtime.enable_fpu_flags) {
                const old_flags = this.registers.fcsr.getFflags();

                this.registers.fcsr.setFflags(old_flags | flags);
            }

            if (std.math.isNan(result)) {
                result = arch.FloatHelpers.canonicalNanF64();
            }

            this.registers.setF64(rd, result);
            this.markFpDirty();

            return .ok;
        }

        fn jitFpUnaryD(
            ctx: *anyopaque,
            op: EngineConfig.Callbacks.UnaryOpD,
            rd: u8,
            rs1: u8,
            rm: u8,
        ) callconv(.c) EngineConfig.Callbacks.FpResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            switch (op) {
                .sqrt => {
                    const mode = this.getEffectiveRm(rm) orelse return .fail;
                    _ = mode;

                    const a = this.registers.getF64(rs1);
                    var flags: u5 = 0;

                    const result = if (a < 0 and !std.math.isNan(a)) blk: {
                        if (comptime config.runtime.enable_fpu_flags) {
                            flags |= arch.Registers.Fcsr.NV;
                        }

                        break :blk arch.FloatHelpers.canonicalNanF64();
                    } else @sqrt(a);

                    if (comptime config.runtime.enable_fpu_flags) {
                        const old = this.registers.fcsr.getFflags();

                        this.registers.fcsr.setFflags(old | flags);
                    }

                    this.registers.setF64(rd, result);
                    this.markFpDirty();
                },
                .fcvt_w_d => {
                    const mode = this.getEffectiveRm(rm) orelse return .fail;
                    const a = this.registers.getF64(rs1);
                    var flags: u5 = 0;

                    const result: i32 = if (std.math.isNan(a)) blk: {
                        flags |= arch.Registers.Fcsr.NV;

                        break :blk std.math.maxInt(i32);
                    } else if (std.math.isInf(a)) blk: {
                        flags |= arch.Registers.Fcsr.NV;

                        break :blk if (a > 0) std.math.maxInt(i32) else std.math.minInt(i32);
                    } else blk: {
                        const rounded: f64 = switch (mode) {
                            .rne => arch.FloatHelpers.roundToNearestEvenF64(a),
                            .rtz => if (a >= 0) @floor(a) else @ceil(a),
                            .rdn => @floor(a),
                            .rup => @ceil(a),
                            .rmm => if (a >= 0) @floor(a + 0.5) else @ceil(a - 0.5),
                            else => arch.FloatHelpers.roundToNearestEvenF64(a),
                        };

                        if (rounded > @as(f64, @floatFromInt(std.math.maxInt(i32)))) {
                            flags |= arch.Registers.Fcsr.NV;

                            break :blk std.math.maxInt(i32);
                        } else if (rounded < @as(f64, @floatFromInt(std.math.minInt(i32)))) {
                            flags |= arch.Registers.Fcsr.NV;

                            break :blk std.math.minInt(i32);
                        } else {
                            const int_result: i32 = @intFromFloat(rounded);

                            if (comptime config.runtime.enable_fpu_flags) {
                                if (rounded != a) {
                                    flags |= arch.Registers.Fcsr.NX;
                                }
                            }

                            break :blk int_result;
                        }
                    };

                    if (comptime config.runtime.enable_fpu_flags) {
                        const old = this.registers.fcsr.getFflags();

                        this.registers.fcsr.setFflags(old | flags);
                    }

                    this.registers.set(rd, result);
                },
                .fcvt_wu_d => {
                    const mode = this.getEffectiveRm(rm) orelse return .fail;
                    const a = this.registers.getF64(rs1);
                    var flags: u5 = 0;

                    const result: u32 = if (std.math.isNan(a)) blk: {
                        flags |= arch.Registers.Fcsr.NV;

                        break :blk std.math.maxInt(u32);
                    } else if (std.math.isInf(a)) blk: {
                        flags |= arch.Registers.Fcsr.NV;

                        break :blk if (a > 0) std.math.maxInt(u32) else 0;
                    } else blk: {
                        const rounded: f64 = switch (mode) {
                            .rne => arch.FloatHelpers.roundToNearestEvenF64(a),
                            .rtz => if (a >= 0) @floor(a) else @ceil(a),
                            .rdn => @floor(a),
                            .rup => @ceil(a),
                            .rmm => if (a >= 0) @floor(a + 0.5) else @ceil(a - 0.5),
                            else => arch.FloatHelpers.roundToNearestEvenF64(a),
                        };

                        if (rounded < 0) {
                            flags |= arch.Registers.Fcsr.NV;

                            break :blk 0;
                        } else if (rounded > @as(f64, @floatFromInt(std.math.maxInt(u32)))) {
                            flags |= arch.Registers.Fcsr.NV;

                            break :blk std.math.maxInt(u32);
                        } else {
                            const int_result: u32 = @intFromFloat(rounded);

                            if (comptime config.runtime.enable_fpu_flags) {
                                if (rounded != a) {
                                    flags |= arch.Registers.Fcsr.NX;
                                }
                            }

                            break :blk int_result;
                        }
                    };

                    if (comptime config.runtime.enable_fpu_flags) {
                        const old = this.registers.fcsr.getFflags();

                        this.registers.fcsr.setFflags(old | flags);
                    }

                    this.registers.set(rd, @bitCast(result));
                },
                .fcvt_d_w => {
                    const a = this.registers.get(rs1);
                    const result: f64 = @floatFromInt(a);

                    this.registers.setF64(rd, result);
                    this.markFpDirty();
                },
                .fcvt_d_wu => {
                    const a: u32 = @bitCast(this.registers.get(rs1));
                    const result: f64 = @floatFromInt(a);

                    this.registers.setF64(rd, result);
                    this.markFpDirty();
                },
                .fcvt_s_d => {
                    const mode = this.getEffectiveRm(rm) orelse return .fail;
                    _ = mode;

                    const a = this.registers.getF64(rs1);

                    if (std.math.isNan(a)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (arch.FloatHelpers.isSignalingNanF64(a)) {
                                const old = this.registers.fcsr.getFflags();

                                this.registers.fcsr.setFflags(old | arch.Registers.Fcsr.NV);
                            }
                        }

                        this.setF32(rd, arch.FloatHelpers.canonicalNanF32());
                    } else {
                        const result: f32 = @floatCast(a);

                        if (comptime config.runtime.enable_fpu_flags) {
                            var f: u5 = 0;

                            if (std.math.isInf(result) and !std.math.isInf(a)) {
                                f |= arch.Registers.Fcsr.OF | arch.Registers.Fcsr.NX;
                            }

                            if (@as(f64, result) != a) {
                                f |= arch.Registers.Fcsr.NX;
                            }

                            if (f != 0) {
                                const old = this.registers.fcsr.getFflags();
                                this.registers.fcsr.setFflags(old | f);
                            }
                        }

                        this.setF32(rd, result);
                    }

                    this.markFpDirty();
                },
                .fcvt_d_s => {
                    const a = this.getF32(rs1);

                    if (std.math.isNan(a)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (arch.FloatHelpers.isSignalingNanF32(a)) {
                                const old = this.registers.fcsr.getFflags();

                                this.registers.fcsr.setFflags(old | arch.Registers.Fcsr.NV);
                            }
                        }

                        this.registers.setF64(rd, arch.FloatHelpers.canonicalNanF64());
                    } else {
                        this.registers.setF64(rd, @as(f64, a));
                    }

                    this.markFpDirty();
                },
                .fclass => {
                    const bits = this.registers.float[rs1];
                    const sign = (bits >> 63) != 0;
                    const exp = (bits >> 52) & 0x7FF;
                    const frac = bits & 0xFFFFFFFFFFFFF;

                    const result: u32 = if (exp == 0x7FF and frac != 0)
                        if ((frac & 0x8000000000000) != 0) (1 << 9) else (1 << 8)
                    else if (exp == 0x7FF)
                        if (sign) (1 << 0) else (1 << 7)
                    else if (exp == 0 and frac == 0)
                        if (sign) (1 << 3) else (1 << 4)
                    else if (exp == 0)
                        if (sign) (1 << 2) else (1 << 5)
                    else if (sign) (1 << 1) else (1 << 6);

                    this.registers.set(rd, @bitCast(result));
                },
            }

            return .ok;
        }

        fn jitFpFmaD(
            ctx: *anyopaque,
            op: EngineConfig.Callbacks.FmaOpS,
            rd: u8,
            rs1: u8,
            rs2: u8,
            rs3: u8,
            rm: u8,
        ) callconv(.c) EngineConfig.Callbacks.FpResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            const mode = this.getEffectiveRm(rm) orelse return .fail;
            _ = mode;

            const a = this.registers.getF64(rs1);
            const b = this.registers.getF64(rs2);
            const c = this.registers.getF64(rs3);

            const raw_result: f64 = switch (op) {
                .fmadd => @mulAdd(f64, a, b, c),
                .fmsub => @mulAdd(f64, a, b, -c),
                .fnmadd => @mulAdd(f64, -a, b, -c),
                .fnmsub => @mulAdd(f64, -a, b, c),
            };

            const result = if (std.math.isNan(raw_result))
                arch.FloatHelpers.canonicalNanF64()
            else
                raw_result;

            this.registers.setF64(rd, result);
            this.markFpDirty();

            return .ok;
        }

        fn jitFpCmpD(
            ctx: *anyopaque,
            op: EngineConfig.Callbacks.CmpOpS,
            rd: u8,
            rs1: u8,
            rs2: u8,
        ) callconv(.c) EngineConfig.Callbacks.FpResult {
            const this: *Self = @ptrCast(@alignCast(ctx));

            const a = this.registers.getF64(rs1);
            const b = this.registers.getF64(rs2);

            var flags: u5 = 0;

            const a_snan = arch.FloatHelpers.isSignalingNanF64(a);
            const b_snan = arch.FloatHelpers.isSignalingNanF64(b);
            const a_nan = std.math.isNan(a);
            const b_nan = std.math.isNan(b);

            const result: i32 = switch (op) {
                .eq => blk: {
                    if (comptime config.runtime.enable_fpu_flags) {
                        if (a_snan or b_snan) flags |= arch.Registers.Fcsr.NV;
                    }

                    break :blk if (a_nan or b_nan) 0 else if (a == b) 1 else 0;
                },
                .lt => blk: {
                    if (a_nan or b_nan) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            flags |= arch.Registers.Fcsr.NV;
                        }

                        break :blk 0;
                    }

                    break :blk if (a < b) 1 else 0;
                },
                .le => blk: {
                    if (a_nan or b_nan) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            flags |= arch.Registers.Fcsr.NV;
                        }

                        break :blk 0;
                    }

                    break :blk if (a <= b) 1 else 0;
                },
            };

            if (comptime config.runtime.enable_fpu_flags) {
                const old = this.registers.fcsr.getFflags();

                this.registers.fcsr.setFflags(old | flags);
            }

            this.registers.set(rd, result);

            return .ok;
        }

        fn jitMret(ctx: *anyopaque) callconv(.c) u32 {
            const this: *Self = @ptrCast(@alignCast(ctx));

            if (this.registers.privilege != .machine) {
                this.registers.mtval = 0;
                this.registers.mcause = .fromException(.illegal_instruction);

                return 0xFFFFFFFF;
            }

            const prev_mpp = this.registers.mstatus.mpp;
            this.registers.privilege = prev_mpp.sanitize();
            this.registers.mstatus.mie = this.registers.mstatus.mpie;
            this.registers.mstatus.mpie = true;
            this.registers.mstatus.mpp = .user;

            if (prev_mpp != .machine) {
                this.registers.mstatus.mprv = false;
            }

            return this.registers.mepc;
        }

        fn jitWfi(ctx: *anyopaque) callconv(.c) EngineConfig.State {
            const this: *Self = @ptrCast(@alignCast(ctx));

            if (this.registers.privilege == .user and this.registers.mstatus.tw) {
                this.registers.mtval = 0;
                this.registers.mcause = .fromException(.illegal_instruction);

                return .trap;
            }

            if (comptime config.hooks.wfi) |hook| {
                if (hook(@ptrCast(this))) {
                    return .ok;
                }
            }

            const mie: u32 = @bitCast(this.registers.mie);
            const mip: u32 = @bitCast(this.registers.mip);

            if (mie & mip != 0) {
                return .ok;
            }

            return .halt;
        }

        inline fn markFpDirty(this: *Self) void {
            this.registers.mstatus.fs = 0b11;
            this.registers.mstatus.updateSD();
        }

        inline fn getEffectiveRm(this: *Self, rm: u8) ?arch.Registers.Fcsr.RoundingMode {
            if (rm == 0b111) {
                const frm = this.registers.fcsr.frm;

                if (@intFromEnum(frm) >= 5) {
                    return null;
                }

                return frm;
            }

            if (rm >= 5) {
                return null;
            }

            return @enumFromInt(rm);
        }

        inline fn getF32(this: *Self, reg: u8) f32 {
            const bits = this.registers.float[reg];

            if ((bits >> 32) != 0xFFFFFFFF) {
                return arch.FloatHelpers.canonicalNanF32();
            }

            return @bitCast(@as(u32, @truncate(bits)));
        }

        inline fn setF32(this: *Self, reg: u8, val: f32) void {
            this.registers.float[reg] = 0xFFFFFFFF00000000 | @as(u64, @as(u32, @bitCast(val)));
        }

        inline fn jitComputeLayout() EngineConfig.Offsets {
            const reg_base = @offsetOf(Self, "registers");

            return .{
                .regs = reg_base + @offsetOf(arch.Registers, "common"),
                .pc = reg_base + @offsetOf(arch.Registers, "pc"),
                .cycle = reg_base + @offsetOf(arch.Registers, "cycle"),
                .instret = reg_base + @offsetOf(arch.Registers, "instret"),
                .mtime = reg_base + @offsetOf(arch.Registers, "mtime"),
                .privilege = reg_base + @offsetOf(arch.Registers, "privilege"),
                .fcsr = reg_base + @offsetOf(arch.Registers, "fcsr"),
                .mstatus = reg_base + @offsetOf(arch.Registers, "mstatus"),
                .mip = reg_base + @offsetOf(arch.Registers, "mip"),
                .float = reg_base + @offsetOf(arch.Registers, "float"),
                .trap_cause = reg_base + @offsetOf(arch.Registers, "mcause"),
                .trap_tval = reg_base + @offsetOf(arch.Registers, "mtval"),
            };
        }
    };
}

fn initRamWithCode(comptime ram_size: usize, code: []const arch.Instruction) [ram_size]u8 {
    var ram: [ram_size]u8 = std.mem.zeroes([ram_size]u8);
    var stream = std.io.fixedBufferStream(&ram);

    for (code) |instr| {
        stream.writer().writeInt(u32, instr.encode(), arch.ENDIAN) catch unreachable;
    }

    return ram;
}

fn runToEbreak(cpu: anytype) !void {
    const result = try cpu.run(std.math.maxInt(u64));

    try std.testing.expectEqual(EngineConfig.State.trap, result);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.breakpoint, cpu.registers.mcause.toException());
}

inline fn setF32(cpu: anytype, reg: u8, val: f32) void {
    cpu.registers.float[reg] = 0xFFFFFFFF00000000 | @as(u64, @as(u32, @bitCast(val)));
}

inline fn setF64(cpu: anytype, reg: u8, val: f64) void {
    cpu.registers.float[reg] = @bitCast(val);
}

inline fn getF32(cpu: anytype, reg: u8) f32 {
    const bits = cpu.registers.float[reg];

    if ((bits >> 32) != 0xFFFFFFFF) {
        return arch.FloatHelpers.canonicalNanF32();
    }

    return @bitCast(@as(u32, @truncate(bits)));
}

inline fn getF64(cpu: anytype, reg: u8) f64 {
    return @bitCast(cpu.registers.float[reg]);
}

const TestCpu = Cpu(.{});

test "jit: x0 always zero after writes" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 0, .rs1 = 0, .imm = 100 } },
        .{ .add = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } },
        .{ .lui = .{ .rd = 0, .imm = 0x12345 } },
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0 } }, // rd1 = x0 = 0
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(0));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
}

test "jit: addi positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 42), cpu.registers.get(1));
}

test "jit: addi negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .addi = .{ .rd = 2, .rs1 = 1, .imm = -3 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 7), cpu.registers.get(2));
}

test "jit: addi overflow wraps" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 2, .rs1 = 1, .imm = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();
    cpu.registers.set(1, std.math.maxInt(i32));

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.minInt(i32), cpu.registers.get(2));
}

test "jit: addi max positive immediate" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = std.math.maxInt(i12) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 2047), cpu.registers.get(1));
}

test "jit: addi min negative immediate" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = std.math.minInt(i12) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -2048), cpu.registers.get(1));
}

test "jit: addi as nop (rd=0)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 0, .rs1 = 0, .imm = 0 } },
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 77 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 77), cpu.registers.get(1));
}

test "jit: add two registers" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 100 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 200 } },
        .{ .add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 300), cpu.registers.get(3));
}

test "jit: sub result negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 10 } },
        .{ .sub = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -5), cpu.registers.get(3));
}

test "jit: sub underflow wraps" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 1 } },
        .{ .sub = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();
    cpu.registers.set(1, std.math.minInt(i32));

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.maxInt(i32), cpu.registers.get(3));
}

test "jit: and/or/xor" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0b1100 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 0b1010 } },
        .{ .@"and" = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .{ .@"or" = .{ .rd = 4, .rs1 = 1, .rs2 = 2 } },
        .{ .xor = .{ .rd = 5, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0b1000), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 0b1110), cpu.registers.get(4));
    try std.testing.expectEqual(@as(i32, 0b0110), cpu.registers.get(5));
}

test "jit: xori as bitwise NOT" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0 } },
        .{ .xori = .{ .rd = 2, .rs1 = 1, .imm = -1 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 0x55 } },
        .{ .xori = .{ .rd = 4, .rs1 = 3, .imm = -1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(2));
    try std.testing.expectEqual(@as(i32, -86), cpu.registers.get(4));
}

test "jit: ori with zero is move" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 123 } },
        .{ .ori = .{ .rd = 2, .rs1 = 1, .imm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 123), cpu.registers.get(2));
}

test "jit: andi masks bits" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0x7FF } },
        .{ .andi = .{ .rd = 2, .rs1 = 1, .imm = 0x0F } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x0F), cpu.registers.get(2));
}

test "jit: andi with negative immediate" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0x7FF } },
        .{ .andi = .{ .rd = 2, .rs1 = 1, .imm = -1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x7FF), cpu.registers.get(2));
}

test "jit: slli by 0 is identity" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0x123 } },
        .{ .slli = .{ .rd = 2, .rs1 = 1, .shamt = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x123), cpu.registers.get(2));
}

test "jit: slli by 31" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
        .{ .slli = .{ .rd = 2, .rs1 = 1, .shamt = 31 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.minInt(i32), cpu.registers.get(2));
}

test "jit: srli logical shift" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .srli = .{ .rd = 2, .rs1 = 1, .shamt = 31 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();
    cpu.registers.set(1, std.math.minInt(i32)); // 0x80000000

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(2));
}

test "jit: srai sign extends" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } },
        .{ .srai = .{ .rd = 2, .rs1 = 1, .shamt = 31 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 0x100 } },
        .{ .srai = .{ .rd = 4, .rs1 = 3, .shamt = 4 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(2));
    try std.testing.expectEqual(@as(i32, 0x10), cpu.registers.get(4));
}

test "jit: sll uses only lower 5 bits of shift" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 32 } }, // 32 & 0x1F = 0
        .{ .sll = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .{ .addi = .{ .rd = 4, .rs1 = 0, .imm = 33 } }, // 33 & 0x1F = 1
        .{ .sll = .{ .rd = 5, .rs1 = 1, .rs2 = 4 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3)); // No shift
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(5)); // Shift by 1
}

test "jit: srl and sra difference" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 4 } },
        .{ .srl = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .{ .sra = .{ .rd = 4, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();
    cpu.registers.set(1, @as(i32, @bitCast(@as(u32, 0x80000010))));

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x08000001))), cpu.registers.get(3)); // Logical
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xF8000001))), cpu.registers.get(4)); // Arithmetic
}

test "jit: slt signed comparison" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .slt = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } }, // -5 < 5 = 1
        .{ .slt = .{ .rd = 4, .rs1 = 2, .rs2 = 1 } }, // 5 < -5 = 0
        .{ .slt = .{ .rd = 5, .rs1 = 1, .rs2 = 1 } }, // -5 < -5 = 0
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(4));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(5));
}

test "jit: sltu unsigned comparison" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } }, // 0xFFFFFFFF
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 1 } },
        .{ .sltu = .{ .rd = 3, .rs1 = 2, .rs2 = 1 } }, // 1 < 0xFFFFFFFF = 1
        .{ .sltu = .{ .rd = 4, .rs1 = 1, .rs2 = 2 } }, // 0xFFFFFFFF < 1 = 0
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(4));
}

test "jit: slti signed immediate" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -10 } },
        .{ .slti = .{ .rd = 2, .rs1 = 1, .imm = -5 } }, // -10 < -5 = 1
        .{ .slti = .{ .rd = 3, .rs1 = 1, .imm = -15 } }, // -10 < -15 = 0
        .{ .slti = .{ .rd = 4, .rs1 = 1, .imm = -10 } }, // -10 < -10 = 0
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(2));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(4));
}

test "jit: sltiu seqz idiom" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .sltiu = .{ .rd = 3, .rs1 = 1, .imm = 1 } }, // 0 < 1 = 1 (is zero)
        .{ .sltiu = .{ .rd = 4, .rs1 = 2, .imm = 1 } }, // 5 < 1 = 0 (not zero)
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(4));
}

test "jit: lui loads upper immediate" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .lui = .{ .rd = 1, .imm = 0x12345 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345000), cpu.registers.get(1));
}

test "jit: lui negative upper immediate" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .lui = .{ .rd = 1, .imm = @truncate(0xFFFFF) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFF000))), cpu.registers.get(1));
}

test "jit: lui + addi full 32-bit constant" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .lui = .{ .rd = 1, .imm = 0x12345 } },
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = 0x678 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(1));
}

test "jit: auipc at non-zero PC" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 0, .rs1 = 0, .imm = 0 } }, // NOP at 0
        .{ .addi = .{ .rd = 0, .rs1 = 0, .imm = 0 } }, // NOP at 4
        .{ .auipc = .{ .rd = 1, .imm = 0x12345 } }, // At PC=8
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x12345000 + 8))), cpu.registers.get(1));
}

test "jit: auipc with zero upper" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .auipc = .{ .rd = 1, .imm = 0 } }, // PC + 0 = 0
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
}

test "jit: jal forward jump with link" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .jal = .{ .rd = 1, .imm = 8 } }, // 0: jump to 8
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 1 } }, // 4: skipped
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 2 } }, // 8: executed
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 4), cpu.registers.get(1)); // return addr
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2)); // skipped
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(3));
}

test "jit: jal rd=x0 discards link" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .jal = .{ .rd = 0, .imm = 8 } },
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(0));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(2));
}

test "jit: jal backward jump" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 99 } }, // 0
        .{ .jal = .{ .rd = 0, .imm = 8 } }, // 4: jump to 12
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } }, // 8: skipped first, executed later
        .{ .jal = .{ .rd = 0, .imm = -4 } }, // 12: jump back to 8
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // 4 steps: addi, jal->12, jal->8, addi
    _ = try cpu.run(4);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(1));
}

test "jit: jalr clears LSB" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 13 } }, // Odd address
        .{ .jalr = .{ .rd = 2, .rs1 = 1, .imm = 0 } }, // Jump to 12 (LSB cleared)
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // 8: skipped
        .{ .addi = .{ .rd = 4, .rs1 = 0, .imm = 2 } }, // 12: executed
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 8), cpu.registers.get(2)); // return addr
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(4));
}

test "jit: jalr with negative offset" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 5, .rs1 = 0, .imm = 77 } }, // 0
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 16 } }, // 4
        .{ .jalr = .{ .rd = 2, .rs1 = 1, .imm = -4 } }, // 8: jump to 12
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // 12: executed
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 12), cpu.registers.get(2));
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit: beq taken" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .beq = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // skipped
        .{ .addi = .{ .rd = 4, .rs1 = 0, .imm = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(4));
}

test "jit: beq not taken" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 10 } },
        .{ .beq = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // executed
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit: bne not taken when equal" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .bne = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // executed
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit: blt signed negative < positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .blt = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } }, // taken
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // skipped
        .{ .addi = .{ .rd = 4, .rs1 = 0, .imm = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(4));
}

test "jit: bltu unsigned (signed negative is large unsigned)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } }, // 0xFFFFFFFF
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 1 } },
        .{ .bltu = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } }, // MAX < 1 = false, not taken
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // executed
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit: bge equal values" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .bge = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } }, // 5 >= 5 taken
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // skipped
        .{ .addi = .{ .rd = 4, .rs1 = 0, .imm = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(4));
}

test "jit: bge not taken" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 10 } },
        .{ .bge = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } }, // 5 >= 10 = false
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // executed
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit: bgeu equal values" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .bgeu = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // skipped
        .{ .addi = .{ .rd = 4, .rs1 = 0, .imm = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(4));
}

test "jit: backward branch loop" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0 } }, // counter = 0
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } }, // target = 5
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = 1 } }, // 8: increment
        .{ .bne = .{ .rs1 = 1, .rs2 = 2, .imm = -4 } }, // loop back to 8
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 5), cpu.registers.get(1));
}

test "jit: sum loop 1..5" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } }, // n = 5
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 0 } }, // sum = 0
        .{ .add = .{ .rd = 2, .rs1 = 2, .rs2 = 1 } }, // 8: sum += n
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = -1 } }, // n--
        .{ .bne = .{ .rs1 = 1, .rs2 = 0, .imm = -8 } }, // if n!=0 goto 8
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
    try std.testing.expectEqual(@as(i32, 15), cpu.registers.get(2)); // 1+2+3+4+5
}

test "jit: lw/sw round trip" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 200 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 42 } },
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
        .{ .lw = .{ .rd = 3, .rs1 = 1, .imm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 42), cpu.registers.get(3));
}

test "jit: lb sign extension 0x80" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 200 } },
        .{ .lb = .{ .rd = 3, .rs1 = 1, .imm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();
    ram[200] = 0x80;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -128), cpu.registers.get(3));
}

test "jit: lbu no sign extension 0x80" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 200 } },
        .{ .lbu = .{ .rd = 3, .rs1 = 1, .imm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();
    ram[200] = 0x80;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 128), cpu.registers.get(3));
}

test "jit: lh sign extension 0x8000" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 200 } },
        .{ .lh = .{ .rd = 3, .rs1 = 1, .imm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();
    std.mem.writeInt(u16, ram[200..202], 0x8000, .little);

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -32768), cpu.registers.get(3));
}

test "jit: lhu no sign extension 0x8000" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 200 } },
        .{ .lhu = .{ .rd = 3, .rs1 = 1, .imm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();
    std.mem.writeInt(u16, ram[200..202], 0x8000, .little);

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x8000), cpu.registers.get(3));
}

test "jit: sb stores only byte" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 200 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 0x41 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 0x42 } },
        .{ .addi = .{ .rd = 4, .rs1 = 0, .imm = 0x43 } },
        .{ .addi = .{ .rd = 5, .rs1 = 0, .imm = 0x44 } },
        .{ .sb = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
        .{ .sb = .{ .rs1 = 1, .rs2 = 3, .imm = 1 } },
        .{ .sb = .{ .rs1 = 1, .rs2 = 4, .imm = 2 } },
        .{ .sb = .{ .rs1 = 1, .rs2 = 5, .imm = 3 } },
        .{ .lw = .{ .rd = 6, .rs1 = 1, .imm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x44434241), cpu.registers.get(6));
}

test "jit: load/store with positive offset" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 200 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 42 } },
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 20 } }, // Store at 220
        .{ .lw = .{ .rd = 3, .rs1 = 1, .imm = 20 } }, // Load from 220
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 42), cpu.registers.get(3));
}

test "jit: load/store with negative offset" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 220 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 55 } },
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = -20 } }, // Store at 200
        .{ .lw = .{ .rd = 3, .rs1 = 1, .imm = -20 } }, // Load from 200
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 55), cpu.registers.get(3));
}

test "jit: memory copy loop" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        // Store source data at 200-215
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 200 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 0x11 } },
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 0x22 } },
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 4 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 0x33 } },
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 0x44 } },
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 12 } },
        // Copy loop: src=200, dst=240, count=4
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 200 } }, // src
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 240 } }, // dst
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 4 } }, // count
        .{ .lw = .{ .rd = 4, .rs1 = 1, .imm = 0 } }, // 48: load
        .{ .sw = .{ .rs1 = 2, .rs2 = 4, .imm = 0 } }, // store
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = 4 } },
        .{ .addi = .{ .rd = 2, .rs1 = 2, .imm = 4 } },
        .{ .addi = .{ .rd = 3, .rs1 = 3, .imm = -1 } },
        .{ .bne = .{ .rs1 = 3, .rs2 = 0, .imm = -20 } }, // back to 48
        // Verify
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 240 } },
        .{ .lw = .{ .rd = 5, .rs1 = 1, .imm = 0 } },
        .{ .lw = .{ .rd = 6, .rs1 = 1, .imm = 4 } },
        .{ .lw = .{ .rd = 7, .rs1 = 1, .imm = 8 } },
        .{ .lw = .{ .rd = 8, .rs1 = 1, .imm = 12 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x11), cpu.registers.get(5));
    try std.testing.expectEqual(@as(i32, 0x22), cpu.registers.get(6));
    try std.testing.expectEqual(@as(i32, 0x33), cpu.registers.get(7));
    try std.testing.expectEqual(@as(i32, 0x44), cpu.registers.get(8));
}

test "jit: mul basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 7 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 6 } },
        .{ .mul = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 42), cpu.registers.get(3));
}

test "jit: mul negative * positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 3 } },
        .{ .mul = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -15), cpu.registers.get(3));
}

test "jit: mul negative * negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -3 } },
        .{ .mul = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 15), cpu.registers.get(3));
}

test "jit: mul by zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1000 } },
        .{ .mul = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "jit: mul overflow returns lower 32 bits" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .lui = .{ .rd = 1, .imm = 0x10000 } }, // 0x10000000
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 16 } },
        .{ .mul = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3)); // 0x100000000 truncated
}

test "jit: mulh upper bits" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .lui = .{ .rd = 1, .imm = 0x10000 } }, // 0x10000000
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 16 } },
        .{ .mulh = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit: mulh negative * positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 2 } },
        .{ .mulh = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(3));
}

test "jit: mulh negative * negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -1 } },
        .{ .mulh = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3)); // (-1)*(-1) = 1
}

test "jit: mulhu large unsigned" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } }, // 0xFFFFFFFF
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 2 } },
        .{ .mulhu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    // 0xFFFFFFFF * 2 = 0x1_FFFFFFFE, upper = 1
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit: mulhsu signed * unsigned" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -1 } }, // 0xFFFFFFFF as unsigned
        .{ .mulhsu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    // 1(signed) * 0xFFFFFFFF(unsigned) = 0xFFFFFFFF, upper = 0
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "jit: mulhsu negative signed" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } }, // signed -1
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 1 } }, // unsigned 1
        .{ .mulhsu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    // (-1)(signed) * 1(unsigned) = -1 (64-bit), upper = -1
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(3));
}

test "jit: div basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 20 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 3 } },
        .{ .div = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 6), cpu.registers.get(3));
}

test "jit: div by zero returns -1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .div = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(3));
}

test "jit: div negative dividend" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -10 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 3 } },
        .{ .div = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -3), cpu.registers.get(3));
}

test "jit: div negative divisor" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -3 } },
        .{ .div = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -3), cpu.registers.get(3));
}

test "jit: div overflow MIN_INT / -1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -1 } },
        .{ .div = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();
    cpu.registers.set(1, std.math.minInt(i32));

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.minInt(i32), cpu.registers.get(3));
}

test "jit: divu basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 20 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 3 } },
        .{ .divu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 6), cpu.registers.get(3));
}

test "jit: divu by zero returns max unsigned" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .divu = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFFFFF))), cpu.registers.get(3));
}

test "jit: divu treats operands as unsigned" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -4 } }, // 0xFFFFFFFC
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 2 } },
        .{ .divu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    // 0xFFFFFFFC / 2 = 0x7FFFFFFE
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x7FFFFFFE))), cpu.registers.get(3));
}

test "jit: rem basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 20 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 3 } },
        .{ .rem = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(3));
}

test "jit: rem by zero returns dividend" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .rem = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 10), cpu.registers.get(3));
}

test "jit: rem negative dividend" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -10 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 3 } },
        .{ .rem = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(3));
}

test "jit: rem overflow MIN_INT % -1 returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -1 } },
        .{ .rem = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();
    cpu.registers.set(1, std.math.minInt(i32));

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "jit: remu basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 20 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 3 } },
        .{ .remu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(3));
}

test "jit: remu by zero returns dividend" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .remu = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 10), cpu.registers.get(3));
}

test "jit: remu treats as unsigned" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } }, // 0xFFFFFFFF
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 10 } },
        .{ .remu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    // 0xFFFFFFFF % 10 = 5
    try std.testing.expectEqual(@as(i32, 5), cpu.registers.get(3));
}

test "jit: function call and return" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        // Main
        .{ .addi = .{ .rd = 10, .rs1 = 0, .imm = 7 } }, // 0: arg = 7
        .{ .jal = .{ .rd = 1, .imm = 12 } }, // 4: call double (at 16)
        .{ .addi = .{ .rd = 11, .rs1 = 10, .imm = 0 } }, // 8: save result
        .ebreak, // 12: done
        // Function "double" at 16
        .{ .add = .{ .rd = 10, .rs1 = 10, .rs2 = 10 } }, // 16: a0 *= 2
        .{ .jalr = .{ .rd = 0, .rs1 = 1, .imm = 0 } }, // 20: return
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 14), cpu.registers.get(10)); // 7 * 2
    try std.testing.expectEqual(@as(i32, 14), cpu.registers.get(11));
}

test "jit: nested function calls" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        // Main: store ra on stack, call add3(5)
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 400 } }, // 0: sp = 400
        .{ .addi = .{ .rd = 10, .rs1 = 0, .imm = 5 } }, // 4: arg = 5
        .{ .jal = .{ .rd = 1, .imm = 16 } }, // 8: call add3 at 24
        .{ .addi = .{ .rd = 11, .rs1 = 10, .imm = 0 } }, // 12: save result
        .ebreak, // 16
        .{ .addi = .{ .rd = 0, .rs1 = 0, .imm = 0 } }, // 20: padding
        // add3: saves ra, calls add1 three times
        .{ .sw = .{ .rs1 = 2, .rs2 = 1, .imm = -4 } }, // 24: save ra
        .{ .jal = .{ .rd = 1, .imm = 20 } }, // 28: call add1 at 48
        .{ .jal = .{ .rd = 1, .imm = 16 } }, // 32: call add1 at 48
        .{ .jal = .{ .rd = 1, .imm = 12 } }, // 36: call add1 at 48
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = -4 } }, // 40: restore ra
        .{ .jalr = .{ .rd = 0, .rs1 = 1, .imm = 0 } }, // 44: return
        // add1: a0 += 1
        .{ .addi = .{ .rd = 10, .rs1 = 10, .imm = 1 } }, // 48
        .{ .jalr = .{ .rd = 0, .rs1 = 1, .imm = 0 } }, // 52: return
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 8), cpu.registers.get(10)); // 5 + 3
    try std.testing.expectEqual(@as(i32, 8), cpu.registers.get(11));
}

test "jit: fibonacci iterative" {
    const allocator = std.testing.allocator;
    // Compute fib(10) = 55
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } }, // 0: n = 10
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 0 } }, // 4: a = 0
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // 8: b = 1
        // loop:
        .{ .beq = .{ .rs1 = 1, .rs2 = 0, .imm = 24 } }, // 12: if n==0 goto 36 (ebreak)
        .{ .add = .{ .rd = 4, .rs1 = 2, .rs2 = 3 } }, // 16: tmp = a + b
        .{ .addi = .{ .rd = 2, .rs1 = 3, .imm = 0 } }, // 20: a = b
        .{ .addi = .{ .rd = 3, .rs1 = 4, .imm = 0 } }, // 24: b = tmp
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = -1 } }, // 28: n--
        .{ .jal = .{ .rd = 0, .imm = -20 } }, // 32: goto 12
        // done:
        .ebreak, // 36
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 55), cpu.registers.get(2));
}

test "jit: M extension comprehensive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 100 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 7 } },
        // div + rem should reconstruct: (a/b)*b + (a%b) == a
        .{ .div = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } }, // 100/7 = 14
        .{ .rem = .{ .rd = 4, .rs1 = 1, .rs2 = 2 } }, // 100%7 = 2
        .{ .mul = .{ .rd = 5, .rs1 = 3, .rs2 = 2 } }, // 14*7 = 98
        .{ .add = .{ .rd = 6, .rs1 = 5, .rs2 = 4 } }, // 98+2 = 100
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 14), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(4));
    try std.testing.expectEqual(@as(i32, 98), cpu.registers.get(5));
    try std.testing.expectEqual(@as(i32, 100), cpu.registers.get(6)); // Reconstructed
}

test "jit: store near code boundary" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 100 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -1 } }, // 0xFFFFFFFF
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
        .{ .lw = .{ .rd = 3, .rs1 = 1, .imm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(3));
}

test "jit: many small blocks" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        // Each branch ends a block, so we get many blocks
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0 } },
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = 1 } },
        .{ .jal = .{ .rd = 0, .imm = 4 } }, // jump to next instruction (creates new block)
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = 1 } },
        .{ .jal = .{ .rd = 0, .imm = 4 } },
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = 1 } },
        .{ .jal = .{ .rd = 0, .imm = 4 } },
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = 1 } },
        .{ .jal = .{ .rd = 0, .imm = 4 } },
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 5), cpu.registers.get(1));
}

test "jit f: flw basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flw = .{ .rd = 1, .rs1 = 0, .imm = 256 } },
        .ebreak,
    });

    const test_val: f32 = 3.14159;
    @memcpy(ram[256..260], std.mem.asBytes(&test_val));

    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectApproxEqRel(@as(f32, 3.14159), getF32(&cpu, 1), 0.0001);
}

test "jit f: flw sets mstatus.fs to dirty" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flw = .{ .rd = 1, .rs1 = 0, .imm = 256 } },
        .ebreak,
    });

    const test_val: f32 = 1.0;
    @memcpy(ram[256..260], std.mem.asBytes(&test_val));

    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(u2, 0b11), cpu.registers.mstatus.fs);
}

test "jit f: flw result is NaN-boxed" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flw = .{ .rd = 1, .rs1 = 0, .imm = 256 } },
        .ebreak,
    });

    const test_val: f32 = 1.0;
    @memcpy(ram[256..260], std.mem.asBytes(&test_val));

    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // FLW must NaN-box: upper 32 bits = 0xFFFFFFFF
    const raw = cpu.registers.float[1];
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), @as(u32, @truncate(raw >> 32)));
    try std.testing.expectEqual(@as(f32, 1.0), getF32(&cpu, 1));
}

test "jit f: flw with negative offset" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flw = .{ .rd = 1, .rs1 = 5, .imm = @intCast(@as(i12, -4)) } },
        .ebreak,
    });

    // Store a float at byte offset 256
    const test_val: f32 = 7.5;
    @memcpy(ram[256..260], std.mem.asBytes(&test_val));

    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(5, 260); // base=260, effective address = 260 + (-4) = 256
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 7.5), getF32(&cpu, 1));
}

test "jit f: flw then fsw roundtrip preserves bits" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flw = .{ .rd = 1, .rs1 = 0, .imm = 256 } },
        .{ .fsw = .{ .rs1 = 0, .rs2 = 1, .imm = 260 } },
        .ebreak,
    });

    // Use a denormal to ensure exact bit preservation
    const test_bits: u32 = 0x00400000; // Positive subnormal
    @memcpy(ram[256..260], std.mem.asBytes(&test_bits));

    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);

    const stored_bits = std.mem.bytesToValue(u32, ram[260..264]);
    try std.testing.expectEqual(test_bits, stored_bits);
}

test "jit f: flw with fs=Off traps illegal instruction" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flw = .{ .rd = 1, .rs1 = 0, .imm = 256 } },
        .ebreak,
    });

    const test_val: f32 = 1.0;
    @memcpy(ram[256..260], std.mem.asBytes(&test_val));

    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mstatus.fs = 0b00; // Off

    const result = try cpu.run(std.math.maxInt(u64));
    try std.testing.expectEqual(.trap, result);
    try std.testing.expectEqual(false, cpu.registers.mcause.interrupt);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, cpu.registers.mcause.toException());
}

test "jit f: fsw basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsw = .{ .rs1 = 0, .rs2 = 1, .imm = 256 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 2.71828);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);

    const stored: f32 = std.mem.bytesToValue(f32, ram[256..260]);
    try std.testing.expectApproxEqRel(@as(f32, 2.71828), stored, 0.0001);
}

test "jit f: fsw does not change mstatus.fs from initial" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsw = .{ .rs1 = 0, .rs2 = 1, .imm = 256 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    cpu.registers.mstatus.fs = 0b01; // Initial (clean)

    try runToEbreak(&cpu);
    // FSW reads from FP reg, doesn't write to FP reg, so fs stays clean
    // (This depends on implementation - some set dirty on any FP access)
    // Per spec, only FP register writes should set dirty
    try std.testing.expectEqual(@as(u2, 0b01), cpu.registers.mstatus.fs);
}

test "jit f: fsw with negative offset" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsw = .{ .rs1 = 5, .rs2 = 1, .imm = @intCast(@as(i12, -4)) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 12.25);
    cpu.registers.set(5, 264); // base=264, effective address = 264 + (-4) = 260
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);

    const stored: f32 = std.mem.bytesToValue(f32, ram[260..264]);
    try std.testing.expectEqual(@as(f32, 12.25), stored);
}

test "jit f: fsw with fs=Off traps illegal instruction" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsw = .{ .rs1 = 0, .rs2 = 1, .imm = 256 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    cpu.registers.mstatus.fs = 0b00; // Off

    const result = try cpu.run(std.math.maxInt(u64));
    try std.testing.expectEqual(.trap, result);
    try std.testing.expectEqual(false, cpu.registers.mcause.interrupt);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, cpu.registers.mcause.toException());
}

test "jit f: fadd.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fadd_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 2.5);
    setF32(&cpu, 2, 3.5);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 6.0), getF32(&cpu, 3));
}

test "jit f: fadd.s sets mstatus.fs to dirty" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fadd_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 1.0);
    setF32(&cpu, 2, 2.0);
    cpu.registers.mstatus.fs = 0b01; // Initial

    try runToEbreak(&cpu);
    // Any FP write must set fs = Dirty (0b11)
    try std.testing.expectEqual(@as(u2, 0b11), cpu.registers.mstatus.fs);
}

test "jit f: fadd.s +inf + -inf sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fadd_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, std.math.inf(f32));
    setF32(&cpu, 2, -std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 3)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fadd.s with improper nan-boxing treats input as canonical NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fadd_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // Set f1 with improper NaN-boxing (upper 32 bits not all 1s)
    cpu.registers.float[1] = 0x00000000_40000000; // Not properly boxed 2.0
    setF32(&cpu, 2, 1.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // Improperly boxed value must be treated as canonical NaN
    try std.testing.expect(std.math.isNan(getF32(&cpu, 3)));
}

test "jit f: fadd.s with subnormals produces correct result" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fadd_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    const subnormal1: f32 = @bitCast(@as(u32, 0x00000002)); // 2 * min_subnormal
    const subnormal2: f32 = @bitCast(@as(u32, 0x00000003)); // 3 * min_subnormal
    setF32(&cpu, 1, subnormal1);
    setF32(&cpu, 2, subnormal2);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // 2 + 3 = 5 * min_subnormal
    const result: u32 = @bitCast(getF32(&cpu, 3));
    try std.testing.expectEqual(@as(u32, 0x00000005), result);
}

test "jit f: fadd.s with fs=Off traps illegal instruction" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fadd_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 1.0);
    setF32(&cpu, 2, 2.0);
    cpu.registers.mstatus.fs = 0b00; // Off

    const result = try cpu.run(std.math.maxInt(u64));
    try std.testing.expectEqual(.trap, result);
    try std.testing.expectEqual(false, cpu.registers.mcause.interrupt);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, cpu.registers.mcause.toException());
}

test "jit f: fadd.s with sNaN sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fadd_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x7F800001))); // sNaN
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 3)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fsub.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsub_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 10.0);
    setF32(&cpu, 2, 3.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 7.0), getF32(&cpu, 3));
}

test "jit f: fsub.s with NaN returns NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsub_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 3)));
}

test "jit f: fsub.s inf minus inf sets NV" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsub_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, std.math.inf(f32));
    setF32(&cpu, 2, std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 3)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fsub.s with subnormals" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsub_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    const subnormal1: f32 = @bitCast(@as(u32, 0x00000005)); // 5 * min_subnormal
    const subnormal2: f32 = @bitCast(@as(u32, 0x00000002)); // 2 * min_subnormal
    setF32(&cpu, 1, subnormal1);
    setF32(&cpu, 2, subnormal2);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    const result: u32 = @bitCast(getF32(&cpu, 3));
    try std.testing.expectEqual(@as(u32, 0x00000003), result); // 3 * min_subnormal
}

test "jit f: fmul.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmul_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 3.0);
    setF32(&cpu, 2, 4.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 12.0), getF32(&cpu, 3));
}

test "jit f: fmul.s underflow sets UF flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmul_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // Use values that produce a subnormal (not flushed to zero)
    // so we can test UF in isolation
    const small_normal: f32 = @bitCast(@as(u32, 0x00800000)); // smallest normal
    setF32(&cpu, 1, small_normal);
    setF32(&cpu, 2, 0.5);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    // Result is subnormal → UF
    const result = getF32(&cpu, 3);
    try std.testing.expect(arch.FloatHelpers.isSubnormalF32(result));
    try std.testing.expect(cpu.registers.fcsr.uf);
}

test "jit f: fmul.s overflow sets OF flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmul_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, std.math.floatMax(f32));
    setF32(&cpu, 2, 2.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isPositiveInf(getF32(&cpu, 3)));
    try std.testing.expect(cpu.registers.fcsr.of);
}

test "jit f: fmul.s subnormal underflow to zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmul_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    const subnormal: f32 = @bitCast(@as(u32, 0x00000001)); // Smallest subnormal
    setF32(&cpu, 1, subnormal);
    setF32(&cpu, 2, 0.5);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // Result underflows to zero
    try std.testing.expectEqual(@as(f32, 0.0), getF32(&cpu, 3));
}

test "jit f: fmul.s 0*inf sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmul_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 0.0);
    setF32(&cpu, 2, std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 3)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fdiv.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fdiv_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 10.0);
    setF32(&cpu, 2, 2.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 5.0), getF32(&cpu, 3));
}

test "jit f: fdiv.s zero by zero returns NaN and sets NV" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fdiv_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 0.0);
    setF32(&cpu, 2, 0.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 3)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fdiv.s negative by zero returns negative infinity and sets DZ" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fdiv_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -5.0);
    setF32(&cpu, 2, 0.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNegativeInf(getF32(&cpu, 3)));
    try std.testing.expect(cpu.registers.fcsr.dz);
}

test "jit f: fdiv.s inf by inf returns NaN and sets NV" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fdiv_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, std.math.inf(f32));
    setF32(&cpu, 2, std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 3)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fdiv.s by zero sets DZ flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fdiv_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    setF32(&cpu, 2, 0.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isPositiveInf(getF32(&cpu, 3)));
    try std.testing.expect(cpu.registers.fcsr.dz);
}

test "jit f: fdiv.s inexact sets NX flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fdiv_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 1.0);
    setF32(&cpu, 2, 3.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    // 1.0 / 3.0 = 0.333... (inexact)
    try std.testing.expect(cpu.registers.fcsr.nx);
}

test "jit f: fdiv.s with NaN returns NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fdiv_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 3)));
}

test "jit f: fsqrt.s basic positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsqrt_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 16.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 4.0), getF32(&cpu, 2));
}

test "jit f: fsqrt.s of positive zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsqrt_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 0.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // IEEE 754: sqrt(+0) = +0
    try std.testing.expectEqual(@as(f32, 0.0), getF32(&cpu, 2));
    try std.testing.expect(!arch.FloatHelpers.isNegativeZeroF32(getF32(&cpu, 2)));
}

test "jit f: fsqrt.s of negative zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsqrt_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x80000000))); // -0.0
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // IEEE 754: sqrt(-0) = -0
    try std.testing.expect(arch.FloatHelpers.isNegativeZeroF32(getF32(&cpu, 2)));
}

test "jit f: fsqrt.s of positive infinity" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsqrt_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // IEEE 754: sqrt(+inf) = +inf
    try std.testing.expect(std.math.isPositiveInf(getF32(&cpu, 2)));
}

test "jit f: fsqrt.s of qNaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsqrt_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 2)));
}

test "jit f: fsqrt.s of negative infinity returns NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsqrt_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 2)));
}

test "jit f: fsqrt.s of negative sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsqrt_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -4.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 2)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fsqrt.s with sNaN sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsqrt_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x7F800001))); // sNaN
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 2)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fmin.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmin_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    setF32(&cpu, 2, 3.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 3.0), getF32(&cpu, 3));
}

test "jit f: fmin.s with mixed zeros returns negative zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmin_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @as(f32, 0.0)); // +0.0
    setF32(&cpu, 2, @bitCast(@as(u32, 0x80000000))); // -0.0
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RISC-V spec (IEEE 754-2008): fmin(+0, -0) = -0
    const result = getF32(&cpu, 3);
    try std.testing.expectEqual(@as(f32, 0.0), result);
    try std.testing.expect(arch.FloatHelpers.isNegativeZeroF32(result));
}

test "jit f: fmin.s with both qNaN returns canonical NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmin_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    setF32(&cpu, 2, arch.FloatHelpers.canonicalNanF32());
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 3)));
}

test "jit f: fmin.s rs1 NaN rs2 number returns rs2" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmin_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    setF32(&cpu, 2, -3.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, -3.0), getF32(&cpu, 3));
}

test "jit f: fmin.s with sNaN sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmin_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x7F800001))); // sNaN
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    // Result should be the non-NaN value
    try std.testing.expectEqual(@as(f32, 5.0), getF32(&cpu, 3));
    // sNaN signals NV
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fmin.s both negative zeros returns negative zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmin_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x80000000))); // -0.0
    setF32(&cpu, 2, @bitCast(@as(u32, 0x80000000))); // -0.0
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    const result = getF32(&cpu, 3);
    try std.testing.expect(arch.FloatHelpers.isNegativeZeroF32(result));
}

test "jit f: fmax.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmax_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 3.0);
    setF32(&cpu, 2, 7.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 7.0), getF32(&cpu, 3));
}

test "jit f: fmax.s both negative zeros returns negative zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmax_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x80000000))); // -0.0
    setF32(&cpu, 2, @bitCast(@as(u32, 0x80000000))); // -0.0
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    const result = getF32(&cpu, 3);
    try std.testing.expect(arch.FloatHelpers.isNegativeZeroF32(result));
}

test "jit f: fmax.s both positive zeros returns positive zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmax_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 0.0);
    setF32(&cpu, 2, 0.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    const result = getF32(&cpu, 3);
    try std.testing.expectEqual(@as(f32, 0.0), result);
    try std.testing.expect(!arch.FloatHelpers.isNegativeZeroF32(result));
}

test "jit f: fmax.s with mixed zeros returns positive zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmax_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @as(f32, 0.0)); // +0.0
    setF32(&cpu, 2, @bitCast(@as(u32, 0x80000000))); // -0.0
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RISC-V spec: fmax(+0, -0) = +0
    const result = getF32(&cpu, 3);
    try std.testing.expectEqual(@as(f32, 0.0), result);
    try std.testing.expect(!arch.FloatHelpers.isNegativeZeroF32(result));
}

test "jit f: fmax.s with one qNaN returns other" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmax_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 5.0), getF32(&cpu, 3));
}

test "jit f: fmax.s with both qNaN returns canonical NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmax_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    setF32(&cpu, 2, arch.FloatHelpers.canonicalNanF32());
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 3)));
}

test "jit f: fmax.s rs1 number rs2 NaN returns rs1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmax_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -7.0);
    setF32(&cpu, 2, arch.FloatHelpers.canonicalNanF32());
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, -7.0), getF32(&cpu, 3));
}

test "jit f: fmax.s with sNaN sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmax_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    setF32(&cpu, 2, @bitCast(@as(u32, 0x7F800001))); // sNaN
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 5.0), getF32(&cpu, 3));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fmadd.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmadd_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 2.0);
    setF32(&cpu, 2, 3.0);
    setF32(&cpu, 3, 4.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // fmadd: rs1*rs2 + rs3 = 2*3 + 4 = 10
    try std.testing.expectEqual(@as(f32, 10.0), getF32(&cpu, 4));
}

test "jit f: fmadd.s with NaN propagates NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmadd_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 2.0);
    setF32(&cpu, 2, arch.FloatHelpers.canonicalNanF32());
    setF32(&cpu, 3, 4.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 4)));
}

test "jit f: fmadd.s 0 * inf + x sets NV" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmadd_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 0.0);
    setF32(&cpu, 2, std.math.inf(f32));
    setF32(&cpu, 3, 1.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 4)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fmadd.s inf * x + (-inf) sets NV" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmadd_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, std.math.inf(f32));
    setF32(&cpu, 2, 1.0);
    setF32(&cpu, 3, -std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    // inf + (-inf) = NaN
    try std.testing.expect(std.math.isNan(getF32(&cpu, 4)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fmadd.s with sNaN sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmadd_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x7F800001))); // sNaN
    setF32(&cpu, 2, 2.0);
    setF32(&cpu, 3, 3.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 4)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fmsub.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmsub_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 3.0);
    setF32(&cpu, 2, 4.0);
    setF32(&cpu, 3, 2.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // fmsub: rs1*rs2 - rs3 = 3*4 - 2 = 10
    try std.testing.expectEqual(@as(f32, 10.0), getF32(&cpu, 4));
}

test "jit f: fmsub.s with NaN propagates NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmsub_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 2.0);
    setF32(&cpu, 2, 3.0);
    setF32(&cpu, 3, arch.FloatHelpers.canonicalNanF32());
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 4)));
}

test "jit f: fmsub.s 0 * inf sets NV" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmsub_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 0.0);
    setF32(&cpu, 2, std.math.inf(f32));
    setF32(&cpu, 3, 1.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 4)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fnmadd.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fnmadd_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 3.0);
    setF32(&cpu, 2, 4.0);
    setF32(&cpu, 3, 2.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // fnmadd: -(rs1*rs2) - rs3 = -(3*4) - 2 = -12 - 2 = -14
    try std.testing.expectEqual(@as(f32, -14.0), getF32(&cpu, 4));
}

test "jit f: fnmadd.s with NaN propagates NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fnmadd_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 2.0);
    setF32(&cpu, 2, arch.FloatHelpers.canonicalNanF32());
    setF32(&cpu, 3, 4.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 4)));
}

test "jit f: fnmadd.s 0 * inf sets NV" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fnmadd_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 0.0);
    setF32(&cpu, 2, std.math.inf(f32));
    setF32(&cpu, 3, 1.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 4)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fnmsub.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fnmsub_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 3.0);
    setF32(&cpu, 2, 4.0);
    setF32(&cpu, 3, 2.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // fnmsub: -(rs1*rs2) + rs3 = -(3*4) + 2 = -12 + 2 = -10
    try std.testing.expectEqual(@as(f32, -10.0), getF32(&cpu, 4));
}

test "jit f: fnmsub.s with NaN propagates NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fnmsub_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    setF32(&cpu, 2, 3.0);
    setF32(&cpu, 3, 4.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isNan(getF32(&cpu, 4)));
}

test "jit f: fnmsub.s inf * x - inf sets NV" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fnmsub_s = .{ .rd = 4, .rs1 = 1, .rs2 = 2, .rs3 = 3, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, std.math.inf(f32));
    setF32(&cpu, 2, 1.0);
    setF32(&cpu, 3, std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    // -(inf*1) + inf = -inf + inf = NaN
    try std.testing.expect(std.math.isNan(getF32(&cpu, 4)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fcvt.w.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 42.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 42), cpu.registers.get(2));
}

test "jit f: fcvt.w.s negative overflow returns min int and sets NV" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -3.0e10); // < INT32_MIN
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.minInt(i32), cpu.registers.get(2));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fcvt.w.s negative infinity returns min int" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.minInt(i32), cpu.registers.get(2));
}

test "jit f: fcvt.w.s with RTZ rounding positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 1 } }, // rm=1 → RTZ
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 2.9);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RTZ: 2.9 truncates toward zero → 2
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(2));
}

test "jit f: fcvt.w.s with RTZ rounding negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -2.9);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RTZ: -2.9 truncates toward zero → -2
    try std.testing.expectEqual(@as(i32, -2), cpu.registers.get(2));
}

test "jit f: fcvt.w.s with RDN rounding positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 2 } }, // rm=2 → RDN (toward -inf)
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 2.9);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RDN: 2.9 rounds down → 2
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(2));
}

test "jit f: fcvt.w.s with RDN rounding negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -2.1);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RDN: -2.1 rounds toward -inf → -3
    try std.testing.expectEqual(@as(i32, -3), cpu.registers.get(2));
}

test "jit f: fcvt.w.s with RUP rounding positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 3 } }, // rm=3 → RUP (toward +inf)
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 2.1);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RUP: 2.1 rounds toward +inf → 3
    try std.testing.expectEqual(@as(i32, 3), cpu.registers.get(2));
}

test "jit f: fcvt.w.s with RUP rounding negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 3 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -2.9);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RUP: -2.9 rounds toward +inf → -2
    try std.testing.expectEqual(@as(i32, -2), cpu.registers.get(2));
}

test "jit f: fcvt.w.s with RMM rounding" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 4 } }, // rm=4 → RMM (to nearest, ties to max magnitude)
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 2.5);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RMM: 2.5 ties to max magnitude → 3
    try std.testing.expectEqual(@as(i32, 3), cpu.registers.get(2));
}

test "jit f: fcvt.w.s with RMM negative tie" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 4 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -2.5);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RMM: -2.5 ties to max magnitude → -3
    try std.testing.expectEqual(@as(i32, -3), cpu.registers.get(2));
}

test "jit f: fcvt.w.s RNE tie 0.5 rounds to 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } }, // rm=0 → RNE
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 0.5);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RNE: 0.5 equidistant from 0 and 1, rounds to nearest even → 0
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "jit f: fcvt.w.s RNE tie 1.5 rounds to 2" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 1.5);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RNE: 1.5 equidistant from 1 and 2, rounds to nearest even → 2
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(2));
}

test "jit f: fcvt.w.s RNE tie 2.5 rounds to 2" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 2.5);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RNE: 2.5 equidistant from 2 and 3, rounds to nearest even → 2
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(2));
}

test "jit f: fcvt.w.s RNE tie 3.5 rounds to 4" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 3.5);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RNE: 3.5 equidistant from 3 and 4, rounds to nearest even → 4
    try std.testing.expectEqual(@as(i32, 4), cpu.registers.get(2));
}

test "jit f: fcvt.w.s RNE tie -1.5 rounds to -2" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -1.5);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RNE: -1.5 equidistant from -1 and -2, rounds to nearest even → -2
    try std.testing.expectEqual(@as(i32, -2), cpu.registers.get(2));
}

test "jit f: fcvt.w.s RNE tie -0.5 rounds to 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -0.5);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // RNE: -0.5 equidistant from 0 and -1, rounds to nearest even → 0
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "jit f: fcvt.w.s overflow sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 3.0e10); // > INT32_MAX
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.maxInt(i32), cpu.registers.get(2));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fcvt.w.s NaN sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.maxInt(i32), cpu.registers.get(2));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fcvt.w.s exact value does not set NX" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 100.0); // Exact integer value
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 100), cpu.registers.get(2));
    try std.testing.expect(!cpu.registers.fcsr.nx);
}

test "jit f: fcvt.w.s inexact value sets NX" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 1.5); // Inexact - will be rounded
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expect(cpu.registers.fcsr.nx);
}

test "jit f: fcvt.w.s positive infinity returns max int and sets NV" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.maxInt(i32), cpu.registers.get(2));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fcvt.wu.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_wu_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 100.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(u32, 100), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "jit f: fcvt.wu.s negative value returns 0 and sets NV" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_wu_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -1.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(u32, 0), @as(u32, @bitCast(cpu.registers.get(2))));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fcvt.wu.s overflow positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_wu_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 1.0e10); // > UINT32_MAX (4294967295)
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.maxInt(u32), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "jit f: fcvt.wu.s qNaN returns max uint" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_wu_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.maxInt(u32), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "jit f: fcvt.wu.s positive infinity returns max uint" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_wu_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.maxInt(u32), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "jit f: fcvt.wu.s negative infinity returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_wu_s = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(u32, 0), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "jit f: fcvt.s.w basic positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_s_w = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 123);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 123.0), getF32(&cpu, 2));
}

test "jit f: fcvt.s.w basic negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_s_w = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, -456);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, -456.0), getF32(&cpu, 2));
}

test "jit f: fcvt.s.w result is NaN-boxed" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_s_w = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 42);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    const raw = cpu.registers.float[2];
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), @as(u32, @truncate(raw >> 32)));
    try std.testing.expectEqual(@as(f32, 42.0), getF32(&cpu, 2));
}

test "jit f: fcvt.s.w zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_s_w = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 0.0), getF32(&cpu, 2));
    // Should be positive zero
    try std.testing.expect(!arch.FloatHelpers.isNegativeZeroF32(getF32(&cpu, 2)));
}

test "jit f: fcvt.s.w max int loses precision" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_s_w = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, std.math.maxInt(i32)); // 2147483647
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // f32 can't represent 2147483647 exactly; rounds to 2147483648.0
    const result = getF32(&cpu, 2);
    try std.testing.expectEqual(@as(f32, 2147483648.0), result);
}

test "jit f: fcvt.s.wu basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_s_wu = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 1000)));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 1000.0), getF32(&cpu, 2));
}

test "jit f: fcvt.s.wu max uint" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fcvt_s_wu = .{ .rd = 2, .rs1 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, std.math.maxInt(u32)))); // 4294967295
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // f32 can't represent exactly, rounds to 4294967296.0
    const result = getF32(&cpu, 2);
    try std.testing.expectEqual(@as(f32, 4294967296.0), result);
}

test "jit f: fmv.x.w basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmv_x_w = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 3.14);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    const expected_bits: u32 = @bitCast(@as(f32, 3.14));
    try std.testing.expectEqual(@as(i32, @bitCast(expected_bits)), cpu.registers.get(2));
}

test "jit f: fmv.x.w does not modify fcsr flags" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmv_x_w = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x7F800001))); // sNaN
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    // FMV.X.W is a bit move, should not signal
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags());
}

test "jit f: fmv.x.w with improper nan-boxing returns canonical NaN bits" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmv_x_w = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // Set improperly NaN-boxed value
    cpu.registers.float[1] = 0x00000000_3F800000; // Not properly boxed 1.0
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // Should return canonical NaN bits
    const expected: u32 = @bitCast(arch.FloatHelpers.canonicalNanF32());
    try std.testing.expectEqual(@as(i32, @bitCast(expected)), cpu.registers.get(2));
}

test "jit f: fmv.w.x basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmv_w_x = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    const bits: u32 = @bitCast(@as(f32, 1.5));
    cpu.registers.set(1, @bitCast(bits));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 1.5), getF32(&cpu, 2));
}

test "jit f: fmv.w.x does not modify fcsr flags" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmv_w_x = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x7F800001))); // sNaN bits
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    // FMV.W.X is a bit move, should not signal
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags());
}

test "jit f: fmv.w.x result is NaN-boxed" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fmv_w_x = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    const bits: u32 = @bitCast(@as(f32, 3.14));
    cpu.registers.set(1, @bitCast(bits));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // FMV.W.X must NaN-box the result
    const raw = cpu.registers.float[2];
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), @as(u32, @truncate(raw >> 32)));
    try std.testing.expectApproxEqRel(@as(f32, 3.14), getF32(&cpu, 2), 0.0001);
}

test "jit f: feq.s equal values returns 1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .feq_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 7.5);
    setF32(&cpu, 2, 7.5);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit f: feq.s different values returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .feq_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 3.0);
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "jit f: feq.s positive zero vs negative zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .feq_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @as(f32, 0.0));
    setF32(&cpu, 2, @bitCast(@as(u32, 0x80000000))); // -0.0
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // IEEE 754: +0 == -0
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit f: feq.s with qNaN does NOT set NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .feq_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
    // feq.s only signals NV for signaling NaN, NOT for quiet NaN
    try std.testing.expect(!cpu.registers.fcsr.nv);
}

test "jit f: feq.s with sNaN sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .feq_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // sNaN: exponent all 1s, fraction MSB = 0, fraction != 0
    setF32(&cpu, 1, @bitCast(@as(u32, 0x7F800001)));
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
    // feq.s signals NV for signaling NaN
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: flt.s less than returns 1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flt_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 3.0);
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit f: flt.s not less than" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flt_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    setF32(&cpu, 2, 3.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "jit f: flt.s equal values returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flt_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "jit f: flt.s negative zero vs positive zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flt_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x80000000))); // -0.0
    setF32(&cpu, 2, @as(f32, 0.0)); // +0.0
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // IEEE 754: -0 is NOT less than +0
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "jit f: flt.s with qNaN sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flt_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    setF32(&cpu, 2, arch.FloatHelpers.canonicalNanF32());
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
    // flt.s signals NV for any NaN operand (including qNaN)
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: flt.s with sNaN sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .flt_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    setF32(&cpu, 2, @bitCast(@as(u32, 0x7F800001))); // sNaN
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fle.s equal values returns 1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fle_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit f: fle.s strictly less than" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fle_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 3.0);
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit f: fle.s greater than returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fle_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 7.0);
    setF32(&cpu, 2, 3.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "jit f: fle.s negative zero vs positive zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fle_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x80000000))); // -0.0
    setF32(&cpu, 2, @as(f32, 0.0)); // +0.0
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // IEEE 754: -0 <= +0 is true (they are equal)
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "jit f: fle.s with qNaN sets NV flag" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fle_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    setF32(&cpu, 2, 5.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
    // fle.s signals NV for any NaN operand
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: fclass.s negative infinity" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fclass_s = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1 << 0), cpu.registers.get(2)); // bit 0
}

test "jit f: fclass.s negative normal" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fclass_s = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -1.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1 << 1), cpu.registers.get(2)); // bit 1
}

test "jit f: fclass.s negative subnormal" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fclass_s = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // Negative subnormal: sign=1, exponent=0, fraction!=0
    setF32(&cpu, 1, @bitCast(@as(u32, 0x80000001)));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1 << 2), cpu.registers.get(2)); // bit 2
}

test "jit f: fclass.s negative zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fclass_s = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x80000000))); // -0.0
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1 << 3), cpu.registers.get(2)); // bit 3
}

test "jit f: fclass.s positive zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fclass_s = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 0.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1 << 4), cpu.registers.get(2)); // bit 4
}

test "jit f: fclass.s positive subnormal" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fclass_s = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // Positive subnormal: sign=0, exponent=0, fraction!=0
    setF32(&cpu, 1, @bitCast(@as(u32, 0x00000001)));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1 << 5), cpu.registers.get(2)); // bit 5
}

test "jit f: fclass.s positive normal" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fclass_s = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 1.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1 << 6), cpu.registers.get(2)); // bit 6
}

test "jit f: fclass.s positive infinity" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fclass_s = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, std.math.inf(f32));
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1 << 7), cpu.registers.get(2)); // bit 7
}

test "jit f: fclass.s signaling NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fclass_s = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // sNaN: exponent all 1s, fraction MSB = 0, fraction != 0
    setF32(&cpu, 1, @bitCast(@as(u32, 0x7F800001)));
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1 << 8), cpu.registers.get(2)); // bit 8
    // FCLASS does NOT signal exceptions, even for sNaN
    try std.testing.expect(!cpu.registers.fcsr.nv);
}

test "jit f: fclass.s quiet NaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fclass_s = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, arch.FloatHelpers.canonicalNanF32());
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1 << 9), cpu.registers.get(2)); // bit 9
}

test "jit f: fclass.s does not modify fcsr flags" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fclass_s = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 1.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    // FCLASS should never set any exception flags
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags());
}

test "jit f: fsgnj.s does not modify fcsr flags with sNaN" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnj_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, @bitCast(@as(u32, 0x7F800001))); // sNaN
    setF32(&cpu, 2, -1.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    // Sign injection instructions should not signal exceptions
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags());
}

test "jit f: fsgnj.s basic positive to negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnj_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    setF32(&cpu, 2, -1.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, -5.0), getF32(&cpu, 3));
}

test "jit f: fsgnj.s basic negative to positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnj_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -5.0);
    setF32(&cpu, 2, 1.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 5.0), getF32(&cpu, 3));
}

test "jit f: fsgnj.s with improper nan-boxing rs1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnj_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // rs1 improperly boxed → canonical NaN (0x7FC00000)
    cpu.registers.float[1] = 0x00000000_40000000;
    setF32(&cpu, 2, -1.0); // rs2 negative → take negative sign
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // Result: canonical NaN magnitude with sign from rs2 (negative)
    // Canonical NaN = 0x7FC00000, with negative sign = 0xFFC00000
    const result_bits: u32 = @truncate(cpu.registers.float[3]);
    try std.testing.expectEqual(@as(u32, 0xFFC00000), result_bits);
}

test "jit f: fsgnj.s preserves NaN payload" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnj_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // qNaN with custom payload
    setF32(&cpu, 1, @bitCast(@as(u32, 0x7FC12345)));
    setF32(&cpu, 2, -1.0); // negative sign
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    const result: u32 = @truncate(cpu.registers.float[3]);
    // Sign should be negative, payload preserved
    try std.testing.expectEqual(@as(u32, 0xFFC12345), result);
}

test "jit f: fsgnj.s with improper nan-boxing rs2" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnj_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0); // properly boxed
    // Improperly boxed: upper bits not all 1s
    // Lower 32 bits = 0x80000000 = -0.0, sign bit = 1 (negative)
    // Implementation takes sign directly from lower 32 bits
    cpu.registers.float[2] = 0x00000000_80000000;
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // Result: magnitude from rs1 (5.0), sign from rs2 lower bits (negative)
    try std.testing.expectEqual(@as(f32, -5.0), getF32(&cpu, 3));
}

test "jit f: fsgnjn.s with improper nan-boxing rs1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnjn_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // rs1 improperly boxed → magnitude becomes canonical NaN (0x7FC00000)
    cpu.registers.float[1] = 0x00000000_40000000;
    setF32(&cpu, 2, -1.0); // negative → negated sign = positive
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // Result: canonical NaN magnitude with negated sign from rs2
    // rs2 is negative (sign=1), negated = 0 (positive)
    // Result = +canonical_NaN = 0x7FC00000
    const result_bits: u32 = @truncate(cpu.registers.float[3]);
    try std.testing.expectEqual(@as(u32, 0x7FC00000), result_bits);
}

test "jit f: fsgnjn.s with improper nan-boxing rs2" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnjn_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0); // properly boxed
    // rs2 improperly boxed, lower 32 bits = 0x3F800000 = +1.0, sign = 0
    // negated sign = 1 (negative)
    cpu.registers.float[2] = 0x00000000_3F800000;
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // Result: magnitude 5.0, negated sign of lower bits (0) = negative
    try std.testing.expectEqual(@as(f32, -5.0), getF32(&cpu, 3));
}

test "jit f: fsgnjn.s on infinity" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnjn_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, std.math.inf(f32)); // +inf
    setF32(&cpu, 2, -1.0); // negative → negate → positive sign
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expect(std.math.isPositiveInf(getF32(&cpu, 3)));
}

test "jit f: fsgnjn.s basic" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnjn_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    setF32(&cpu, 2, 1.0); // positive → negated = negative
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, -5.0), getF32(&cpu, 3));
}

test "jit f: fsgnjx.s both negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnjx_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -5.0);
    setF32(&cpu, 2, -3.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // XOR of two negative signs = positive
    try std.testing.expectEqual(@as(f32, 5.0), getF32(&cpu, 3));
}

test "jit f: fsgnjx.s mixed signs" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnjx_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0); // positive
    setF32(&cpu, 2, -3.0); // negative
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // XOR of positive and negative = negative
    try std.testing.expectEqual(@as(f32, -5.0), getF32(&cpu, 3));
}

test "jit f: fsgnjx.s with improper nan-boxing rs1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnjx_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // rs1 improperly boxed → getF32 returns canonical NaN (0x7FC00000, sign=0)
    cpu.registers.float[1] = 0x00000000_C0000000;
    setF32(&cpu, 2, -1.0); // sign = 1
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // getF32(rs1) = canonical NaN = 0x7FC00000 (sign bit = 0)
    // rs2 = -1.0 = 0xBF800000 (sign bit = 1)
    // XOR of signs: 0 XOR 1 = 1 (negative)
    // Result: canonical NaN magnitude with negative sign = 0xFFC00000
    const result_bits: u32 = @truncate(cpu.registers.float[3]);
    try std.testing.expectEqual(@as(u32, 0xFFC00000), result_bits);
}

test "jit f: fsgnjx.s with improper nan-boxing rs2" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fsgnjx_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, -5.0); // sign = 1
    // rs2 improperly boxed, lower 32 bits = 0xBF800000 = -1.0, sign = 1
    cpu.registers.float[2] = 0x00000000_BF800000;
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // XOR of signs: 1 XOR 1 = 0 (positive)
    try std.testing.expectEqual(@as(f32, 5.0), getF32(&cpu, 3));
}

test "jit f: fcsr flags are cumulative (sticky)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fdiv_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } }, // 5.0/0.0 → DZ
        .{ .fsqrt_s = .{ .rd = 4, .rs1 = 5, .rm = 0 } }, // sqrt(-1) → NV
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 5.0);
    setF32(&cpu, 2, 0.0);
    setF32(&cpu, 5, -1.0);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr = .{};

    try runToEbreak(&cpu);
    // Both flags should be set (cumulative)
    try std.testing.expect(cpu.registers.fcsr.dz);
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jit f: f0 is writable (not hardwired zero)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fadd_s = .{ .rd = 0, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 0, 0.0); // Clear f0
    setF32(&cpu, 1, 2.0);
    setF32(&cpu, 2, 3.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    // Unlike integer x0, floating-point f0 is a normal writable register
    try std.testing.expectEqual(@as(f32, 5.0), getF32(&cpu, 0));
}

test "jit f: f0 can be used as source" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fadd_s = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 0, 10.0);
    setF32(&cpu, 1, 5.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(f32, 15.0), getF32(&cpu, 3));
}

test "jit f: result is properly NaN-boxed in upper bits" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .fadd_s = .{ .rd = 3, .rs1 = 1, .rs2 = 2, .rm = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    setF32(&cpu, 1, 1.0);
    setF32(&cpu, 2, 2.0);
    cpu.registers.mstatus.fs = 0b01;

    try runToEbreak(&cpu);
    const raw = cpu.registers.float[3];
    // For a single-precision result, upper 32 bits must be all 1s (NaN-boxing)
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), @as(u32, @truncate(raw >> 32)));
    try std.testing.expectEqual(@as(f32, 3.0), getF32(&cpu, 3));
}

const CsrTestCpu = Cpu(.{ .runtime = .{ .enable_pmp = false } });

test "jit zicsr: csrrw read and write" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrw = .{ .rd = 1, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.mscratch) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mscratch = 0x12345678;
    cpu.registers.set(2, @bitCast(@as(u32, 0xDEADBEEF)));

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(1));
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), cpu.registers.mscratch);
}

test "jit zicsr: csrrw with rd=x0 (write only)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrw = .{ .rd = 0, .rs1 = 1, .csr = @intFromEnum(arch.Registers.Csr.mscratch) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mscratch = 0x12345678;
    cpu.registers.set(1, @bitCast(@as(u32, 0xAABBCCDD)));

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(u32, 0xAABBCCDD), cpu.registers.mscratch);
}

test "jit zicsr: csrrs set bits" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.mscratch) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mscratch = 0x0F0F0F0F;
    cpu.registers.set(2, @bitCast(@as(u32, 0xF0F0F0F0)));

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x0F0F0F0F), cpu.registers.get(1)); // old value
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), cpu.registers.mscratch); // set bits
}

test "jit zicsr: csrrs with rs1=x0 (read only)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.mscratch) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mscratch = 0x12345678;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(1));
    try std.testing.expectEqual(@as(u32, 0x12345678), cpu.registers.mscratch); // unchanged
}

test "jit zicsr: csrrc clear bits" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrc = .{ .rd = 1, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.mscratch) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mscratch = 0xFFFFFFFF;
    cpu.registers.set(2, 0x0F0F0F0F);

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFFFFF))), cpu.registers.get(1));
    try std.testing.expectEqual(@as(u32, 0xF0F0F0F0), cpu.registers.mscratch);
}

test "jit zicsr: csrrwi with immediate" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrwi = .{ .rd = 1, .uimm = 0x1F, .csr = @intFromEnum(arch.Registers.Csr.mscratch) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mscratch = 0x12345678;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(1));
    try std.testing.expectEqual(@as(u32, 0x1F), cpu.registers.mscratch);
}

test "jit zicsr: csrrsi set bits with immediate" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrsi = .{ .rd = 1, .uimm = 0x15, .csr = @intFromEnum(arch.Registers.Csr.mscratch) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mscratch = 0x0A;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x0A), cpu.registers.get(1));
    try std.testing.expectEqual(@as(u32, 0x1F), cpu.registers.mscratch);
}

test "jit zicsr: csrrci clear bits with immediate" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrci = .{ .rd = 1, .uimm = 0x0F, .csr = @intFromEnum(arch.Registers.Csr.mscratch) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mscratch = 0xFF;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0xFF), cpu.registers.get(1));
    try std.testing.expectEqual(@as(u32, 0xF0), cpu.registers.mscratch);
}

test "jit zicsr: read mstatus" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.mstatus) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mstatus.mie = true;
    cpu.registers.mstatus.mpie = true;

    try runToEbreak(&cpu);
    const mstatus_val: u32 = @bitCast(cpu.registers.mstatus);
    try std.testing.expectEqual(@as(i32, @bitCast(mstatus_val)), cpu.registers.get(1));
}

test "jit zicsr: write mtvec" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrw = .{ .rd = 0, .rs1 = 1, .csr = @intFromEnum(arch.Registers.Csr.mtvec) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x80001000)));

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(u30, 0x80001000 >> 2), cpu.registers.mtvec.base);
}

test "jit zicsr: read mepc" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.mepc) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mepc = 0xDEADBEE0;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xDEADBEE0))), cpu.registers.get(1));
}

test "jit zicsr: write mepc aligns to 4 bytes" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrw = .{ .rd = 0, .rs1 = 1, .csr = @intFromEnum(arch.Registers.Csr.mepc) } },
        .{ .csrrs = .{ .rd = 2, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.mepc) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345677); // misaligned

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(u32, 0x12345674), cpu.registers.mepc); // aligned
    try std.testing.expectEqual(@as(i32, 0x12345674), cpu.registers.get(2));
}

test "jit zicsr: read mcause" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.mcause) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mcause = arch.Registers.Mcause.fromException(.illegal_instruction);

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(1));
}

test "jit zicsr: read misa" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.misa) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(arch.Registers.MISA_VALUE)), cpu.registers.get(1));
}

test "jit zicsr: fcsr read/write" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrw = .{ .rd = 1, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.fcsr) } },
        .{ .csrrs = .{ .rd = 3, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.fcsr) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.fcsr.nv = true; // bit 4
    cpu.registers.fcsr.frm = .rtz; // bits 7:5 = 001
    // Old fcsr = (001 << 5) | (1 << 4) = 0x20 | 0x10 = 0x30
    cpu.registers.set(2, 0x45); // frm=010, flags=00101

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x30), cpu.registers.get(1));
    try std.testing.expectEqual(@as(i32, 0x45), cpu.registers.get(3));
}

test "jit zicsr: fflags read/write" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrw = .{ .rd = 1, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.fflags) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.fcsr.nx = true;
    cpu.registers.fcsr.of = true;
    cpu.registers.set(2, 0x1F); // all flags

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x05), cpu.registers.get(1)); // nx | of
    try std.testing.expect(cpu.registers.fcsr.nv);
    try std.testing.expect(cpu.registers.fcsr.dz);
    try std.testing.expect(cpu.registers.fcsr.of);
    try std.testing.expect(cpu.registers.fcsr.uf);
    try std.testing.expect(cpu.registers.fcsr.nx);
}

test "jit zicsr: frm read/write" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrw = .{ .rd = 1, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.frm) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.fcsr.frm = .rne;
    cpu.registers.set(2, 0x03); // rdn

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x00), cpu.registers.get(1));
    try std.testing.expectEqual(arch.Registers.Fcsr.RoundingMode.rup, cpu.registers.fcsr.frm);
}

test "jit zicsr: user mode cannot access machine CSR" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.mscratch) } },
        .ebreak,
    });
    var cpu = try CsrTestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;

    const result = try cpu.run(std.math.maxInt(u64));
    try std.testing.expectEqual(EngineConfig.State.trap, result);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, cpu.registers.mcause.toException());
}

test "jit zicsr: write to read-only CSR traps" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrw = .{ .rd = 0, .rs1 = 1, .csr = @intFromEnum(arch.Registers.Csr.mvendorid) } },
        .ebreak,
    });
    var cpu = try CsrTestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);

    const result = try cpu.run(std.math.maxInt(u64));
    try std.testing.expectEqual(EngineConfig.State.trap, result);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, cpu.registers.mcause.toException());
}

test "jit zicsr: read mvendorid" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.mvendorid) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(cpu.registers.mvendorid)), cpu.registers.get(1));
}

test "jit zicsr: read mhartid" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.mhartid) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
}

test "zbb clz: basic value" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .clz = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x00100000); // bit 20 set
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 11), cpu.registers.get(2));
}

test "zbb clz: all zeros returns 32" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .clz = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 32), cpu.registers.get(2));
}

test "zbb clz: msb set returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .clz = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x80000000)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "zbb clz: all ones returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .clz = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFFFFFF)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "zbb clz: single lsb set returns 31" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .clz = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 1);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 31), cpu.registers.get(2));
}

test "zbb clz: rd equals rs1 (self-overwrite)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .clz = .{ .rd = 1, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x00010000); // bit 16 set, clz = 15
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 15), cpu.registers.get(1));
}

test "zbb ctz: basic value" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .ctz = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x00100000); // bit 20 set
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 20), cpu.registers.get(2));
}

test "zbb ctz: all zeros returns 32" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .ctz = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 32), cpu.registers.get(2));
}

test "zbb ctz: lsb set returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .ctz = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 1);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "zbb ctz: only msb set returns 31" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .ctz = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x80000000)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 31), cpu.registers.get(2));
}

test "zbb ctz: all ones returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .ctz = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFFFFFF)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "zbb ctz: alternating bits starting with 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .ctz = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xAAAAAAAA))); // 10101010...
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(2));
}

test "zbb cpop: basic value 0x12345678" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .cpop = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 13), cpu.registers.get(2));
}

test "zbb cpop: all ones returns 32" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .cpop = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFFFFFF)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 32), cpu.registers.get(2));
}

test "zbb cpop: zero returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .cpop = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "zbb cpop: single bit returns 1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .cpop = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x00008000);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(2));
}

test "zbb cpop: alternating bits returns 16" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .cpop = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xAAAAAAAA)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 16), cpu.registers.get(2));
}

test "zbb cpop: 0x55555555 returns 16" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .cpop = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x55555555);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 16), cpu.registers.get(2));
}

test "zbb andn: basic case" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .andn = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFF0000)));
    cpu.registers.set(2, @bitCast(@as(u32, 0xFF00FF00)));
    try runToEbreak(&cpu);
    // rs1 AND NOT(rs2) = 0xFFFF0000 AND 0x00FF00FF = 0x00FF0000
    try std.testing.expectEqual(@as(i32, 0x00FF0000), cpu.registers.get(3));
}

test "zbb andn: rs2 zero returns rs1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .andn = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, 0);
    try runToEbreak(&cpu);
    // rs1 AND NOT(0) = rs1 AND 0xFFFFFFFF = rs1
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(3));
}

test "zbb andn: rs2 all ones returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .andn = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, @bitCast(@as(u32, 0xFFFFFFFF)));
    try runToEbreak(&cpu);
    // rs1 AND NOT(0xFFFFFFFF) = rs1 AND 0 = 0
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "zbb andn: rs1 equals rs2 returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .andn = .{ .rd = 3, .rs1 = 1, .rs2 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    try runToEbreak(&cpu);
    // rs1 AND NOT(rs1) = 0
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "zbb orn: basic case" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .orn = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x0F0F0F0F);
    cpu.registers.set(2, @bitCast(@as(u32, 0xFF00FF00)));
    try runToEbreak(&cpu);
    // rs1 OR NOT(rs2) = 0x0F0F0F0F OR 0x00FF00FF = 0x0FFF0FFF
    try std.testing.expectEqual(@as(i32, 0x0FFF0FFF), cpu.registers.get(3));
}

test "zbb orn: rs2 zero returns all ones" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .orn = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, 0);
    try runToEbreak(&cpu);
    // rs1 OR NOT(0) = rs1 OR 0xFFFFFFFF = 0xFFFFFFFF
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFFFFF))), cpu.registers.get(3));
}

test "zbb orn: rs2 all ones returns rs1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .orn = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, @bitCast(@as(u32, 0xFFFFFFFF)));
    try runToEbreak(&cpu);
    // rs1 OR NOT(0xFFFFFFFF) = rs1 OR 0 = rs1
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(3));
}

test "zbb orn: rs1 equals rs2 returns all ones" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .orn = .{ .rd = 3, .rs1 = 1, .rs2 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    try runToEbreak(&cpu);
    // rs1 OR NOT(rs1) = 0xFFFFFFFF
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFFFFF))), cpu.registers.get(3));
}

test "zbb xnor: opposite bits returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .xnor = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xAAAAAAAA)));
    cpu.registers.set(2, @bitCast(@as(u32, 0x55555555)));
    try runToEbreak(&cpu);
    // NOT(0xAAAAAAAA XOR 0x55555555) = NOT(0xFFFFFFFF) = 0
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "zbb xnor: same values returns all ones" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .xnor = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, 0x12345678);
    try runToEbreak(&cpu);
    // NOT(rs1 XOR rs1) = NOT(0) = 0xFFFFFFFF
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFFFFF))), cpu.registers.get(3));
}

test "zbb xnor: rs1 zero rs2 all ones returns 0" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .xnor = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0);
    cpu.registers.set(2, @bitCast(@as(u32, 0xFFFFFFFF)));
    try runToEbreak(&cpu);
    // NOT(0 XOR 0xFFFFFFFF) = NOT(0xFFFFFFFF) = 0
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "zbb xnor: both zero returns all ones" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .xnor = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0);
    cpu.registers.set(2, 0);
    try runToEbreak(&cpu);
    // NOT(0 XOR 0) = NOT(0) = 0xFFFFFFFF
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFFFFF))), cpu.registers.get(3));
}

test "zbb max: both positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .max = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 100);
    cpu.registers.set(2, 200);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 200), cpu.registers.get(3));
}

test "zbb max: both negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .max = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, -100);
    cpu.registers.set(2, -50);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -50), cpu.registers.get(3));
}

test "zbb max: mixed signs" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .max = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, -10);
    cpu.registers.set(2, 5);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 5), cpu.registers.get(3));
}

test "zbb max: equal values" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .max = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 42);
    cpu.registers.set(2, 42);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 42), cpu.registers.get(3));
}

test "zbb max: INT_MIN vs INT_MAX" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .max = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, std.math.minInt(i32));
    cpu.registers.set(2, std.math.maxInt(i32));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.maxInt(i32), cpu.registers.get(3));
}

test "zbb max: INT_MIN vs zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .max = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, std.math.minInt(i32));
    cpu.registers.set(2, 0);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "zbb maxu: basic unsigned comparison" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .maxu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 100);
    cpu.registers.set(2, 200);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 200), cpu.registers.get(3));
}

test "zbb maxu: -1 vs positive (unsigned -1 is max)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .maxu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, -1); // 0xFFFFFFFF unsigned
    cpu.registers.set(2, 5);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(3));
}

test "zbb maxu: equal values" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .maxu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x80000000)));
    cpu.registers.set(2, @bitCast(@as(u32, 0x80000000)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x80000000))), cpu.registers.get(3));
}

test "zbb maxu: zero vs large unsigned" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .maxu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0);
    cpu.registers.set(2, @bitCast(@as(u32, 0xFFFFFFFE)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFFFFE))), cpu.registers.get(3));
}

test "zbb min: both positive" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .min = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 100);
    cpu.registers.set(2, 200);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 100), cpu.registers.get(3));
}

test "zbb min: both negative" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .min = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, -100);
    cpu.registers.set(2, -50);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -100), cpu.registers.get(3));
}

test "zbb min: mixed signs" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .min = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, -10);
    cpu.registers.set(2, 5);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -10), cpu.registers.get(3));
}

test "zbb min: equal values" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .min = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, -42);
    cpu.registers.set(2, -42);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -42), cpu.registers.get(3));
}

test "zbb min: INT_MIN vs INT_MAX" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .min = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, std.math.minInt(i32));
    cpu.registers.set(2, std.math.maxInt(i32));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(std.math.minInt(i32), cpu.registers.get(3));
}

test "zbb minu: basic unsigned comparison" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .minu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 100);
    cpu.registers.set(2, 200);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 100), cpu.registers.get(3));
}

test "zbb minu: -1 vs positive (positive is smaller)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .minu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, -1); // 0xFFFFFFFF unsigned
    cpu.registers.set(2, 5);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 5), cpu.registers.get(3));
}

test "zbb minu: equal values" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .minu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x80000000)));
    cpu.registers.set(2, @bitCast(@as(u32, 0x80000000)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x80000000))), cpu.registers.get(3));
}

test "zbb minu: zero is minimum" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .minu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0);
    cpu.registers.set(2, @bitCast(@as(u32, 0xFFFFFFFF)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "zbb sext.b: positive byte (0x7F)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sext_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x1234567F);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 127), cpu.registers.get(2));
}

test "zbb sext.b: positive byte extracted from larger value" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sext_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x78), cpu.registers.get(2));
}

test "zbb sext.b: negative byte 0xFF becomes -1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sext_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x123456FF);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(2));
}

test "zbb sext.b: 0x80 becomes -128" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sext_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x00000080);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -128), cpu.registers.get(2));
}

test "zbb sext.b: zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sext_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFFFF00)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "zbb sext.h: positive halfword (0x7FFF)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sext_h = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12347FFF);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 32767), cpu.registers.get(2));
}

test "zbb sext.h: positive halfword extracted" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sext_h = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x5678), cpu.registers.get(2));
}

test "zbb sext.h: 0xFFFF becomes -1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sext_h = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x1234FFFF);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(2));
}

test "zbb sext.h: 0x8000 becomes -32768" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sext_h = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x00008000);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, -32768), cpu.registers.get(2));
}

test "zbb sext.h: zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sext_h = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFF0000)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "zbb zext.h: clears upper bits" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .zext_h = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFFFFFF)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0xFFFF), cpu.registers.get(2));
}

test "zbb zext.h: preserves lower halfword" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .zext_h = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x5678), cpu.registers.get(2));
}

test "zbb zext.h: zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .zext_h = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFF0000)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "zbb zext.h: max halfword value" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .zext_h = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x0000FFFF);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0xFFFF), cpu.registers.get(2));
}

test "zbb rol: basic rotation by 4" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rol = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x80000001)));
    cpu.registers.set(2, 4);
    try runToEbreak(&cpu);
    // 0x80000001 rotated left 4 = 0x00000018
    try std.testing.expectEqual(@as(i32, 0x00000018), cpu.registers.get(3));
}

test "zbb rol: by 0 unchanged" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rol = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, 0);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(3));
}

test "zbb rol: by 32 unchanged (wraps)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rol = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, 32);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(3));
}

test "zbb rol: by 31" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rol = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 1);
    cpu.registers.set(2, 31);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x80000000))), cpu.registers.get(3));
}

test "zbb rol: large shift uses only lower 5 bits" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rol = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, 36); // 36 & 31 = 4
    try runToEbreak(&cpu);
    // Same as rotating by 4
    try std.testing.expectEqual(@as(i32, 0x23456781), cpu.registers.get(3));
}

test "zbb ror: basic rotation by 4" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .ror = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x80000001)));
    cpu.registers.set(2, 4);
    try runToEbreak(&cpu);
    // 0x80000001 rotated right 4 = 0x18000000
    try std.testing.expectEqual(@as(i32, 0x18000000), cpu.registers.get(3));
}

test "zbb ror: by 0 unchanged" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .ror = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, 0);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(3));
}

test "zbb ror: by 32 unchanged (wraps)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .ror = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, 32);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(3));
}

test "zbb ror: by 31" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .ror = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x80000000)));
    cpu.registers.set(2, 31);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "zbb rori: basic rotation by 8" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rori = .{ .rd = 2, .rs1 = 1, .shamt = 8 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x78123456), cpu.registers.get(2));
}

test "zbb rori: by 0 unchanged" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rori = .{ .rd = 2, .rs1 = 1, .shamt = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(2));
}

test "zbb rori: by 31" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rori = .{ .rd = 2, .rs1 = 1, .shamt = 31 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x80000000)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(2));
}

test "zbb rori: by 16" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rori = .{ .rd = 2, .rs1 = 1, .shamt = 16 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x56781234), cpu.registers.get(2));
}

test "zbb rev8: basic byte swap" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rev8 = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x78563412), cpu.registers.get(2));
}

test "zbb rev8: all same bytes unchanged" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rev8 = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xAAAAAAAA)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xAAAAAAAA))), cpu.registers.get(2));
}

test "zbb rev8: zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rev8 = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "zbb rev8: all ones" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rev8 = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFFFFFF)));
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFFFFF))), cpu.registers.get(2));
}

test "zbb rev8: double reversal returns original" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .rev8 = .{ .rd = 2, .rs1 = 1 } },
        .{ .rev8 = .{ .rd = 3, .rs1 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x12345678);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(3));
}

test "zbb orc.b: all bytes non-zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .orc_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x01020304);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFFFFF))), cpu.registers.get(2));
}

test "zbb orc.b: all bytes zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .orc_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "zbb orc.b: only byte 0 non-zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .orc_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x00000001);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x000000FF), cpu.registers.get(2));
}

test "zbb orc.b: only byte 1 non-zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .orc_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x00000100);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x0000FF00), cpu.registers.get(2));
}

test "zbb orc.b: only byte 2 non-zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .orc_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x00010000);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x00FF0000), cpu.registers.get(2));
}

test "zbb orc.b: only byte 3 non-zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .orc_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x01000000);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFF000000))), cpu.registers.get(2));
}

test "zbb orc.b: mixed zero and non-zero bytes" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .orc_b = .{ .rd = 2, .rs1 = 1 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x01000001);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFF0000FF))), cpu.registers.get(2));
}

test "zba sh1add: basic case" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh1add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 10);
    cpu.registers.set(2, 100);
    try runToEbreak(&cpu);
    // (10 << 1) + 100 = 20 + 100 = 120
    try std.testing.expectEqual(@as(i32, 120), cpu.registers.get(3));
}

test "zba sh1add: rs1 zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh1add = .{ .rd = 3, .rs1 = 0, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(2, 0x12345678);
    try runToEbreak(&cpu);
    // (0 << 1) + rs2 = rs2
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(3));
}

test "zba sh1add: rs2 zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh1add = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 16);
    try runToEbreak(&cpu);
    // (16 << 1) + 0 = 32
    try std.testing.expectEqual(@as(i32, 32), cpu.registers.get(3));
}

test "zba sh1add: overflow wraps" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh1add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x80000000)));
    cpu.registers.set(2, 1);
    try runToEbreak(&cpu);
    // (0x80000000 << 1) + 1 = 0 + 1 = 1
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "zba sh1add: negative rs1" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh1add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, -5);
    cpu.registers.set(2, 100);
    try runToEbreak(&cpu);
    // (-5 << 1) + 100 = -10 + 100 = 90
    try std.testing.expectEqual(@as(i32, 90), cpu.registers.get(3));
}

test "zba sh1add: array indexing i16" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh1add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    const base_addr = 0x1000;
    const index = 7;
    cpu.registers.set(1, index);
    cpu.registers.set(2, base_addr);
    try runToEbreak(&cpu);
    // address = base + index * 2
    try std.testing.expectEqual(@as(i32, base_addr + index * 2), cpu.registers.get(3));
}

test "zba sh2add: basic case" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh2add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 10);
    cpu.registers.set(2, 100);
    try runToEbreak(&cpu);
    // (10 << 2) + 100 = 40 + 100 = 140
    try std.testing.expectEqual(@as(i32, 140), cpu.registers.get(3));
}

test "zba sh2add: rs1 zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh2add = .{ .rd = 3, .rs1 = 0, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(2, 0x12345678);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(3));
}

test "zba sh2add: rs2 zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh2add = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 16);
    try runToEbreak(&cpu);
    // (16 << 2) + 0 = 64
    try std.testing.expectEqual(@as(i32, 64), cpu.registers.get(3));
}

test "zba sh2add: array indexing i32" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh2add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    const base_addr = 0x1000;
    const index = 5;
    cpu.registers.set(1, index);
    cpu.registers.set(2, base_addr);
    try runToEbreak(&cpu);
    // address = base + index * 4
    try std.testing.expectEqual(@as(i32, base_addr + index * 4), cpu.registers.get(3));
}

test "zba sh2add: overflow wraps" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh2add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x40000000)));
    cpu.registers.set(2, 1);
    try runToEbreak(&cpu);
    // (0x40000000 << 2) + 1 = 0 + 1 = 1
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "zba sh2add: negative index" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh2add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, -2);
    cpu.registers.set(2, 100);
    try runToEbreak(&cpu);
    // (-2 << 2) + 100 = -8 + 100 = 92
    try std.testing.expectEqual(@as(i32, 92), cpu.registers.get(3));
}

test "zba sh3add: basic case" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh3add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 10);
    cpu.registers.set(2, 100);
    try runToEbreak(&cpu);
    // (10 << 3) + 100 = 80 + 100 = 180
    try std.testing.expectEqual(@as(i32, 180), cpu.registers.get(3));
}

test "zba sh3add: rs1 zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh3add = .{ .rd = 3, .rs1 = 0, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(2, 0x12345678);
    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(3));
}

test "zba sh3add: rs2 zero" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh3add = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 16);
    try runToEbreak(&cpu);
    // (16 << 3) + 0 = 128
    try std.testing.expectEqual(@as(i32, 128), cpu.registers.get(3));
}

test "zba sh3add: array indexing i64/double" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh3add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    const base_addr = 0x2000;
    const index = 3;
    cpu.registers.set(1, index);
    cpu.registers.set(2, base_addr);
    try runToEbreak(&cpu);
    // address = base + index * 8
    try std.testing.expectEqual(@as(i32, base_addr + index * 8), cpu.registers.get(3));
}

test "zba sh3add: overflow wraps" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh3add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, @bitCast(@as(u32, 0x20000000)));
    cpu.registers.set(2, 1);
    try runToEbreak(&cpu);
    // (0x20000000 << 3) + 1 = 0 + 1 = 1
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "zba sh3add: negative index" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh3add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, -1);
    cpu.registers.set(2, 100);
    try runToEbreak(&cpu);
    // (-1 << 3) + 100 = -8 + 100 = 92
    try std.testing.expectEqual(@as(i32, 92), cpu.registers.get(3));
}

test "zba sh3add: large values" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .sh3add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.set(1, 0x10000000);
    cpu.registers.set(2, @bitCast(@as(u32, 0x80000000)));
    try runToEbreak(&cpu);
    // (0x10000000 << 3) + 0x80000000 = 0x80000000 + 0x80000000 = 0 (overflow)
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3));
}

test "jit zicntr: read cycle" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.cycle) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.cycle = 0x123456789ABCDEF0;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x9ABCDEF1))), cpu.registers.get(1));
}

test "jit zicntr: read cycleh" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.cycleh) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.cycle = 0x123456789ABCDEF0;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(1));
}

test "jit zicntr: read time" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.time) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mtime = 2000;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 2001), cpu.registers.get(1));
}

test "jit zicntr: read timeh" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.timeh) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.mtime = 0xFEDCBA9876543210;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFEDCBA98))), cpu.registers.get(1));
}

test "jit zicntr: read instret" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.instret) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.instret = 5000;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 5001), cpu.registers.get(1));
}

test "jit zicntr: read instreth" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.instreth) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.instret = 0xAABBCCDDEEFF0011;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xAABBCCDD))), cpu.registers.get(1));
}

test "jit zicntr: mcycle write low" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrw = .{ .rd = 0, .rs1 = 1, .csr = @intFromEnum(arch.Registers.Csr.mcycle) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // Use a high word that won't be affected, and low word that won't overflow
    cpu.registers.cycle = 0x1111111100000000;
    cpu.registers.set(1, 0x12345678);

    try runToEbreak(&cpu);
    // Pre-increment: cycle = 0x11111111_00000001
    // Write low: cycle = 0x11111111_12345678
    // EBREAK pre-increment: cycle = 0x11111111_12345679
    try std.testing.expectEqual(@as(u64, 0x1111111112345679), cpu.registers.cycle);
}

test "jit zicntr: mcycleh write high" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrw = .{ .rd = 0, .rs1 = 1, .csr = @intFromEnum(arch.Registers.Csr.mcycleh) } },
        .ebreak,
    });
    var cpu = try TestCpu.init(allocator, &ram);
    defer cpu.deinit();

    // Start at 0 so low word won't overflow
    cpu.registers.cycle = 0;
    cpu.registers.set(1, @bitCast(@as(u32, 0xDEADBEEF)));

    try runToEbreak(&cpu);
    // Pre-increment: cycle = 1
    // Write high: cycle = 0xDEADBEEF_00000001
    // EBREAK pre-increment: cycle = 0xDEADBEEF_00000002
    try std.testing.expectEqual(@as(u64, 0xDEADBEEF00000002), cpu.registers.cycle);
}

test "jit zicntr: user mode can read cycle when enabled" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.cycle) } },
        .ebreak,
    });
    var cpu = try CsrTestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.mcounteren.cy = true;
    cpu.registers.cycle = 12345;

    try runToEbreak(&cpu);
    // +1 for the CSRRS instruction itself
    try std.testing.expectEqual(@as(i32, 12346), cpu.registers.get(1));
}

test "jit zicntr: user mode cannot read cycle when disabled" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.cycle) } },
        .ebreak,
    });
    var cpu = try CsrTestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.mcounteren.cy = false;
    cpu.registers.cycle = 12345;

    const result = try cpu.run(std.math.maxInt(u64));
    try std.testing.expectEqual(EngineConfig.State.trap, result);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, cpu.registers.mcause.toException());
}

test "jit zicntr: user mode can read time when enabled" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.time) } },
        .ebreak,
    });
    var cpu = try CsrTestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.mcounteren.tm = true;
    cpu.registers.mtime = 67890;

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 67891), cpu.registers.get(1));
}

test "jit zicntr: user mode cannot read instret when disabled" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(512, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.instret) } },
        .ebreak,
    });
    var cpu = try CsrTestCpu.init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.mcounteren.ir = false;

    const result = try cpu.run(std.math.maxInt(u64));
    try std.testing.expectEqual(EngineConfig.State.trap, result);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, cpu.registers.mcause.toException());
}

fn runAndExpectTrap(cpu: anytype) !void {
    const result = try cpu.run(std.math.maxInt(u64));

    try std.testing.expectEqual(EngineConfig.State.trap, result);
}

/// NAPOT region calculation helper.
/// Returns pmpaddr value for a NAPOT region of given size at given base.
/// Size must be power of 2 and >= 8.
inline fn napotAddr(base: u32, size: u32) u32 {
    std.debug.assert(size >= 8 and @popCount(size) == 1);

    return (base >> 2) | ((size >> 3) - 1);
}

/// Configure PMP to allow full RWX access for U-mode to RAM region [0, size)
inline fn configurePmpFullAccess(cpu: anytype, size: u32) void {
    setPmpEntry(cpu, 0, napotAddr(0, size), .{ .r = true, .w = true, .x = true, .a = .napot });
}

inline fn configurePmpForCodeRegion(cpu: anytype, entry: u5) void {
    // Code region 0x000-0x100 (256 bytes), RX
    cpu.registers.pmpaddr[entry] = 0x1F;

    const cfg = arch.Registers.PmpCfg{
        .r = true,
        .w = false,
        .x = true,
        .a = .napot,
    };

    const cfg_reg = entry / 4;
    const byte_pos = @as(u5, @intCast((entry % 4) * 8));
    cpu.registers.pmpcfg[cfg_reg] = (cpu.registers.pmpcfg[cfg_reg] & ~(@as(u32, 0xFF) << byte_pos)) |
        (@as(u32, @as(u8, @bitCast(cfg))) << byte_pos);
}

inline fn setPmpEntry(cpu: anytype, entry: u5, addr: u32, cfg: arch.Registers.PmpCfg) void {
    cpu.registers.pmpaddr[entry] = addr;

    const cfg_reg = entry / 4;
    const byte_pos = @as(u5, @intCast((entry % 4) * 8));
    cpu.registers.pmpcfg[cfg_reg] = (cpu.registers.pmpcfg[cfg_reg] & ~(@as(u32, 0xFF) << byte_pos)) |
        (@as(u32, @as(u8, @bitCast(cfg))) << byte_pos);
}

test "jit pmp: denies U-mode access to unprotected memory" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x200);

    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{
        .r = true,
        .w = true,
        .x = true,
        .a = .napot,
    });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(false, cpu.registers.mcause.interrupt);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_access_fault, cpu.registers.mcause.toException());
}

test "jit pmp: allows M-mode access without configuration" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });
    std.mem.writeInt(u32, ram[0x100..0x104], 0xDEADBEEF, arch.ENDIAN);

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .machine;
    cpu.registers.set(2, 0x100);

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xDEADBEEF))), cpu.registers.get(1));
}

test "jit pmp: NAPOT mode allows access within range" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });
    std.mem.writeInt(u32, ram[0x100..0x104], 0x12345678, arch.ENDIAN);

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x100);

    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = true, .x = true, .a = .napot });

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(1));
}

test "jit pmp: denies access outside configured range" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x200);

    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = true, .x = true, .a = .napot });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_access_fault, cpu.registers.mcause.toException());
}

test "jit pmp: TOR mode allows access within range" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });
    std.mem.writeInt(u32, ram[0x80..0x84], 0xCAFEBABE, arch.ENDIAN);

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x80);

    // TOR: region [0, 0x200)
    setPmpEntry(&cpu, 0, 0x200 >> 2, .{ .r = true, .w = true, .x = true, .a = .tor });

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xCAFEBABE))), cpu.registers.get(1));
}

test "jit pmp: TOR mode denies access outside range" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x200);

    setPmpEntry(&cpu, 0, 0x200 >> 2, .{ .r = true, .w = true, .x = true, .a = .tor });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_access_fault, cpu.registers.mcause.toException());
}

test "jit pmp: TOR with non-zero base" {
    const allocator = std.testing.allocator;

    // Test 1: Load from 0x100 (in second TOR region)
    var ram1 = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });
    std.mem.writeInt(u32, ram1[0x100..0x104], 0x11111111, arch.ENDIAN);

    var cpu1 = try Cpu(.{}).init(allocator, &ram1);
    defer cpu1.deinit();

    cpu1.registers.privilege = .user;
    cpu1.registers.set(2, 0x100);

    // PMP0: TOR [0, 0x100) - code region with RWX
    setPmpEntry(&cpu1, 0, 0x100 >> 2, .{ .r = true, .w = true, .x = true, .a = .tor });
    // PMP1: TOR [0x100, 0x200) - data region with RW (no X)
    setPmpEntry(&cpu1, 1, 0x200 >> 2, .{ .r = true, .w = true, .x = false, .a = .tor });

    try runToEbreak(&cpu1);
    try std.testing.expectEqual(@as(i32, 0x11111111), cpu1.registers.get(1));

    // Test 2: Load from 0x80 (in first TOR region)
    var ram2 = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });
    std.mem.writeInt(u32, ram2[0x80..0x84], 0x22222222, arch.ENDIAN);

    var cpu2 = try Cpu(.{}).init(allocator, &ram2);
    defer cpu2.deinit();

    cpu2.registers.privilege = .user;
    cpu2.registers.set(2, 0x80);

    setPmpEntry(&cpu2, 0, 0x100 >> 2, .{ .r = true, .w = true, .x = true, .a = .tor });
    setPmpEntry(&cpu2, 1, 0x200 >> 2, .{ .r = true, .w = true, .x = false, .a = .tor });

    try runToEbreak(&cpu2);
    try std.testing.expectEqual(@as(i32, 0x22222222), cpu2.registers.get(1));
}

test "jit pmp: NA4 mode protects exactly 4 bytes" {
    const allocator = std.testing.allocator;

    // Test that NA4 region is accessible
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });
    std.mem.writeInt(u32, ram[0x100..0x104], 0x11111111, arch.ENDIAN);

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x100);

    // PMP0: NAPOT for code [0, 0x100)
    setPmpEntry(&cpu, 0, napotAddr(0, 256), .{ .r = true, .w = false, .x = true, .a = .napot });
    // PMP1: NA4 at exactly 0x100
    setPmpEntry(&cpu, 1, 0x100 >> 2, .{ .r = true, .w = false, .x = false, .a = .na4 });

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x11111111), cpu.registers.get(1));
}

test "jit pmp: NA4 denies access at adjacent address" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x104); // Adjacent to NA4 region, not covered

    // PMP0: NAPOT for code [0, 0x100)
    setPmpEntry(&cpu, 0, napotAddr(0, 256), .{ .r = true, .w = false, .x = true, .a = .napot });
    // PMP1: NA4 at exactly 0x100 (only covers 0x100-0x103)
    setPmpEntry(&cpu, 1, 0x100 >> 2, .{ .r = true, .w = false, .x = false, .a = .na4 });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_access_fault, cpu.registers.mcause.toException());
}

test "jit pmp: execute permission checked for instruction fetch" {
    const allocator = std.testing.allocator;
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    const addi = (arch.Instruction{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } }).encode();
    std.mem.writeInt(u32, ram[0x100..0x104], addi, arch.ENDIAN);

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.pc = 0x100;

    // RW but no X
    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = true, .x = false, .a = .napot });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.instruction_access_fault, cpu.registers.mcause.toException());
}

test "jit pmp: execute permission allows fetch in U-mode" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;

    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = true, .x = true, .a = .napot });

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 42), cpu.registers.get(1));
}

test "jit pmp: locked entry cannot be modified" {
    const allocator = std.testing.allocator;
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .machine;

    setPmpEntry(&cpu, 0, 0x1F, .{
        .r = true,
        .w = false,
        .x = false,
        .a = .napot,
        .l = true,
    });

    const original_addr = cpu.registers.pmpaddr[0];
    const original_cfg = cpu.registers.pmpcfg[0] & 0xFF;

    cpu.registers.setPmpCfg(0, .{ .r = true, .w = true, .x = true, .a = .napot });
    cpu.registers.writePmpaddr(0, 0xFF);

    try std.testing.expectEqual(original_addr, cpu.registers.pmpaddr[0]);
    try std.testing.expectEqual(original_cfg, cpu.registers.pmpcfg[0] & 0xFF);
}

test "jit pmp: locked entry enforced in M-mode (write denied)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 2, .rs2 = 1, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .machine;
    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, 0x100);

    // Locked region covering entire space, R and X but NO write
    setPmpEntry(&cpu, 0, 0x1FFFFFFF, .{ .r = true, .w = false, .x = true, .a = .napot, .l = true });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_access_fault, cpu.registers.mcause.toException());
    try std.testing.expectEqual(@as(u32, 0x100), cpu.registers.mtval);
}

test "jit pmp: locked entry enforced in M-mode for execute" {
    const allocator = std.testing.allocator;
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    const addi = (arch.Instruction{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } }).encode();
    std.mem.writeInt(u32, ram[0x100..0x104], addi, arch.ENDIAN);

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .machine;
    cpu.registers.pc = 0x100;

    // Locked region with NO execute
    setPmpEntry(&cpu, 0, 0x1FFFFFFF, .{ .r = true, .w = true, .x = false, .a = .napot, .l = true });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.instruction_access_fault, cpu.registers.mcause.toException());
}

test "jit pmp: locked entry enforced in M-mode (read allowed)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });
    std.mem.writeInt(u32, ram[0x100..0x104], 0xABCDEF01, arch.ENDIAN);

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .machine;
    cpu.registers.set(2, 0x100);

    // Locked region with R and X
    setPmpEntry(&cpu, 0, 0x1FFFFFFF, .{ .r = true, .w = false, .x = true, .a = .napot, .l = true });

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xABCDEF01))), cpu.registers.get(1));
}

test "jit pmp: byte access at last address of region succeeds" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lb = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });
    ram[0x1FF] = 0x42;

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x1FF);

    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = true, .x = true, .a = .napot });

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x42), cpu.registers.get(1));
}

test "jit pmp: byte access at first address outside region fails" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lb = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x200);

    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = true, .x = true, .a = .napot });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_access_fault, cpu.registers.mcause.toException());
}

test "jit pmp: store denied past region end" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(1, 0x200);
    cpu.registers.set(2, 0x12345678);

    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = true, .x = true, .a = .napot });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_access_fault, cpu.registers.mcause.toException());
    try std.testing.expectEqual(@as(u32, 0x200), cpu.registers.mtval);
}

test "jit pmp: store inside region succeeds" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(1, 0x120);
    cpu.registers.set(2, 0x12345678);

    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = true, .x = true, .a = .napot });

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(u32, 0x12345678), std.mem.readInt(u32, ram[0x120..0x124], arch.ENDIAN));
}

test "jit pmp: store denied when region is read-only" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(1, 0x120);
    cpu.registers.set(2, 0x12345678);

    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = false, .x = true, .a = .napot });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_access_fault, cpu.registers.mcause.toException());
}

test "jit pmp: load denied when region has no read permission" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x120);

    // W and X but no R
    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = false, .w = true, .x = true, .a = .napot });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_access_fault, cpu.registers.mcause.toException());
}

test "jit pmp: first matching entry takes priority (deny)" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(1, 0x100);
    cpu.registers.set(2, 0x12345678);

    // PMP0: full region but NO write permission (checked first)
    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = false, .x = true, .a = .napot });

    // PMP1: same region WITH write (but lower priority)
    setPmpEntry(&cpu, 1, napotAddr(0, 512), .{ .r = true, .w = true, .x = true, .a = .napot });

    try runAndExpectTrap(&cpu);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_access_fault, cpu.registers.mcause.toException());
}

test "jit pmp: OFF mode entry skipped" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });
    std.mem.writeInt(u32, ram[0x100..0x104], 0x11223344, arch.ENDIAN);

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x100);

    // PMP0: OFF mode (disabled)
    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = false, .w = false, .x = false, .a = .off });

    // PMP1: Actually allows access
    setPmpEntry(&cpu, 1, napotAddr(0, 512), .{ .r = true, .w = true, .x = true, .a = .napot });

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x11223344), cpu.registers.get(1));
}

test "jit pmp: multiple loads in block all succeed" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .{ .lw = .{ .rd = 3, .rs1 = 4, .imm = 0 } },
        .{ .lw = .{ .rd = 5, .rs1 = 6, .imm = 0 } },
        .ebreak,
    });
    std.mem.writeInt(u32, ram[0x100..0x104], 0x11111111, arch.ENDIAN);
    std.mem.writeInt(u32, ram[0x104..0x108], 0x22222222, arch.ENDIAN);
    std.mem.writeInt(u32, ram[0x108..0x10C], 0x33333333, arch.ENDIAN);

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x100);
    cpu.registers.set(4, 0x104);
    cpu.registers.set(6, 0x108);

    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = true, .x = true, .a = .napot });

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, 0x11111111), cpu.registers.get(1));
    try std.testing.expectEqual(@as(i32, 0x22222222), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 0x33333333), cpu.registers.get(5));
}

test "jit pmp: M-mode ignores non-locked entries" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
        .ebreak,
    });

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .machine;
    cpu.registers.set(1, 0x100);
    cpu.registers.set(2, @bitCast(@as(u32, 0xDEADBEEF)));

    // Non-locked entry with no write permission
    setPmpEntry(&cpu, 0, napotAddr(0, 512), .{ .r = true, .w = false, .x = true, .a = .napot, .l = false });

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), std.mem.readInt(u32, ram[0x100..0x104], arch.ENDIAN));
}

test "jit pmp: entry 15 can be used" {
    const allocator = std.testing.allocator;
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
        .ebreak,
    });
    std.mem.writeInt(u32, ram[0x100..0x104], 0xFEDCBA98, arch.ENDIAN);

    var cpu = try Cpu(.{}).init(allocator, &ram);
    defer cpu.deinit();

    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x100);

    // Set up all entries 0-14 as OFF
    for (0..15) |i| {
        setPmpEntry(&cpu, @intCast(i), 0, .{ .r = false, .w = false, .x = false, .a = .off });
    }

    // Entry 15: covers [0, 0x200)
    setPmpEntry(&cpu, 15, napotAddr(0, 512), .{ .r = true, .w = true, .x = true, .a = .napot });

    try runToEbreak(&cpu);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFEDCBA98))), cpu.registers.get(1));
}

test {
    _ = BlockCache;
    _ = CodeArena;
    _ = Engine;
}
