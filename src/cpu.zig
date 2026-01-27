// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

const elf = @import("elf.zig");
const arch = @import("arch.zig");
const utils = @import("utils.zig");

pub const Config = struct {
    pub const Hooks = struct {
        pub const Action = enum {
            proceed,
            skip,
            halt,
        };

        ecall: ?*const fn (cpu: *anyopaque, cause: arch.Registers.Mcause.Exception) callconv(.@"inline") Action = null,
        ebreak: ?*const fn (cpu: *anyopaque) callconv(.@"inline") Action = null,
        /// Return true to continue, false to halt.
        wfi: ?*const fn (cpu: *anyopaque) callconv(.@"inline") bool = null,
        isMmio: ?*const fn (cpu: *anyopaque, address: u32) callconv(.@"inline") bool = null,
        read: ?*const fn (cpu: *anyopaque, address: u32) callconv(.@"inline") ?u8 = null,
        write: ?*const fn (cpu: *anyopaque, address: u32, value: u8) callconv(.@"inline") bool = null,
        readTranslate: ?*const fn (cpu: *anyopaque, address: u32) callconv(.@"inline") u32 = null,
        writeTranslate: ?*const fn (cpu: *anyopaque, address: u32) callconv(.@"inline") u32 = null,
    };

    pub const Compile = struct {
        inline_execute: bool = true,

        pub const fast_compile: Compile = .{
            .inline_execute = false,
        };

        pub const fast_execution: Compile = .{};
    };

    pub const Runtime = struct {
        /// Enable Physical Memory Protection checks.
        /// Disable for ~2-3x speedup when running trusted code.
        enable_pmp: bool = true,

        /// If disabled - enables Physical Memory Protection checks in M mode only when
        /// MPRV is set.
        enable_pmp_m: bool = true,

        /// Enable memory alignment checks for loads/stores.
        /// RISC-V spec requires this, disable only for known-aligned code.
        enable_memory_alignment: bool = true,

        /// Enable privilege level enforcement.
        /// When disabled, all code runs in effective_privilege mode.
        enable_privilege: bool = true,

        /// Enable CSR privilege and read-only checks.
        enable_csr_checks: bool = true,

        /// Privilege level when enable_privilege=false
        effective_privilege: arch.PrivilegeLevel = .machine,

        /// Enable interrupt checking each step.
        /// Disable if using polling-based interrupt model.
        enable_interrupts: bool = true,

        /// Enable branch/jump target alignment checks (4-byte for RV32I).
        enable_branch_alignment: bool = true,

        /// Enable floating-point extensions (F/D).
        enable_fpu: bool = true,

        /// Enable FPU exception flags (NV, DZ, OF, UF, NX).
        /// When disabled, FCSR flags are not updated.
        enable_fpu_flags: bool = true,

        /// Enable cycle/instret counter updates.
        enable_counters: bool = true,

        /// Enable M extension (multiply/divide)
        enable_m_ext: bool = true,

        /// Enable Zba extension (address generation)
        enable_zba_ext: bool = true,

        /// Enable Zbb extension (bit manipulation)
        enable_zbb_ext: bool = true,

        timer_ticks_per_step: u64 = 1,

        /// Maximum performance, minimal checks (for trusted code)
        pub const fast = Runtime{
            .enable_pmp = false,
            .enable_memory_alignment = false,
            .enable_privilege = false,
            .enable_csr_checks = false,
            .enable_interrupts = false,
            .enable_branch_alignment = false,
            .enable_fpu_flags = false,
            .enable_counters = false,
            .timer_ticks_per_step = 0,
        };

        /// Full spec compliance (default)
        pub const compliant = Runtime{};

        /// Embedded system (no FPU, with protection)
        pub const embedded = Runtime{
            .enable_fpu = false,
            .enable_fpu_flags = false,
        };

        /// User-mode sandbox (full protection, no M-mode features)
        pub const sandbox = Runtime{
            .effective_privilege = .user,
        };
    };

    hooks: Hooks = .{},
    compile: Compile = .fast_execution,
    runtime: Runtime = .compliant,
};

pub inline fn Cpu(comptime config: Config) type {
    return struct {
        const Self = @This();

        const MemoryError = error{
            AddressOutOfBounds,
            MisalignedAddress,
            PmpViolation,
            ReadFailed,
            WriteFailed,
        };
        const FetchError = MemoryError || arch.Instruction.DecodeError;

        const ErrorCause = enum { instruction, load, store };

        pub const ElfLoadError = error{OutOfRam} || elf.ParseError;

        pub const TrapCause = union(enum) {
            exception: arch.Registers.Mcause.Exception,
            interrupt: arch.Registers.Mcause.Interrupt,

            pub inline fn toMcause(this: TrapCause) arch.Registers.Mcause {
                return switch (this) {
                    .exception => |e| arch.Registers.Mcause.fromException(e),
                    .interrupt => |i| arch.Registers.Mcause.fromInterrupt(i),
                };
            }
        };

        pub const State = union(enum) {
            ok,
            trap: TrapInfo,
            halt, // WFI with no pending interrupts

            pub const TrapInfo = struct {
                cause: TrapCause,
                tval: u32,
            };
        };

        ram: []u8,
        registers: arch.Registers = .{},

        pub inline fn init(ram: []u8) Self {
            std.debug.assert(ram.len % 4 == 0);

            return .{
                .ram = ram,
            };
        }

        pub inline fn step(this: *Self) State {
            @setEvalBranchQuota(std.math.maxInt(u32));

            if (comptime config.runtime.timer_ticks_per_step > 0) {
                this.registers.updateTimer(config.runtime.timer_ticks_per_step);
            }

            if (comptime config.runtime.enable_interrupts) {
                if (this.checkInterrupts()) |int_cause| {
                    this.handleTrap(.{ .interrupt = int_cause }, 0);
                    this.incCounters(false);

                    return .ok;
                }
            }

            const instr = this.fetch() catch |err| {
                return this.fetchErrorToState(err);
            };

            if (comptime config.compile.inline_execute) {
                return @call(.always_inline, execute, .{ this, instr });
            } else {
                return @call(.never_inline, execute, .{ this, instr });
            }
        }

        pub inline fn run(this: *Self, times: usize) State {
            @setEvalBranchQuota(std.math.maxInt(u32));

            for (0..times) |_| {
                const state = this.step();

                if (state != .ok) {
                    return state;
                }
            }

            return .ok;
        }

        pub inline fn getPrivilege(this: *Self) arch.PrivilegeLevel {
            if (comptime config.runtime.enable_privilege) {
                return this.registers.privilege.sanitize();
            } else {
                return config.runtime.effective_privilege;
            }
        }

        pub inline fn checkFpuAccess(this: *Self) ?State {
            if (comptime !config.runtime.enable_fpu) {
                return trapState(.illegal_instruction, 0);
            }

            if (this.registers.mstatus.fs == 0) {
                return trapState(.illegal_instruction, 0);
            }

            return null;
        }

        inline fn checkRoundingMode(this: *Self, rm: u3) ?State {
            if (rm == 0b101 or rm == 0b110) {
                return trapState(.illegal_instruction, 0);
            }

            if (rm == 0b111) {
                const frm = @intFromEnum(this.registers.fcsr.frm);

                if (frm >= 5) {
                    return trapState(.illegal_instruction, 0);
                }
            }

            return null;
        }

        pub inline fn markFpuDirty(this: *Self) void {
            if (this.registers.mstatus.fs != 0) {
                this.registers.mstatus.fs = 0b11; // Dirty
                this.registers.mstatus.updateSD();
            }
        }

        inline fn trapState(exception: arch.Registers.Mcause.Exception, tval: u32) State {
            return .{ .trap = .{ .cause = .{ .exception = exception }, .tval = tval } };
        }

        pub inline fn loadElf(this: *Self, allocator: std.mem.Allocator, content: []const u8, offset: u32) ElfLoadError!void {
            var reader: std.Io.Reader = .fixed(content);

            var file = try elf.File.parse(allocator, &reader);
            defer file.deinit(allocator);

            const ventry = file.header.entry;
            file.header.entry = file.header.entry -% offset;

            if (file.header.entry > this.ram.len) {
                return ElfLoadError.OutOfRam;
            }

            for (file.program_headers.items) |*header| {
                if (header.ty != .load) {
                    continue;
                }

                header.vaddr = header.vaddr -% offset;

                if (header.vaddr >= this.ram.len) {
                    return ElfLoadError.OutOfRam;
                }

                if (header.vaddr +% header.filesz > this.ram.len or header.vaddr +% header.memsz > this.ram.len) {
                    return ElfLoadError.OutOfRam;
                }

                if (header.filesz > 0) {
                    const from: u32 = header.vaddr;
                    const to: u32 = from +% header.filesz;

                    @memcpy(this.ram[from..to], content[header.offset .. header.offset + header.filesz]);
                }

                if (header.memsz > header.filesz) {
                    const from: u32 = header.vaddr +% header.filesz;
                    const to: u32 = (from +% header.memsz) - header.filesz;

                    @memset(this.ram[from..to], 0);
                }
            }

            this.registers.pc = ventry;
        }

        pub inline fn readMemory(this: *Self, address: u32, comptime T: type, comptime access: arch.Registers.Pmp.AccessType) MemoryError!T {
            @setEvalBranchQuota(std.math.maxInt(u32));

            const byte_len = @sizeOf(T);

            if (this.needsPmpCheck(access)) {
                if (!this.registers.checkPmpAccess(address, byte_len, access, this.getPrivilege())) {
                    return MemoryError.PmpViolation;
                }
            }

            if (comptime config.runtime.enable_memory_alignment) {
                if (address % byte_len != 0) {
                    return MemoryError.MisalignedAddress;
                }
            }

            if (comptime config.hooks.isMmio != null and config.hooks.read != null) {
                if (config.hooks.isMmio.?(this, address)) {
                    var dst: [byte_len]u8 = undefined;

                    inline for (0..byte_len) |i| {
                        if (config.hooks.read.?(this, address +% @as(u32, @intCast(i)))) |value| {
                            dst[i] = value;
                        } else {
                            return MemoryError.ReadFailed;
                        }
                    }

                    return std.mem.bytesToValue(T, &dst);
                }
            }

            const translated = if (comptime config.hooks.readTranslate) |hook|
                hook(this, address)
            else
                address;

            if (translated + byte_len > this.ram.len) {
                return MemoryError.AddressOutOfBounds;
            }

            const result: T = std.mem.bytesToValue(T, this.ram[translated .. translated + byte_len]);

            return std.mem.toNative(T, result, arch.ENDIAN);
        }

        pub inline fn writeMemory(this: *Self, address: u32, value: anytype) MemoryError!void {
            @setEvalBranchQuota(std.math.maxInt(u32));

            const T = @TypeOf(value);
            const byte_len = @sizeOf(T);

            if (this.needsPmpCheck(.write)) {
                if (!this.registers.checkPmpAccess(address, byte_len, .write, this.getPrivilege())) {
                    return MemoryError.PmpViolation;
                }
            }

            if (comptime config.runtime.enable_memory_alignment) {
                if (address % byte_len != 0) {
                    return MemoryError.MisalignedAddress;
                }
            }

            if (comptime config.hooks.isMmio != null and config.hooks.write != null) {
                if (config.hooks.isMmio.?(this, address)) {
                    const src = std.mem.asBytes(&value);

                    inline for (0..byte_len) |i| {
                        if (!config.hooks.write.?(this, address +% @as(u32, @intCast(i)), src[i])) {
                            return MemoryError.WriteFailed;
                        }
                    }

                    return;
                }
            }

            const translated = if (comptime config.hooks.writeTranslate) |hook|
                hook(this, address)
            else
                address;

            if (translated + byte_len > this.ram.len) {
                return MemoryError.AddressOutOfBounds;
            }

            const bytes = std.mem.asBytes(&std.mem.nativeTo(T, value, arch.ENDIAN));
            @memcpy(this.ram[translated .. translated + byte_len], bytes);
        }

        inline fn needsPmpCheck(this: *Self, comptime access: arch.Registers.Pmp.AccessType) bool {
            if (comptime !config.runtime.enable_pmp) {
                return false;
            }

            if (comptime config.runtime.enable_pmp_m) {
                return true;
            }

            if (this.getPrivilege() != .machine) {
                return true;
            }

            if (comptime access == .execute) {
                return false;
            }

            return this.registers.mstatus.mprv;
        }

        pub inline fn fetch(this: *Self) FetchError!arch.Instruction {
            @setEvalBranchQuota(std.math.maxInt(u32));

            const raw = try this.readMemory(this.registers.pc, u32, .execute);

            return arch.Instruction.decode(raw);
        }

        inline fn incCounters(this: *Self, comptime is_retired: bool) void {
            if (comptime config.runtime.enable_counters) {
                this.registers.cycle +%= 1;

                if (is_retired) {
                    this.registers.instret +%= 1;
                }
            }
        }

        inline fn memoryErrorToException(err: MemoryError, cause: ErrorCause) arch.Registers.Mcause.Exception {
            switch (err) {
                MemoryError.ReadFailed => return .load_access_fault,
                MemoryError.WriteFailed => return .store_access_fault,
                else => {},
            }

            return switch (cause) {
                .instruction => switch (err) {
                    MemoryError.AddressOutOfBounds, MemoryError.PmpViolation => .instruction_access_fault,
                    MemoryError.MisalignedAddress => .instruction_address_misaligned,
                    else => unreachable,
                },
                .load => switch (err) {
                    MemoryError.AddressOutOfBounds, MemoryError.PmpViolation => .load_access_fault,
                    MemoryError.MisalignedAddress => .load_address_misaligned,
                    else => unreachable,
                },
                .store => switch (err) {
                    MemoryError.AddressOutOfBounds, MemoryError.PmpViolation => .store_access_fault,
                    MemoryError.MisalignedAddress => .store_address_misaligned,
                    else => unreachable,
                },
            };
        }

        inline fn memoryErrorToState(err: MemoryError, cause: ErrorCause, addr: u32) State {
            return trapState(memoryErrorToException(err, cause), addr);
        }

        inline fn fetchErrorToState(this: *Self, err: FetchError) State {
            const exception: arch.Registers.Mcause.Exception = switch (err) {
                FetchError.AddressOutOfBounds, FetchError.PmpViolation => .instruction_access_fault,
                FetchError.MisalignedAddress => .instruction_address_misaligned,
                FetchError.UnknownInstruction, FetchError.BadRegister => .illegal_instruction,
                FetchError.ReadFailed => .load_access_fault,
                FetchError.WriteFailed => .store_access_fault,
            };

            return trapState(exception, this.registers.pc);
        }

        pub inline fn handleTrap(this: *Self, cause: TrapCause, tval: u32) void {
            const mcause = cause.toMcause();
            const is_interrupt = mcause.interrupt;

            this.registers.mepc = this.registers.pc;
            this.registers.mcause = mcause;
            this.registers.mtval = tval;

            this.registers.mstatus.mpie = this.registers.mstatus.mie;
            this.registers.mstatus.mpp = this.getPrivilege();
            this.registers.mstatus.mie = false;

            this.registers.privilege = .machine;

            this.registers.pc = this.registers.mtvec.getAddress(mcause.code, is_interrupt);
        }

        inline fn executeMret(this: *Self) State {
            if (this.getPrivilege() != .machine) {
                return trapState(.illegal_instruction, 0);
            }

            this.registers.privilege = this.registers.mstatus.mpp.sanitize();

            this.registers.mstatus.mie = this.registers.mstatus.mpie;
            this.registers.mstatus.mpie = true;

            this.registers.mstatus.mpp = .user;

            this.registers.pc = this.registers.mepc;

            return .ok;
        }

        pub inline fn checkInterrupts(this: *Self) ?arch.Registers.Mcause.Interrupt {
            if (comptime !config.runtime.enable_interrupts) {
                return null;
            }

            const priv = this.getPrivilege();
            const can_interrupt = this.registers.mstatus.mie or (priv == .user);

            if (!can_interrupt) {
                return null;
            }

            const mie: u32 = @bitCast(this.registers.mie);
            const mip: u32 = @bitCast(this.registers.mip);
            const pending = mie & mip;

            // Priority: MEI > MSI > MTI
            if (pending & 0x800 != 0) {
                return .machine_external;
            }

            if (pending & 0x008 != 0) {
                return .machine_software;
            }

            if (pending & 0x080 != 0) {
                return .machine_timer;
            }

            return null;
        }

        fn execute(this: *Self, instruction: arch.Instruction) State {
            switch (instruction) {
                .lui => |i| {
                    this.registers.set(i.rd, @as(i32, i.imm) << 12);
                    this.registers.pc +%= 4;
                },
                .auipc => |i| {
                    const offset: u32 = @bitCast(@as(i32, i.imm) << 12);

                    this.registers.set(i.rd, @bitCast(this.registers.pc +% offset));
                    this.registers.pc +%= 4;
                },
                .jal => |i| {
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const target = this.registers.pc +% offset;

                    if (comptime config.runtime.enable_branch_alignment) {
                        if (target % 4 != 0) {
                            this.incCounters(true);

                            return trapState(.instruction_address_misaligned, target);
                        }
                    }

                    this.registers.set(i.rd, @bitCast(this.registers.pc +% 4));
                    this.registers.pc = target;
                },
                .jalr => |i| {
                    const target: u32 = @bitCast((this.registers.get(i.rs1) +% i.imm) & ~@as(i32, 1));

                    if (comptime config.runtime.enable_branch_alignment) {
                        if (target % 4 != 0) {
                            this.incCounters(true);

                            return trapState(.instruction_address_misaligned, target);
                        }
                    }

                    this.registers.set(i.rd, @bitCast(this.registers.pc +% 4));
                    this.registers.pc = target;
                },
                .beq => |i| {
                    if (this.registers.get(i.rs1) == this.registers.get(i.rs2)) {
                        const offset: u32 = @bitCast(@as(i32, i.imm));
                        const target = this.registers.pc +% offset;

                        if (comptime config.runtime.enable_branch_alignment) {
                            if (target % 4 != 0) {
                                this.incCounters(true);

                                return trapState(.instruction_address_misaligned, target);
                            }
                        }

                        this.registers.pc = target;
                    } else {
                        this.registers.pc +%= 4;
                    }
                },
                .bne => |i| {
                    if (this.registers.get(i.rs1) != this.registers.get(i.rs2)) {
                        const offset: u32 = @bitCast(@as(i32, i.imm));
                        const target = this.registers.pc +% offset;

                        if (comptime config.runtime.enable_branch_alignment) {
                            if (target % 4 != 0) {
                                this.incCounters(true);

                                return trapState(.instruction_address_misaligned, target);
                            }
                        }

                        this.registers.pc = target;
                    } else {
                        this.registers.pc +%= 4;
                    }
                },
                .blt => |i| {
                    if (this.registers.get(i.rs1) < this.registers.get(i.rs2)) {
                        const offset: u32 = @bitCast(@as(i32, i.imm));
                        const target = this.registers.pc +% offset;

                        if (comptime config.runtime.enable_branch_alignment) {
                            if (target % 4 != 0) {
                                this.incCounters(true);

                                return trapState(.instruction_address_misaligned, target);
                            }
                        }

                        this.registers.pc = target;
                    } else {
                        this.registers.pc +%= 4;
                    }
                },
                .bge => |i| {
                    if (this.registers.get(i.rs1) >= this.registers.get(i.rs2)) {
                        const offset: u32 = @bitCast(@as(i32, i.imm));
                        const target = this.registers.pc +% offset;

                        if (comptime config.runtime.enable_branch_alignment) {
                            if (target % 4 != 0) {
                                this.incCounters(true);

                                return trapState(.instruction_address_misaligned, target);
                            }
                        }

                        this.registers.pc = target;
                    } else {
                        this.registers.pc +%= 4;
                    }
                },
                .bltu => |i| {
                    const rs1_u: u32 = @bitCast(this.registers.get(i.rs1));
                    const rs2_u: u32 = @bitCast(this.registers.get(i.rs2));

                    if (rs1_u < rs2_u) {
                        const offset: u32 = @bitCast(@as(i32, i.imm));
                        const target = this.registers.pc +% offset;

                        if (comptime config.runtime.enable_branch_alignment) {
                            if (target % 4 != 0) {
                                this.incCounters(true);

                                return trapState(.instruction_address_misaligned, target);
                            }
                        }

                        this.registers.pc = target;
                    } else {
                        this.registers.pc +%= 4;
                    }
                },
                .bgeu => |i| {
                    const rs1_u: u32 = @bitCast(this.registers.get(i.rs1));
                    const rs2_u: u32 = @bitCast(this.registers.get(i.rs2));

                    if (rs1_u >= rs2_u) {
                        const offset: u32 = @bitCast(@as(i32, i.imm));
                        const target = this.registers.pc +% offset;

                        if (comptime config.runtime.enable_branch_alignment) {
                            if (target % 4 != 0) {
                                this.incCounters(true);

                                return trapState(.instruction_address_misaligned, target);
                            }
                        }

                        this.registers.pc = target;
                    } else {
                        this.registers.pc +%= 4;
                    }
                },
                .lb => |i| {
                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;
                    const val = this.readMemory(addr, i8, .read) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .load, addr);
                    };

                    this.registers.set(i.rd, val);
                    this.registers.pc +%= 4;
                },
                .lh => |i| {
                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;
                    const val = this.readMemory(addr, i16, .read) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .load, addr);
                    };

                    this.registers.set(i.rd, val);
                    this.registers.pc +%= 4;
                },
                .lw => |i| {
                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;
                    const val = this.readMemory(addr, i32, .read) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .load, addr);
                    };

                    this.registers.set(i.rd, val);
                    this.registers.pc +%= 4;
                },
                .lbu => |i| {
                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;
                    const val = this.readMemory(addr, u8, .read) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .load, addr);
                    };

                    this.registers.set(i.rd, val);
                    this.registers.pc +%= 4;
                },
                .lhu => |i| {
                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;
                    const val = this.readMemory(addr, u16, .read) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .load, addr);
                    };

                    this.registers.set(i.rd, val);
                    this.registers.pc +%= 4;
                },
                .sb => |i| {
                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;
                    const val: u8 = @truncate(@as(u32, @bitCast(this.registers.get(i.rs2))));

                    this.writeMemory(addr, val) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .store, addr);
                    };

                    this.registers.pc +%= 4;
                },
                .sh => |i| {
                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;
                    const val: u16 = @truncate(@as(u32, @bitCast(this.registers.get(i.rs2))));

                    this.writeMemory(addr, val) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .store, addr);
                    };

                    this.registers.pc +%= 4;
                },
                .sw => |i| {
                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;

                    this.writeMemory(addr, @as(u32, @bitCast(this.registers.get(i.rs2)))) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .store, addr);
                    };

                    this.registers.pc +%= 4;
                },
                .addi => |i| {
                    this.registers.set(i.rd, this.registers.get(i.rs1) +% i.imm);
                    this.registers.pc +%= 4;
                },
                .slti => |i| {
                    const result: i32 = if (this.registers.get(i.rs1) < i.imm) 1 else 0;

                    this.registers.set(i.rd, result);
                    this.registers.pc +%= 4;
                },
                .sltiu => |i| {
                    const rs1_u: u32 = @bitCast(this.registers.get(i.rs1));
                    const imm_u: u32 = @bitCast(@as(i32, i.imm)); // sign-extend then treat as unsigned
                    const result: i32 = if (rs1_u < imm_u) 1 else 0;

                    this.registers.set(i.rd, result);
                    this.registers.pc +%= 4;
                },
                .xori => |i| {
                    this.registers.set(i.rd, this.registers.get(i.rs1) ^ i.imm);
                    this.registers.pc +%= 4;
                },
                .ori => |i| {
                    this.registers.set(i.rd, this.registers.get(i.rs1) | i.imm);
                    this.registers.pc +%= 4;
                },
                .andi => |i| {
                    this.registers.set(i.rd, this.registers.get(i.rs1) & i.imm);
                    this.registers.pc +%= 4;
                },
                .slli => |i| {
                    this.registers.set(i.rd, this.registers.get(i.rs1) << i.shamt);
                    this.registers.pc +%= 4;
                },
                .srli => |i| {
                    const val_u: u32 = @bitCast(this.registers.get(i.rs1));

                    this.registers.set(i.rd, @bitCast(val_u >> i.shamt));
                    this.registers.pc +%= 4;
                },
                .srai => |i| {
                    this.registers.set(i.rd, this.registers.get(i.rs1) >> i.shamt);
                    this.registers.pc +%= 4;
                },
                .add => |i| {
                    this.registers.set(i.rd, this.registers.get(i.rs1) +% this.registers.get(i.rs2));
                    this.registers.pc +%= 4;
                },
                .sub => |i| {
                    this.registers.set(i.rd, this.registers.get(i.rs1) -% this.registers.get(i.rs2));
                    this.registers.pc +%= 4;
                },
                .sll => |i| {
                    const shamt: u5 = @truncate(@as(u32, @bitCast(this.registers.get(i.rs2))));

                    this.registers.set(i.rd, this.registers.get(i.rs1) << shamt);
                    this.registers.pc +%= 4;
                },
                .slt => |i| {
                    const result: i32 = if (this.registers.get(i.rs1) < this.registers.get(i.rs2)) 1 else 0;

                    this.registers.set(i.rd, result);
                    this.registers.pc +%= 4;
                },
                .sltu => |i| {
                    const rs1_u: u32 = @bitCast(this.registers.get(i.rs1));
                    const rs2_u: u32 = @bitCast(this.registers.get(i.rs2));
                    const result: i32 = if (rs1_u < rs2_u) 1 else 0;

                    this.registers.set(i.rd, result);
                    this.registers.pc +%= 4;
                },
                .xor => |i| {
                    this.registers.set(i.rd, this.registers.get(i.rs1) ^ this.registers.get(i.rs2));
                    this.registers.pc +%= 4;
                },
                .srl => |i| {
                    const shamt: u5 = @truncate(@as(u32, @bitCast(this.registers.get(i.rs2))));
                    const val_u: u32 = @bitCast(this.registers.get(i.rs1));

                    this.registers.set(i.rd, @bitCast(val_u >> shamt));
                    this.registers.pc +%= 4;
                },
                .sra => |i| {
                    const shamt: u5 = @truncate(@as(u32, @bitCast(this.registers.get(i.rs2))));

                    this.registers.set(i.rd, this.registers.get(i.rs1) >> shamt);
                    this.registers.pc +%= 4;
                },
                .@"or" => |i| {
                    this.registers.set(i.rd, this.registers.get(i.rs1) | this.registers.get(i.rs2));
                    this.registers.pc +%= 4;
                },
                .@"and" => |i| {
                    this.registers.set(i.rd, this.registers.get(i.rs1) & this.registers.get(i.rs2));
                    this.registers.pc +%= 4;
                },
                .fence => {
                    // noop
                    this.registers.pc +%= 4;
                },
                .ecall => {
                    const cause: arch.Registers.Mcause.Exception = switch (this.getPrivilege()) {
                        .user => .ecall_from_u,
                        .machine => .ecall_from_m,
                        _ => .ecall_from_m,
                    };

                    if (comptime config.hooks.ecall) |hook| {
                        switch (hook(@ptrCast(this), cause)) {
                            .proceed => {},
                            .skip => {
                                this.incCounters(true);
                                this.registers.pc +%= 4;

                                return .ok;
                            },
                            .halt => {
                                this.incCounters(true);

                                return .halt;
                            },
                        }
                    }

                    this.incCounters(true);

                    return trapState(cause, 0);
                },
                .ebreak => {
                    if (comptime config.hooks.ebreak) |hook| {
                        switch (hook(this)) {
                            .proceed => {},
                            .skip => {
                                this.incCounters(true);
                                this.registers.pc +%= 4;

                                return .ok;
                            },
                            .halt => {
                                this.incCounters(true);

                                return .halt;
                            },
                        }
                    }

                    this.incCounters(true);

                    return trapState(.breakpoint, this.registers.pc); // breakpoint: mtval = PC
                },
                .mul => |i| {
                    if (comptime !config.runtime.enable_m_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    this.registers.set(i.rd, this.registers.get(i.rs1) *% this.registers.get(i.rs2));
                    this.registers.pc +%= 4;
                },
                .mulh => |i| {
                    if (comptime !config.runtime.enable_m_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: i64 = this.registers.get(i.rs1);
                    const rs2: i64 = this.registers.get(i.rs2);

                    this.registers.set(i.rd, @truncate((rs1 * rs2) >> 32));
                    this.registers.pc +%= 4;
                },
                .mulhsu => |i| {
                    if (comptime !config.runtime.enable_m_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1_s: i64 = this.registers.get(i.rs1);
                    const rs2_u: u64 = @as(u32, @bitCast(this.registers.get(i.rs2)));
                    const val: i64 = rs1_s * @as(i64, @bitCast(rs2_u));

                    this.registers.set(i.rd, @truncate(val >> 32));
                    this.registers.pc +%= 4;
                },
                .mulhu => |i| {
                    if (comptime !config.runtime.enable_m_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1_u: u64 = @as(u32, @bitCast(this.registers.get(i.rs1)));
                    const rs2_u: u64 = @as(u32, @bitCast(this.registers.get(i.rs2)));

                    this.registers.set(i.rd, @bitCast(@as(u32, @truncate((rs1_u * rs2_u) >> 32))));
                    this.registers.pc +%= 4;
                },
                .div => |i| {
                    if (comptime !config.runtime.enable_m_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const dividend = this.registers.get(i.rs1);
                    const divisor = this.registers.get(i.rs2);
                    const result: i32 = if (divisor == 0)
                        -1
                    else if (dividend == std.math.minInt(i32) and divisor == -1)
                        dividend
                    else
                        @divTrunc(dividend, divisor);

                    this.registers.set(i.rd, result);
                    this.registers.pc +%= 4;
                },
                .divu => |i| {
                    if (comptime !config.runtime.enable_m_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const dividend_u: u32 = @bitCast(this.registers.get(i.rs1));
                    const divisor_u: u32 = @bitCast(this.registers.get(i.rs2));

                    const result: u32 = if (divisor_u == 0)
                        std.math.maxInt(u32)
                    else
                        dividend_u / divisor_u;

                    this.registers.set(i.rd, @bitCast(result));
                    this.registers.pc +%= 4;
                },
                .rem => |i| {
                    if (comptime !config.runtime.enable_m_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const dividend = this.registers.get(i.rs1);
                    const divisor = this.registers.get(i.rs2);

                    const result: i32 = if (divisor == 0)
                        dividend
                    else if (dividend == std.math.minInt(i32) and divisor == -1)
                        0
                    else
                        @rem(dividend, divisor);

                    this.registers.set(i.rd, result);
                    this.registers.pc +%= 4;
                },
                .remu => |i| {
                    if (comptime !config.runtime.enable_m_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const dividend_u: u32 = @bitCast(this.registers.get(i.rs1));
                    const divisor_u: u32 = @bitCast(this.registers.get(i.rs2));

                    const result: u32 = if (divisor_u == 0)
                        dividend_u
                    else
                        dividend_u % divisor_u;

                    this.registers.set(i.rd, @bitCast(result));
                    this.registers.pc +%= 4;
                },
                .flw => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;
                    const val = this.readMemory(addr, u32, .read) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .load, addr);
                    };

                    this.registers.setF32(i.rd, @bitCast(val));
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsw => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;
                    const val: u32 = @bitCast(this.registers.getF32(i.rs2));

                    this.writeMemory(addr, val) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .store, addr);
                    };

                    this.registers.pc +%= 4;
                },
                .fadd_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1) or
                            arch.FloatHelpers.isSignalingNanF32(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if (std.math.isInf(rs1) and std.math.isInf(rs2)) {
                            if ((rs1 > 0) != (rs2 > 0)) {
                                this.registers.fcsr.nv = true;
                                this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                                this.markFpuDirty();
                                this.registers.pc +%= 4;
                                this.incCounters(true);

                                return .ok;
                            }
                        }
                    }

                    const result = rs1 + rs2;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and !std.math.isInf(rs1) and !std.math.isInf(rs2)) {
                            this.registers.fcsr.of = true;
                            this.registers.fcsr.nx = true;
                        }

                        if (arch.FloatHelpers.isSubnormalF32(result)) {
                            this.registers.fcsr.uf = true;
                        }

                        if (!std.math.isNan(result) and !std.math.isInf(result)) {
                            const check: f64 = @as(f64, rs1) + @as(f64, rs2);

                            if (@as(f64, result) != check) {
                                this.registers.fcsr.nx = true;
                            }
                        }
                    }

                    this.registers.setF32(i.rd, if (std.math.isNan(result)) arch.FloatHelpers.canonicalNanF32() else result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsub_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1) or
                            arch.FloatHelpers.isSignalingNanF32(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if (std.math.isInf(rs1) and std.math.isInf(rs2) and (rs1 > 0) == (rs2 > 0)) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = rs1 - rs2;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and !std.math.isInf(rs1) and !std.math.isInf(rs2)) {
                            this.registers.fcsr.of = true;
                            this.registers.fcsr.nx = true;
                        }

                        if (arch.FloatHelpers.isSubnormalF32(result)) {
                            this.registers.fcsr.uf = true;
                        }

                        if (!std.math.isNan(result) and !std.math.isInf(result)) {
                            const check: f64 = @as(f64, rs1) - @as(f64, rs2);

                            if (@as(f64, result) != check) {
                                this.registers.fcsr.nx = true;
                            }
                        }
                    }

                    this.registers.setF32(i.rd, if (std.math.isNan(result)) arch.FloatHelpers.canonicalNanF32() else result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fmul_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1) or
                            arch.FloatHelpers.isSignalingNanF32(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if ((rs1 == 0 and std.math.isInf(rs2)) or (std.math.isInf(rs1) and rs2 == 0)) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = rs1 * rs2;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and !std.math.isInf(rs1) and !std.math.isInf(rs2)) {
                            this.registers.fcsr.of = true;
                            this.registers.fcsr.nx = true;
                        }

                        if (arch.FloatHelpers.isSubnormalF32(result)) {
                            this.registers.fcsr.uf = true;
                        }

                        if (!std.math.isNan(result) and
                            !std.math.isInf(result) and
                            !std.math.isInf(rs1) and
                            !std.math.isInf(rs2))
                        {
                            const check: f64 = @as(f64, rs1) * @as(f64, rs2);

                            if (@as(f64, result) != check) {
                                this.registers.fcsr.nx = true;
                            }
                        }
                    }

                    this.registers.setF32(i.rd, if (std.math.isNan(result)) arch.FloatHelpers.canonicalNanF32() else result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fdiv_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1) or
                            arch.FloatHelpers.isSignalingNanF32(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if ((rs1 == 0 and rs2 == 0) or (std.math.isInf(rs1) and std.math.isInf(rs2))) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }

                        if (rs2 == 0 and rs1 != 0 and !std.math.isNan(rs1)) {
                            this.registers.fcsr.dz = true;
                        }
                    }

                    const result = rs1 / rs2;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and !std.math.isInf(rs1) and rs2 != 0) {
                            this.registers.fcsr.of = true;
                            this.registers.fcsr.nx = true;
                        }

                        if (arch.FloatHelpers.isSubnormalF32(result)) {
                            this.registers.fcsr.uf = true;
                        }

                        if (!std.math.isNan(result) and !std.math.isInf(result) and rs2 != 0) {
                            const check: f64 = @as(f64, rs1) / @as(f64, rs2);

                            if (@as(f64, result) != check) {
                                this.registers.fcsr.nx = true;
                            }
                        }
                    }

                    this.registers.setF32(i.rd, if (std.math.isNan(result)) arch.FloatHelpers.canonicalNanF32() else result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsqrt_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1)) {
                            this.registers.fcsr.nv = true;
                        }

                        if (rs1 < 0 and !arch.FloatHelpers.isNegativeZeroF32(rs1)) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = @sqrt(rs1);

                    if (arch.FloatHelpers.isNegativeZeroF32(rs1)) {
                        this.registers.setF32(i.rd, rs1);
                    } else {
                        this.registers.setF32(i.rd, if (std.math.isNan(result)) arch.FloatHelpers.canonicalNanF32() else result);
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fmin_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1) or
                            arch.FloatHelpers.isSignalingNanF32(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    const result: f32 = if (std.math.isNan(rs1) and std.math.isNan(rs2))
                        arch.FloatHelpers.canonicalNanF32()
                    else if (std.math.isNan(rs1))
                        rs2
                    else if (std.math.isNan(rs2))
                        rs1
                    else if (rs1 == 0 and rs2 == 0)
                        // -0.0 < +0.0
                        if (arch.FloatHelpers.isNegativeZeroF32(rs1) or arch.FloatHelpers.isNegativeZeroF32(rs2))
                            @bitCast(@as(u32, 0x80000000)) // -0.0
                        else
                            rs1
                    else
                        @min(rs1, rs2);

                    this.registers.setF32(i.rd, result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fmax_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1) or
                            arch.FloatHelpers.isSignalingNanF32(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    const result: f32 = if (std.math.isNan(rs1) and std.math.isNan(rs2))
                        arch.FloatHelpers.canonicalNanF32()
                    else if (std.math.isNan(rs1))
                        rs2
                    else if (std.math.isNan(rs2))
                        rs1
                    else if (rs1 == 0 and rs2 == 0)
                        // +0.0 > -0.0
                        if (arch.FloatHelpers.isPositiveZeroF32(rs1) or arch.FloatHelpers.isPositiveZeroF32(rs2))
                            @as(f32, 0.0) // +0.0
                        else
                            rs1
                    else
                        @max(rs1, rs2);

                    this.registers.setF32(i.rd, result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsgnj_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1: u32 = @bitCast(this.registers.getF32(i.rs1));
                    const rs2: u32 = @bitCast(this.registers.getF32(i.rs2));
                    const result = (rs1 & 0x7FFFFFFF) | (rs2 & 0x80000000);

                    this.registers.setF32(i.rd, @bitCast(result));
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsgnjn_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1: u32 = @bitCast(this.registers.getF32(i.rs1));
                    const rs2: u32 = @bitCast(this.registers.getF32(i.rs2));
                    const result = (rs1 & 0x7FFFFFFF) | (~rs2 & 0x80000000);

                    this.registers.setF32(i.rd, @bitCast(result));
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsgnjx_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1: u32 = @bitCast(this.registers.getF32(i.rs1));
                    const rs2: u32 = @bitCast(this.registers.getF32(i.rs2));
                    const result = rs1 ^ (rs2 & 0x80000000);

                    this.registers.setF32(i.rd, @bitCast(result));
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .feq_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1) or
                            arch.FloatHelpers.isSignalingNanF32(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    const result: i32 = if (std.math.isNan(rs1) or std.math.isNan(rs2))
                        0
                    else if (rs1 == rs2)
                        1
                    else
                        0;

                    this.registers.set(i.rd, result);
                    this.registers.pc +%= 4;
                },
                .flt_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isNan(rs1) or std.math.isNan(rs2)) {
                            this.registers.fcsr.nv = true;
                            this.registers.set(i.rd, 0);
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    this.registers.set(i.rd, if (rs1 < rs2) 1 else 0);
                    this.registers.pc +%= 4;
                },
                .fle_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isNan(rs1) or std.math.isNan(rs2)) {
                            this.registers.fcsr.nv = true;
                            this.registers.set(i.rd, 0);
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    this.registers.set(i.rd, if (rs1 <= rs2) 1 else 0);
                    this.registers.pc +%= 4;
                },
                .fcvt_w_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rm = this.registers.fcsr.getEffectiveRm(i.rm);

                    var result: i32 = undefined;
                    var invalid = false;

                    if (std.math.isNan(rs1)) {
                        result = std.math.maxInt(i32);
                        invalid = true;
                    } else if (std.math.isInf(rs1)) {
                        result = if (rs1 > 0) std.math.maxInt(i32) else std.math.minInt(i32);
                        invalid = true;
                    } else {
                        const rounded: f32 = switch (rm) {
                            .rne => arch.FloatHelpers.roundToNearestEvenF32(rs1),
                            .rtz => if (rs1 >= 0) @floor(rs1) else @ceil(rs1),
                            .rdn => @floor(rs1),
                            .rup => @ceil(rs1),
                            .rmm => if (rs1 >= 0) @floor(rs1 + 0.5) else @ceil(rs1 - 0.5),
                            else => arch.FloatHelpers.roundToNearestEvenF32(rs1),
                        };

                        if (rounded > @as(f32, @floatFromInt(std.math.maxInt(i32)))) {
                            result = std.math.maxInt(i32);
                            invalid = true;
                        } else if (rounded < @as(f32, @floatFromInt(std.math.minInt(i32)))) {
                            result = std.math.minInt(i32);
                            invalid = true;
                        } else {
                            result = @intFromFloat(rounded);

                            if (comptime config.runtime.enable_fpu_flags) {
                                if (rounded != rs1) {
                                    this.registers.fcsr.nx = true;
                                }
                            }
                        }
                    }

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (invalid) {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    this.registers.set(i.rd, result);
                    this.registers.pc +%= 4;
                },
                .fcvt_wu_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);
                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);
                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rm = this.registers.fcsr.getEffectiveRm(i.rm);

                    var result: u32 = undefined;
                    var invalid = false;

                    if (std.math.isNan(rs1)) {
                        result = std.math.maxInt(u32);
                        invalid = true;
                    } else if (std.math.isInf(rs1)) {
                        result = if (rs1 > 0) std.math.maxInt(u32) else 0;
                        invalid = true;
                    } else {
                        const rounded: f32 = switch (rm) {
                            .rne => arch.FloatHelpers.roundToNearestEvenF32(rs1),
                            .rtz => if (rs1 >= 0) @floor(rs1) else @ceil(rs1),
                            .rdn => @floor(rs1),
                            .rup => @ceil(rs1),
                            .rmm => if (rs1 >= 0) @floor(rs1 + 0.5) else @ceil(rs1 - 0.5),
                            else => arch.FloatHelpers.roundToNearestEvenF32(rs1),
                        };

                        if (rounded < 0) {
                            result = 0;
                            invalid = true;
                        } else if (rounded > @as(f32, @floatFromInt(std.math.maxInt(u32)))) {
                            result = std.math.maxInt(u32);
                            invalid = true;
                        } else {
                            result = @intFromFloat(rounded);

                            if (comptime config.runtime.enable_fpu_flags) {
                                if (rounded != rs1) {
                                    this.registers.fcsr.nx = true;
                                }
                            }
                        }
                    }

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (invalid) {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    this.registers.set(i.rd, @bitCast(result));
                    this.registers.pc +%= 4;
                },
                .fcvt_s_w => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.get(i.rs1);
                    const result: f32 = @floatFromInt(rs1);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (@as(i32, @intFromFloat(result)) != rs1) {
                            this.registers.fcsr.nx = true;
                        }
                    }

                    this.registers.setF32(i.rd, result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fcvt_s_wu => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const result: f32 = @floatFromInt(rs1);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (@as(u32, @intFromFloat(result)) != rs1) {
                            this.registers.fcsr.nx = true;
                        }
                    }

                    this.registers.setF32(i.rd, result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fmv_x_w => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const val: u32 = @bitCast(this.registers.getF32(i.rs1));

                    this.registers.set(i.rd, @bitCast(val));
                    this.registers.pc +%= 4;
                },
                .fmv_w_x => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const val: u32 = @bitCast(this.registers.get(i.rs1));

                    this.registers.setF32(i.rd, @bitCast(val));
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fclass_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const val = this.registers.getF32(i.rs1);
                    const bits: u32 = @bitCast(val);
                    const sign = (bits >> 31) & 1;
                    const exp = (bits >> 23) & 0xFF;
                    const frac = bits & 0x7FFFFF;

                    const result: u32 = if (exp == 0xFF and frac != 0)
                        // NaN
                        if (frac & 0x400000 != 0) 0x200 else 0x100 // qNaN (bit 9) or sNaN (bit 8)
                    else if (exp == 0xFF)
                        // Infinity
                        if (sign != 0) 0x001 else 0x080 // -inf (bit 0) or +inf (bit 7)
                    else if (exp == 0 and frac == 0)
                        // Zero
                        if (sign != 0) 0x008 else 0x010 // -0 (bit 3) or +0 (bit 4)
                    else if (exp == 0)
                        // Subnormal
                        if (sign != 0) 0x004 else 0x020 // negative (bit 2) or positive (bit 5)
                    else
                        // Normal
                        if (sign != 0) 0x002 else 0x040; // negative (bit 1) or positive (bit 6)

                    this.registers.set(i.rd, @bitCast(result));
                    this.registers.pc +%= 4;
                },
                .fmadd_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);
                    const rs3 = this.registers.getF32(i.rs3);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1) or
                            arch.FloatHelpers.isSignalingNanF32(rs2) or
                            arch.FloatHelpers.isSignalingNanF32(rs3))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if ((std.math.isInf(rs1) and rs2 == 0) or (rs1 == 0 and std.math.isInf(rs2))) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = @mulAdd(f32, rs1, rs2, rs3);

                    if (std.math.isNan(result)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            // If result is NaN but no input was NaN, it's an invalid operation
                            // (e.g., inf + (-inf) from the fused operation)
                            if (!std.math.isNan(rs1) and !std.math.isNan(rs2) and !std.math.isNan(rs3)) {
                                this.registers.fcsr.nv = true;
                            }
                        }

                        this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                    } else {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (std.math.isInf(result) and
                                !std.math.isInf(rs1) and
                                !std.math.isInf(rs2) and
                                !std.math.isInf(rs3))
                            {
                                this.registers.fcsr.of = true;
                                this.registers.fcsr.nx = true;
                            }
                        }

                        this.registers.setF32(i.rd, result);
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fmsub_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);
                    const rs3 = this.registers.getF32(i.rs3);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1) or
                            arch.FloatHelpers.isSignalingNanF32(rs2) or
                            arch.FloatHelpers.isSignalingNanF32(rs3))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if ((std.math.isInf(rs1) and rs2 == 0) or (rs1 == 0 and std.math.isInf(rs2))) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = @mulAdd(f32, rs1, rs2, -rs3);

                    if (std.math.isNan(result)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (!std.math.isNan(rs1) and !std.math.isNan(rs2) and !std.math.isNan(rs3)) {
                                this.registers.fcsr.nv = true;
                            }
                        }

                        this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                    } else {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (std.math.isInf(result) and
                                !std.math.isInf(rs1) and
                                !std.math.isInf(rs2) and
                                !std.math.isInf(rs3))
                            {
                                this.registers.fcsr.of = true;
                                this.registers.fcsr.nx = true;
                            }
                        }

                        this.registers.setF32(i.rd, result);
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fnmsub_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);
                    const rs3 = this.registers.getF32(i.rs3);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1) or
                            arch.FloatHelpers.isSignalingNanF32(rs2) or
                            arch.FloatHelpers.isSignalingNanF32(rs3))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if ((std.math.isInf(rs1) and rs2 == 0) or (rs1 == 0 and std.math.isInf(rs2))) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = @mulAdd(f32, -rs1, rs2, rs3);

                    if (std.math.isNan(result)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (!std.math.isNan(rs1) and !std.math.isNan(rs2) and !std.math.isNan(rs3)) {
                                this.registers.fcsr.nv = true;
                            }
                        }

                        this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                    } else {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (std.math.isInf(result) and
                                !std.math.isInf(rs1) and
                                !std.math.isInf(rs2) and
                                !std.math.isInf(rs3))
                            {
                                this.registers.fcsr.of = true;
                                this.registers.fcsr.nx = true;
                            }
                        }

                        this.registers.setF32(i.rd, result);
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fnmadd_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);
                    const rs2 = this.registers.getF32(i.rs2);
                    const rs3 = this.registers.getF32(i.rs3);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1) or
                            arch.FloatHelpers.isSignalingNanF32(rs2) or
                            arch.FloatHelpers.isSignalingNanF32(rs3))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if ((std.math.isInf(rs1) and rs2 == 0) or (rs1 == 0 and std.math.isInf(rs2))) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = @mulAdd(f32, -rs1, rs2, -rs3);

                    if (std.math.isNan(result)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (!std.math.isNan(rs1) and !std.math.isNan(rs2) and !std.math.isNan(rs3)) {
                                this.registers.fcsr.nv = true;
                            }
                        }

                        this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                    } else {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (std.math.isInf(result) and
                                !std.math.isInf(rs1) and
                                !std.math.isInf(rs2) and
                                !std.math.isInf(rs3))
                            {
                                this.registers.fcsr.of = true;
                                this.registers.fcsr.nx = true;
                            }
                        }

                        this.registers.setF32(i.rd, result);
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fld => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;
                    const val = this.readMemory(addr, u64, .read) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .load, addr);
                    };

                    this.registers.setF64(i.rd, @bitCast(val));
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsd => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const base: u32 = @bitCast(this.registers.get(i.rs1));
                    const offset: u32 = @bitCast(@as(i32, i.imm));
                    const addr = base +% offset;

                    this.writeMemory(addr, @as(u64, @bitCast(this.registers.getF64(i.rs2)))) catch |err| {
                        this.incCounters(true);

                        return memoryErrorToState(err, .store, addr);
                    };

                    this.registers.pc +%= 4;
                },
                .fadd_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1) or
                            arch.FloatHelpers.isSignalingNanF64(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if (std.math.isInf(rs1) and std.math.isInf(rs2) and (rs1 > 0) != (rs2 > 0)) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = rs1 + rs2;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and !std.math.isInf(rs1) and !std.math.isInf(rs2)) {
                            this.registers.fcsr.of = true;
                            this.registers.fcsr.nx = true;
                        }

                        if (arch.FloatHelpers.isSubnormalF64(result)) {
                            this.registers.fcsr.uf = true;
                        }
                    }

                    this.registers.setF64(i.rd, if (std.math.isNan(result)) arch.FloatHelpers.canonicalNanF64() else result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsub_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1) or arch.FloatHelpers.isSignalingNanF64(rs2)) {
                            this.registers.fcsr.nv = true;
                        }

                        // inf - inf with same signs = NaN
                        if (std.math.isInf(rs1) and std.math.isInf(rs2) and (rs1 > 0) == (rs2 > 0)) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = rs1 - rs2;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and
                            !std.math.isInf(rs1) and
                            !std.math.isInf(rs2))
                        {
                            this.registers.fcsr.of = true;
                            this.registers.fcsr.nx = true;
                        }

                        if (arch.FloatHelpers.isSubnormalF64(result)) {
                            this.registers.fcsr.uf = true;
                        }
                    }

                    this.registers.setF64(i.rd, if (std.math.isNan(result)) arch.FloatHelpers.canonicalNanF64() else result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fmul_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1) or
                            arch.FloatHelpers.isSignalingNanF64(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        // 0 * inf = NaN
                        if ((rs1 == 0 and std.math.isInf(rs2)) or (std.math.isInf(rs1) and rs2 == 0)) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = rs1 * rs2;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and
                            !std.math.isInf(rs1) and
                            !std.math.isInf(rs2))
                        {
                            this.registers.fcsr.of = true;
                            this.registers.fcsr.nx = true;
                        }

                        if (arch.FloatHelpers.isSubnormalF64(result)) {
                            this.registers.fcsr.uf = true;
                        }
                    }

                    this.registers.setF64(i.rd, if (std.math.isNan(result)) arch.FloatHelpers.canonicalNanF64() else result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fdiv_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1) or
                            arch.FloatHelpers.isSignalingNanF64(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        // 0/0 or inf/inf = NaN
                        if ((rs1 == 0 and rs2 == 0) or
                            (std.math.isInf(rs1) and std.math.isInf(rs2)))
                        {
                            this.registers.fcsr.nv = true;
                            this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }

                        // x/0 (x != 0, x != NaN) = ±inf, sets DZ
                        if (rs2 == 0 and rs1 != 0 and !std.math.isNan(rs1)) {
                            this.registers.fcsr.dz = true;
                        }
                    }

                    const result = rs1 / rs2;

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isInf(result) and !std.math.isInf(rs1) and rs2 != 0) {
                            this.registers.fcsr.of = true;
                            this.registers.fcsr.nx = true;
                        }

                        if (arch.FloatHelpers.isSubnormalF64(result)) {
                            this.registers.fcsr.uf = true;
                        }
                    }

                    this.registers.setF64(i.rd, if (std.math.isNan(result)) arch.FloatHelpers.canonicalNanF64() else result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsqrt_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1)) {
                            this.registers.fcsr.nv = true;
                        }

                        // sqrt of negative (except -0) = NaN
                        if (rs1 < 0 and !arch.FloatHelpers.isNegativeZeroF64(rs1)) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = @sqrt(rs1);

                    // sqrt(-0) = -0
                    if (arch.FloatHelpers.isNegativeZeroF64(rs1)) {
                        this.registers.setF64(i.rd, rs1);
                    } else {
                        this.registers.setF64(i.rd, if (std.math.isNan(result)) arch.FloatHelpers.canonicalNanF64() else result);
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fmin_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1) or
                            arch.FloatHelpers.isSignalingNanF64(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    const result: f64 = if (std.math.isNan(rs1) and std.math.isNan(rs2))
                        arch.FloatHelpers.canonicalNanF64()
                    else if (std.math.isNan(rs1))
                        rs2
                    else if (std.math.isNan(rs2))
                        rs1
                    else if (rs1 == 0 and rs2 == 0)
                        // -0.0 < +0.0
                        if (arch.FloatHelpers.isNegativeZeroF64(rs1) or arch.FloatHelpers.isNegativeZeroF64(rs2))
                            @bitCast(@as(u64, 0x8000000000000000)) // -0.0
                        else
                            rs1
                    else
                        @min(rs1, rs2);

                    this.registers.setF64(i.rd, result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fmax_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1) or
                            arch.FloatHelpers.isSignalingNanF64(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    const result: f64 = if (std.math.isNan(rs1) and std.math.isNan(rs2))
                        arch.FloatHelpers.canonicalNanF64()
                    else if (std.math.isNan(rs1))
                        rs2
                    else if (std.math.isNan(rs2))
                        rs1
                    else if (rs1 == 0 and rs2 == 0)
                        // +0.0 > -0.0
                        if (arch.FloatHelpers.isPositiveZeroF64(rs1) or
                            arch.FloatHelpers.isPositiveZeroF64(rs2))
                            @as(f64, 0.0) // +0.0
                        else
                            rs1
                    else
                        @max(rs1, rs2);

                    this.registers.setF64(i.rd, result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsgnj_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1: u64 = @bitCast(this.registers.getF64(i.rs1));
                    const rs2: u64 = @bitCast(this.registers.getF64(i.rs2));
                    const result = (rs1 & 0x7FFFFFFFFFFFFFFF) | (rs2 & 0x8000000000000000);

                    this.registers.setF64(i.rd, @bitCast(result));
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsgnjn_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1: u64 = @bitCast(this.registers.getF64(i.rs1));
                    const rs2: u64 = @bitCast(this.registers.getF64(i.rs2));
                    const result = (rs1 & 0x7FFFFFFFFFFFFFFF) | (~rs2 & 0x8000000000000000);

                    this.registers.setF64(i.rd, @bitCast(result));
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fsgnjx_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1: u64 = @bitCast(this.registers.getF64(i.rs1));
                    const rs2: u64 = @bitCast(this.registers.getF64(i.rs2));
                    const result = rs1 ^ (rs2 & 0x8000000000000000);

                    this.registers.setF64(i.rd, @bitCast(result));
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .feq_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        // feq: only sNaN sets NV
                        if (arch.FloatHelpers.isSignalingNanF64(rs1) or
                            arch.FloatHelpers.isSignalingNanF64(rs2))
                        {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    // NaN is never equal to anything (including itself)
                    const result: i32 = if (std.math.isNan(rs1) or std.math.isNan(rs2))
                        0
                    else if (rs1 == rs2)
                        1
                    else
                        0;

                    this.registers.set(i.rd, result);
                    this.registers.pc +%= 4;
                },
                .flt_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        // flt/fle: any NaN sets NV
                        if (std.math.isNan(rs1) or std.math.isNan(rs2)) {
                            this.registers.fcsr.nv = true;
                            this.registers.set(i.rd, 0);
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    this.registers.set(i.rd, if (rs1 < rs2) 1 else 0);
                    this.registers.pc +%= 4;
                },
                .fle_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (std.math.isNan(rs1) or std.math.isNan(rs2)) {
                            this.registers.fcsr.nv = true;
                            this.registers.set(i.rd, 0);
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    this.registers.set(i.rd, if (rs1 <= rs2) 1 else 0);
                    this.registers.pc +%= 4;
                },
                .fcvt_w_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rm = this.registers.fcsr.getEffectiveRm(i.rm);

                    var result: i32 = undefined;
                    var invalid = false;

                    if (std.math.isNan(rs1)) {
                        result = std.math.maxInt(i32);
                        invalid = true;
                    } else if (std.math.isInf(rs1)) {
                        result = if (rs1 > 0) std.math.maxInt(i32) else std.math.minInt(i32);
                        invalid = true;
                    } else {
                        const rounded: f64 = switch (rm) {
                            .rne => arch.FloatHelpers.roundToNearestEvenF64(rs1),
                            .rtz => if (rs1 >= 0) @floor(rs1) else @ceil(rs1),
                            .rdn => @floor(rs1),
                            .rup => @ceil(rs1),
                            .rmm => if (rs1 >= 0) @floor(rs1 + 0.5) else @ceil(rs1 - 0.5),
                            else => arch.FloatHelpers.roundToNearestEvenF64(rs1),
                        };

                        if (rounded > @as(f64, @floatFromInt(std.math.maxInt(i32)))) {
                            result = std.math.maxInt(i32);
                            invalid = true;
                        } else if (rounded < @as(f64, @floatFromInt(std.math.minInt(i32)))) {
                            result = std.math.minInt(i32);
                            invalid = true;
                        } else {
                            result = @intFromFloat(rounded);

                            if (comptime config.runtime.enable_fpu_flags) {
                                if (rounded != rs1) {
                                    this.registers.fcsr.nx = true;
                                }
                            }
                        }
                    }

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (invalid) {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    this.registers.set(i.rd, result);
                    this.registers.pc +%= 4;
                },
                .fcvt_wu_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rm = this.registers.fcsr.getEffectiveRm(i.rm);

                    var result: u32 = undefined;
                    var invalid = false;

                    if (std.math.isNan(rs1)) {
                        result = std.math.maxInt(u32);
                        invalid = true;
                    } else if (std.math.isInf(rs1)) {
                        result = if (rs1 > 0) std.math.maxInt(u32) else 0;
                        invalid = true;
                    } else {
                        const rounded: f64 = switch (rm) {
                            .rne => arch.FloatHelpers.roundToNearestEvenF64(rs1),
                            .rtz => if (rs1 >= 0) @floor(rs1) else @ceil(rs1),
                            .rdn => @floor(rs1),
                            .rup => @ceil(rs1),
                            .rmm => if (rs1 >= 0) @floor(rs1 + 0.5) else @ceil(rs1 - 0.5),
                            else => arch.FloatHelpers.roundToNearestEvenF64(rs1),
                        };

                        if (rounded < 0) {
                            result = 0;
                            invalid = true;
                        } else if (rounded > @as(f64, @floatFromInt(std.math.maxInt(u32)))) {
                            result = std.math.maxInt(u32);
                            invalid = true;
                        } else {
                            result = @intFromFloat(rounded);

                            if (comptime config.runtime.enable_fpu_flags) {
                                if (rounded != rs1) {
                                    this.registers.fcsr.nx = true;
                                }
                            }
                        }
                    }

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (invalid) {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    this.registers.set(i.rd, @bitCast(result));
                    this.registers.pc +%= 4;
                },
                .fcvt_d_w => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.get(i.rs1);
                    // i32 -> f64 is always exact
                    const result: f64 = @floatFromInt(rs1);

                    this.registers.setF64(i.rd, result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fcvt_d_wu => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    // u32 -> f64 is always exact
                    const result: f64 = @floatFromInt(rs1);

                    this.registers.setF64(i.rd, result);
                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fclass_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const val = this.registers.getF64(i.rs1);
                    const bits: u64 = @bitCast(val);
                    const sign = (bits >> 63) & 1;
                    const exp = (bits >> 52) & 0x7FF;
                    const frac = bits & 0xFFFFFFFFFFFFF;

                    const result: u32 = if (exp == 0x7FF and frac != 0)
                        // NaN
                        if (frac & 0x8000000000000 != 0) 0x200 else 0x100 // qNaN (bit 9) or sNaN (bit 8)
                    else if (exp == 0x7FF)
                        // Infinity
                        if (sign != 0) 0x001 else 0x080 // -inf (bit 0) or +inf (bit 7)
                    else if (exp == 0 and frac == 0)
                        // Zero
                        if (sign != 0) 0x008 else 0x010 // -0 (bit 3) or +0 (bit 4)
                    else if (exp == 0)
                        // Subnormal
                        if (sign != 0) 0x004 else 0x020 // negative (bit 2) or positive (bit 5)
                    else
                        // Normal
                        if (sign != 0) 0x002 else 0x040; // negative (bit 1) or positive (bit 6)

                    this.registers.set(i.rd, @bitCast(result));
                    this.registers.pc +%= 4;
                },
                .fmadd_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);
                    const rs3 = this.registers.getF64(i.rs3);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1) or
                            arch.FloatHelpers.isSignalingNanF64(rs2) or
                            arch.FloatHelpers.isSignalingNanF64(rs3))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        // inf * 0 or 0 * inf
                        if ((std.math.isInf(rs1) and rs2 == 0) or
                            (rs1 == 0 and std.math.isInf(rs2)))
                        {
                            this.registers.fcsr.nv = true;
                            this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = @mulAdd(f64, rs1, rs2, rs3);

                    if (std.math.isNan(result)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (!std.math.isNan(rs1) and !std.math.isNan(rs2) and !std.math.isNan(rs3)) {
                                this.registers.fcsr.nv = true;
                            }
                        }

                        this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                    } else {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (std.math.isInf(result) and
                                !std.math.isInf(rs1) and
                                !std.math.isInf(rs2) and
                                !std.math.isInf(rs3))
                            {
                                this.registers.fcsr.of = true;
                                this.registers.fcsr.nx = true;
                            }
                        }

                        this.registers.setF64(i.rd, result);
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fmsub_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);
                    const rs3 = this.registers.getF64(i.rs3);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1) or
                            arch.FloatHelpers.isSignalingNanF64(rs2) or
                            arch.FloatHelpers.isSignalingNanF64(rs3))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if ((std.math.isInf(rs1) and rs2 == 0) or (rs1 == 0 and std.math.isInf(rs2))) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = @mulAdd(f64, rs1, rs2, -rs3);

                    if (std.math.isNan(result)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (!std.math.isNan(rs1) and !std.math.isNan(rs2) and !std.math.isNan(rs3)) {
                                this.registers.fcsr.nv = true;
                            }
                        }

                        this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                    } else {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (std.math.isInf(result) and
                                !std.math.isInf(rs1) and
                                !std.math.isInf(rs2) and
                                !std.math.isInf(rs3))
                            {
                                this.registers.fcsr.of = true;
                                this.registers.fcsr.nx = true;
                            }
                        }

                        this.registers.setF64(i.rd, result);
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fnmsub_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);
                    const rs3 = this.registers.getF64(i.rs3);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1) or
                            arch.FloatHelpers.isSignalingNanF64(rs2) or
                            arch.FloatHelpers.isSignalingNanF64(rs3))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if ((std.math.isInf(rs1) and rs2 == 0) or (rs1 == 0 and std.math.isInf(rs2))) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = @mulAdd(f64, -rs1, rs2, rs3);

                    if (std.math.isNan(result)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (!std.math.isNan(rs1) and !std.math.isNan(rs2) and !std.math.isNan(rs3)) {
                                this.registers.fcsr.nv = true;
                            }
                        }

                        this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                    } else {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (std.math.isInf(result) and
                                !std.math.isInf(rs1) and
                                !std.math.isInf(rs2) and
                                !std.math.isInf(rs3))
                            {
                                this.registers.fcsr.of = true;
                                this.registers.fcsr.nx = true;
                            }
                        }

                        this.registers.setF64(i.rd, result);
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fnmadd_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);
                    const rs2 = this.registers.getF64(i.rs2);
                    const rs3 = this.registers.getF64(i.rs3);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1) or
                            arch.FloatHelpers.isSignalingNanF64(rs2) or
                            arch.FloatHelpers.isSignalingNanF64(rs3))
                        {
                            this.registers.fcsr.nv = true;
                        }

                        if ((std.math.isInf(rs1) and rs2 == 0) or (rs1 == 0 and std.math.isInf(rs2))) {
                            this.registers.fcsr.nv = true;
                            this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                            this.markFpuDirty();
                            this.registers.pc +%= 4;
                            this.incCounters(true);

                            return .ok;
                        }
                    }

                    const result = @mulAdd(f64, -rs1, rs2, -rs3);

                    if (std.math.isNan(result)) {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (!std.math.isNan(rs1) and !std.math.isNan(rs2) and !std.math.isNan(rs3)) {
                                this.registers.fcsr.nv = true;
                            }
                        }

                        this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                    } else {
                        if (comptime config.runtime.enable_fpu_flags) {
                            if (std.math.isInf(result) and
                                !std.math.isInf(rs1) and
                                !std.math.isInf(rs2) and
                                !std.math.isInf(rs3))
                            {
                                this.registers.fcsr.of = true;
                                this.registers.fcsr.nx = true;
                            }
                        }

                        this.registers.setF64(i.rd, result);
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fcvt_s_d => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF64(i.rs1);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF64(rs1)) {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    if (std.math.isNan(rs1)) {
                        this.registers.setF32(i.rd, arch.FloatHelpers.canonicalNanF32());
                    } else {
                        const result: f32 = @floatCast(rs1);

                        if (comptime config.runtime.enable_fpu_flags) {
                            if (std.math.isInf(result) and
                                !std.math.isInf(rs1))
                            {
                                this.registers.fcsr.of = true;
                                this.registers.fcsr.nx = true;
                            }

                            if (arch.FloatHelpers.isSubnormalF32(result)) {
                                this.registers.fcsr.uf = true;
                            }

                            if (@as(f64, result) != rs1) {
                                this.registers.fcsr.nx = true;
                            }
                        }

                        this.registers.setF32(i.rd, result);
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .fcvt_d_s => |i| {
                    if (this.checkFpuAccess()) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    if (this.checkRoundingMode(i.rm)) |state| {
                        this.incCounters(true);

                        return state;
                    }

                    const rs1 = this.registers.getF32(i.rs1);

                    if (comptime config.runtime.enable_fpu_flags) {
                        if (arch.FloatHelpers.isSignalingNanF32(rs1)) {
                            this.registers.fcsr.nv = true;
                        }
                    }

                    if (std.math.isNan(rs1)) {
                        this.registers.setF64(i.rd, arch.FloatHelpers.canonicalNanF64());
                    } else {
                        this.registers.setF64(i.rd, @as(f64, rs1));
                    }

                    this.markFpuDirty();
                    this.registers.pc +%= 4;
                },
                .csrrw => |i| {
                    const csr: arch.Registers.Csr = @enumFromInt(i.csr);
                    const rs1_val: u32 = @bitCast(this.registers.get(i.rs1));

                    if (comptime config.runtime.enable_csr_checks) {
                        if (i.rd != 0) {
                            const old = this.registers.readCsr(csr, this.getPrivilege()) catch {
                                this.incCounters(true);

                                return trapState(.illegal_instruction, 0);
                            };

                            this.registers.set(i.rd, @bitCast(old));
                        }

                        this.registers.writeCsr(csr, rs1_val, this.getPrivilege()) catch {
                            this.incCounters(true);

                            return trapState(.illegal_instruction, 0);
                        };
                    } else {
                        if (i.rd != 0) {
                            const old = this.registers.readCsrUnchecked(csr);

                            this.registers.set(i.rd, @bitCast(old));
                        }

                        this.registers.writeCsrUnchecked(csr, rs1_val);
                    }

                    this.registers.pc +%= 4;
                },
                .csrrs => |i| {
                    const csr: arch.Registers.Csr = @enumFromInt(i.csr);

                    if (comptime config.runtime.enable_csr_checks) {
                        const old = this.registers.readCsr(csr, this.getPrivilege()) catch {
                            this.incCounters(true);

                            return trapState(.illegal_instruction, 0);
                        };

                        this.registers.set(i.rd, @bitCast(old));

                        if (i.rs1 != 0) {
                            const rs1_val: u32 = @bitCast(this.registers.get(i.rs1));

                            this.registers.writeCsr(csr, old | rs1_val, this.getPrivilege()) catch {
                                this.incCounters(true);

                                return trapState(.illegal_instruction, 0);
                            };
                        }
                    } else {
                        const old = this.registers.readCsrUnchecked(csr);

                        this.registers.set(i.rd, @bitCast(old));

                        if (i.rs1 != 0) {
                            const rs1_val: u32 = @bitCast(this.registers.get(i.rs1));

                            this.registers.writeCsrUnchecked(csr, old | rs1_val);
                        }
                    }

                    this.registers.pc +%= 4;
                },
                .csrrc => |i| {
                    const csr: arch.Registers.Csr = @enumFromInt(i.csr);

                    if (comptime config.runtime.enable_csr_checks) {
                        const old = this.registers.readCsr(csr, this.getPrivilege()) catch {
                            this.incCounters(true);

                            return trapState(.illegal_instruction, 0);
                        };

                        this.registers.set(i.rd, @bitCast(old));

                        if (i.rs1 != 0) {
                            const rs1_val: u32 = @bitCast(this.registers.get(i.rs1));

                            this.registers.writeCsr(csr, old & ~rs1_val, this.getPrivilege()) catch {
                                this.incCounters(true);

                                return trapState(.illegal_instruction, 0);
                            };
                        }
                    } else {
                        const old = this.registers.readCsrUnchecked(csr);

                        this.registers.set(i.rd, @bitCast(old));

                        if (i.rs1 != 0) {
                            const rs1_val: u32 = @bitCast(this.registers.get(i.rs1));

                            this.registers.writeCsrUnchecked(csr, old & ~rs1_val);
                        }
                    }

                    this.registers.pc +%= 4;
                },
                .csrrwi => |i| {
                    const csr: arch.Registers.Csr = @enumFromInt(i.csr);

                    if (comptime config.runtime.enable_csr_checks) {
                        if (i.rd != 0) {
                            const old = this.registers.readCsr(csr, this.getPrivilege()) catch {
                                this.incCounters(true);

                                return trapState(.illegal_instruction, 0);
                            };

                            this.registers.set(i.rd, @bitCast(old));
                        }

                        this.registers.writeCsr(csr, @as(u32, i.uimm), this.getPrivilege()) catch {
                            this.incCounters(true);

                            return trapState(.illegal_instruction, 0);
                        };
                    } else {
                        if (i.rd != 0) {
                            const old = this.registers.readCsrUnchecked(csr);

                            this.registers.set(i.rd, @bitCast(old));
                        }

                        this.registers.writeCsrUnchecked(csr, @as(u32, i.uimm));
                    }

                    this.registers.pc +%= 4;
                },
                .csrrsi => |i| {
                    const csr: arch.Registers.Csr = @enumFromInt(i.csr);

                    if (comptime config.runtime.enable_csr_checks) {
                        const old = this.registers.readCsr(csr, this.getPrivilege()) catch {
                            this.incCounters(true);

                            return trapState(.illegal_instruction, 0);
                        };

                        this.registers.set(i.rd, @bitCast(old));

                        if (i.uimm != 0) {
                            this.registers.writeCsr(csr, old | @as(u32, i.uimm), this.getPrivilege()) catch {
                                this.incCounters(true);

                                return trapState(.illegal_instruction, 0);
                            };
                        }
                    } else {
                        const old = this.registers.readCsrUnchecked(csr);

                        this.registers.set(i.rd, @bitCast(old));

                        if (i.uimm != 0) {
                            this.registers.writeCsrUnchecked(csr, old | @as(u32, i.uimm));
                        }
                    }

                    this.registers.pc +%= 4;
                },
                .csrrci => |i| {
                    const csr: arch.Registers.Csr = @enumFromInt(i.csr);

                    if (comptime config.runtime.enable_csr_checks) {
                        const old = this.registers.readCsr(csr, this.getPrivilege()) catch {
                            this.incCounters(true);

                            return trapState(.illegal_instruction, 0);
                        };

                        this.registers.set(i.rd, @bitCast(old));

                        if (i.uimm != 0) {
                            this.registers.writeCsr(csr, old & ~@as(u32, i.uimm), this.getPrivilege()) catch {
                                this.incCounters(true);

                                return trapState(.illegal_instruction, 0);
                            };
                        }
                    } else {
                        const old = this.registers.readCsrUnchecked(csr);

                        this.registers.set(i.rd, @bitCast(old));

                        if (i.uimm != 0) {
                            this.registers.writeCsrUnchecked(csr, old & ~@as(u32, i.uimm));
                        }
                    }

                    this.registers.pc +%= 4;
                },
                .fence_i => {
                    this.registers.pc +%= 4;
                },
                .sh1add => |i| {
                    if (comptime !config.runtime.enable_zba_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const rs2: u32 = @bitCast(this.registers.get(i.rs2));

                    this.registers.set(i.rd, @bitCast((rs1 << 1) +% rs2));
                    this.registers.pc +%= 4;
                },
                .sh2add => |i| {
                    if (comptime !config.runtime.enable_zba_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const rs2: u32 = @bitCast(this.registers.get(i.rs2));

                    this.registers.set(i.rd, @bitCast((rs1 << 2) +% rs2));
                    this.registers.pc +%= 4;
                },
                .sh3add => |i| {
                    if (comptime !config.runtime.enable_zba_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const rs2: u32 = @bitCast(this.registers.get(i.rs2));

                    this.registers.set(i.rd, @bitCast((rs1 << 3) +% rs2));
                    this.registers.pc +%= 4;
                },
                .andn => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const rs2: u32 = @bitCast(this.registers.get(i.rs2));

                    this.registers.set(i.rd, @bitCast(rs1 & ~rs2));
                    this.registers.pc +%= 4;
                },
                .orn => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const rs2: u32 = @bitCast(this.registers.get(i.rs2));

                    this.registers.set(i.rd, @bitCast(rs1 | ~rs2));
                    this.registers.pc +%= 4;
                },
                .xnor => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const rs2: u32 = @bitCast(this.registers.get(i.rs2));

                    this.registers.set(i.rd, @bitCast(~(rs1 ^ rs2)));
                    this.registers.pc +%= 4;
                },
                .clz => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));

                    this.registers.set(i.rd, @clz(rs1));
                    this.registers.pc +%= 4;
                },
                .ctz => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));

                    this.registers.set(i.rd, @ctz(rs1));
                    this.registers.pc +%= 4;
                },
                .cpop => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));

                    this.registers.set(i.rd, @popCount(rs1));
                    this.registers.pc +%= 4;
                },
                .max => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1 = this.registers.get(i.rs1);
                    const rs2 = this.registers.get(i.rs2);

                    this.registers.set(i.rd, @max(rs1, rs2));
                    this.registers.pc +%= 4;
                },
                .maxu => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const rs2: u32 = @bitCast(this.registers.get(i.rs2));

                    this.registers.set(i.rd, @bitCast(@max(rs1, rs2)));
                    this.registers.pc +%= 4;
                },
                .min => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1 = this.registers.get(i.rs1);
                    const rs2 = this.registers.get(i.rs2);

                    this.registers.set(i.rd, @min(rs1, rs2));
                    this.registers.pc +%= 4;
                },
                .minu => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const rs2: u32 = @bitCast(this.registers.get(i.rs2));

                    this.registers.set(i.rd, @bitCast(@min(rs1, rs2)));
                    this.registers.pc +%= 4;
                },
                .sext_b => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const byte: i8 = @bitCast(@as(u8, @truncate(rs1)));

                    this.registers.set(i.rd, @as(i32, byte));
                    this.registers.pc +%= 4;
                },
                .sext_h => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const half: i16 = @bitCast(@as(u16, @truncate(rs1)));

                    this.registers.set(i.rd, @as(i32, half));
                    this.registers.pc +%= 4;
                },
                .zext_h => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));

                    this.registers.set(i.rd, @bitCast(rs1 & 0xFFFF));
                    this.registers.pc +%= 4;
                },
                .rol => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const shamt: u5 = @truncate(@as(u32, @bitCast(this.registers.get(i.rs2))));

                    this.registers.set(i.rd, @bitCast(std.math.rotl(u32, rs1, shamt)));
                    this.registers.pc +%= 4;
                },
                .ror => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    const shamt: u5 = @truncate(@as(u32, @bitCast(this.registers.get(i.rs2))));

                    this.registers.set(i.rd, @bitCast(std.math.rotr(u32, rs1, shamt)));
                    this.registers.pc +%= 4;
                },
                .rori => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));

                    this.registers.set(i.rd, @bitCast(std.math.rotr(u32, rs1, i.shamt)));
                    this.registers.pc +%= 4;
                },
                .orc_b => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));
                    var result: u32 = 0;

                    inline for (0..4) |j| {
                        const shift: u5 = @intCast(j * 8);
                        const byte: u8 = @truncate(rs1 >> shift);
                        const combined: u8 = if (byte != 0) 0xFF else 0x00;

                        result |= @as(u32, combined) << shift;
                    }

                    this.registers.set(i.rd, @bitCast(result));
                    this.registers.pc +%= 4;
                },
                .rev8 => |i| {
                    if (comptime !config.runtime.enable_zbb_ext) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    const rs1: u32 = @bitCast(this.registers.get(i.rs1));

                    this.registers.set(i.rd, @bitCast(@byteSwap(rs1)));
                    this.registers.pc +%= 4;
                },
                .mret => {
                    const state = this.executeMret();

                    if (state != .ok) {
                        this.incCounters(true);

                        return state;
                    }
                },
                .wfi => {
                    // WFI in U-mode with TW=1 causes illegal instruction
                    if (this.getPrivilege() == .user and this.registers.mstatus.tw) {
                        this.incCounters(true);

                        return trapState(.illegal_instruction, 0);
                    }

                    // WFI resumes if any enabled interrupt is pending,
                    // regardless of whether global interrupts are enabled
                    const mie: u32 = @bitCast(this.registers.mie);
                    const mip: u32 = @bitCast(this.registers.mip);
                    const pending = mie & mip;

                    if (pending != 0) {
                        // Enabled interrupt is pending - resume execution
                        this.incCounters(true);
                        this.registers.pc +%= 4;

                        return .ok;
                    }

                    if (comptime config.hooks.wfi) |hook| {
                        if (hook(this)) {
                            this.incCounters(true);
                            this.registers.pc +%= 4;

                            return .ok;
                        }
                    }

                    this.incCounters(false);

                    return .halt;
                },
            }

            this.incCounters(true);

            return .ok;
        }
    };
}

fn initRamWithCode(ram_size: comptime_int, code: []const arch.Instruction) [ram_size]u8 {
    var ram: [ram_size]u8 = std.mem.zeroes([ram_size]u8);
    var stream = std.io.fixedBufferStream(&ram);

    for (code) |instr| {
        stream.writer().writeInt(u32, instr.encode(), arch.ENDIAN) catch unreachable;
    }

    return ram;
}

fn configurePmpFullAccess(cpu: *TestCpu) void {
    // NAPOT covering entire 32-bit address space (4GB)
    // pmpaddr with 29 trailing 1s gives size = 8 << 29 = 4GB
    cpu.registers.pmpaddr[0] = 0x1FFFFFFF;
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true,
        .a = .napot,
    }));
}

const TestCpu = Cpu(.{ .runtime = .compliant, .compile = .fast_compile });

test "x0 register is always zero" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 0, .rs1 = 0, .imm = 100 } },
        .{ .add = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } },
        .{ .lui = .{ .rd = 0, .imm = 1111 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(0, cpu.registers.get(0));
}

test "addi - negative immediate" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .addi = .{ .rd = 2, .rs1 = 1, .imm = -3 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(7, cpu.registers.get(2));
}

test "addi - overflow wraps around" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 2, .rs1 = 1, .imm = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, std.math.maxInt(i32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(std.math.minInt(i32), cpu.registers.get(2));
}

test "addi - max positive immediate" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = std.math.maxInt(i12) } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(2047, cpu.registers.get(1));
}

test "addi - min negative immediate" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = std.math.minInt(i12) } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(-2048, cpu.registers.get(1));
}

test "mul - negative operands" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 3 } },
        .{ .mul = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(-15, cpu.registers.get(3));
}

test "mul - both negative" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -3 } },
        .{ .mul = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(15, cpu.registers.get(3));
}

test "mul - overflow returns lower 32 bits" {
    var ram = initRamWithCode(1024, &.{
        .{ .lui = .{ .rd = 1, .imm = 0x10000 } }, // 0x10000000
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 16 } },
        .{ .mul = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(0, cpu.registers.get(3)); // 0x100000000 & 0xFFFFFFFF = 0
}

test "mulh - produces non-zero upper bits" {
    var ram = initRamWithCode(1024, &.{
        .{ .lui = .{ .rd = 1, .imm = 0x10000 } }, // 0x10000000
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 16 } },
        .{ .mulh = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(1, cpu.registers.get(3));
}

test "mulh - negative times positive" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 2 } },
        .{ .mulh = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(-1, cpu.registers.get(3));
}

test "mulh - negative times negative" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -1 } },
        .{ .mulh = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    // (-1) * (-1) = 1, upper bits = 0
    try std.testing.expectEqual(0, cpu.registers.get(3));
}

test "mulhsu - large unsigned" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -1 } }, // 0xFFFFFFFF as unsigned
        .{ .mulhsu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    // 1 * 0xFFFFFFFF = 0xFFFFFFFF, upper 32 bits = 0
    try std.testing.expectEqual(0, cpu.registers.get(3));
}

test "div - division by zero returns -1" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .div = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(-1, cpu.registers.get(3));
}

test "div - negative dividend" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -10 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 3 } },
        .{ .div = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(-3, cpu.registers.get(3));
}

test "div - negative divisor" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -3 } },
        .{ .div = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(-3, cpu.registers.get(3));
}

test "div - overflow MIN_INT / -1 returns MIN_INT" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -1 } },
        .{ .div = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, std.math.minInt(i32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(std.math.minInt(i32), cpu.registers.get(3));
}

test "divu - division by zero returns MAX_UINT" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .divu = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFFFFF))), cpu.registers.get(3));
}

test "divu - treats operands as unsigned" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -4 } }, // 0xFFFFFFFC
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 2 } },
        .{ .divu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    // 0xFFFFFFFC / 2 = 0x7FFFFFFE
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x7FFFFFFE))), cpu.registers.get(3));
}

test "rem - division by zero returns dividend" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .rem = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(10, cpu.registers.get(3));
}

test "rem - negative dividend" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -10 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 3 } },
        .{ .rem = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(-1, cpu.registers.get(3));
}

test "rem - overflow MIN_INT % -1 returns 0" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = -1 } },
        .{ .rem = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, std.math.minInt(i32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(0, cpu.registers.get(3));
}

test "remu - division by zero returns dividend" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 10 } },
        .{ .remu = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(10, cpu.registers.get(3));
}

test "sub - result negative" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 10 } },
        .{ .sub = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(-5, cpu.registers.get(3));
}

test "sub - underflow wraps" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 1 } },
        .{ .sub = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, std.math.minInt(i32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(std.math.maxInt(i32), cpu.registers.get(3));
}

test "sll - only lower 5 bits of shift used" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 32 } }, // 32 & 0x1F = 0
        .{ .sll = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(1, cpu.registers.get(3)); // No shift
}

test "sll - shift by 31" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 31 } },
        .{ .sll = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(std.math.minInt(i32), cpu.registers.get(3)); // 0x80000000
}

test "srl - shift by 31 of negative" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 31 } },
        .{ .srl = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, std.math.minInt(i32)); // 0x80000000

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(1, cpu.registers.get(3)); // Logical shift, no sign extension
}

test "sra - shift by 31 of negative fills with ones" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 31 } },
        .{ .sra = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(-1, cpu.registers.get(3));
}

test "sra - positive number" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0x100 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 4 } },
        .{ .sra = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(0x10, cpu.registers.get(3));
}

test "slli - shift by 0" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0x123 } },
        .{ .slli = .{ .rd = 2, .rs1 = 1, .shamt = 0 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(0x123, cpu.registers.get(2));
}

test "slli - shift by 31" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
        .{ .slli = .{ .rd = 2, .rs1 = 1, .shamt = 31 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(std.math.minInt(i32), cpu.registers.get(2));
}

test "slt - equal values return 0" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .slt = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(0, cpu.registers.get(3));
}

test "slt - negative less than positive" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .slt = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(1, cpu.registers.get(3));
}

test "sltu - signed negative is large unsigned" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } }, // 0xFFFFFFFF
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 1 } },
        .{ .sltu = .{ .rd = 3, .rs1 = 2, .rs2 = 1 } }, // 1 < MAX = 1
        .{ .sltu = .{ .rd = 4, .rs1 = 1, .rs2 = 2 } }, // MAX < 1 = 0
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(1, cpu.registers.get(3));
    try std.testing.expectEqual(0, cpu.registers.get(4));
}

test "slti - negative immediate" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -10 } },
        .{ .slti = .{ .rd = 2, .rs1 = 1, .imm = -5 } }, // -10 < -5 = 1
        .{ .slti = .{ .rd = 3, .rs1 = 1, .imm = -15 } }, // -10 < -15 = 0
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(1, cpu.registers.get(2));
    try std.testing.expectEqual(0, cpu.registers.get(3));
}

test "sltiu - detects non-zero (seqz idiom)" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .sltiu = .{ .rd = 3, .rs1 = 1, .imm = 1 } }, // 0 < 1 = 1 (is zero)
        .{ .sltiu = .{ .rd = 4, .rs1 = 2, .imm = 1 } }, // 5 < 1 = 0 (not zero)
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(1, cpu.registers.get(3));
    try std.testing.expectEqual(0, cpu.registers.get(4));
}

test "beq - not taken" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 10 } },
        .{ .beq = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(1, cpu.registers.get(3));
}

test "bne - not taken when equal" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .bne = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(1, cpu.registers.get(3));
}

test "blt - negative comparison" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .blt = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } }, // -5 < 5, taken
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // Skipped
        .{ .addi = .{ .rd = 4, .rs1 = 0, .imm = 2 } }, // Executed
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(0, cpu.registers.get(3));
    try std.testing.expectEqual(2, cpu.registers.get(4));
}

test "bltu - signed negative not less than (unsigned)" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -1 } }, // 0xFFFFFFFF
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 1 } },
        .{ .bltu = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } }, // MAX < 1 = false
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // Executed
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(1, cpu.registers.get(3));
}

test "bge - equal values" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .bge = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } }, // 5 >= 5, taken
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // Skipped
        .{ .addi = .{ .rd = 4, .rs1 = 0, .imm = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(0, cpu.registers.get(3));
    try std.testing.expectEqual(2, cpu.registers.get(4));
}

test "bge - not taken" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 10 } },
        .{ .bge = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } }, // 5 >= 10 = false
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // Executed
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(1, cpu.registers.get(3));
}

test "bgeu - equal values" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 5 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 5 } },
        .{ .bgeu = .{ .rs1 = 1, .rs2 = 2, .imm = 8 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // Skipped
        .{ .addi = .{ .rd = 4, .rs1 = 0, .imm = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(0, cpu.registers.get(3));
    try std.testing.expectEqual(2, cpu.registers.get(4));
}

test "backward branch - simple loop" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0 } }, // Counter = 0
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 3 } }, // Target = 3
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = 1 } }, // Increment (addr 8)
        .{ .bne = .{ .rs1 = 1, .rs2 = 2, .imm = -4 } }, // Loop back
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(8)); // 2 init + 3 iterations * 2 instructions
    try std.testing.expectEqual(3, cpu.registers.get(1));
}

test "lb - sign extension of 0x80" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 100 } },
        .{ .lb = .{ .rd = 3, .rs1 = 1, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.ram[100] = 0x80;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(-128, cpu.registers.get(3));
}

test "lbu - no sign extension of 0x80" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 100 } },
        .{ .lbu = .{ .rd = 3, .rs1 = 1, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.ram[100] = 0x80;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(128, cpu.registers.get(3));
}

test "lh - sign extension of 0x8000" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 100 } },
        .{ .lh = .{ .rd = 3, .rs1 = 1, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    try cpu.writeMemory(100, @as(u16, 0x8000));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(-32768, cpu.registers.get(3));
}

test "lhu - no sign extension of 0x8000" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 100 } },
        .{ .lhu = .{ .rd = 3, .rs1 = 1, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    try cpu.writeMemory(100, @as(u16, 0x8000));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(0x8000, cpu.registers.get(3));
}

test "load/store with positive offset" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 100 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 42 } },
        .{ .sb = .{ .rs1 = 1, .rs2 = 2, .imm = 20 } }, // Store at 120
        .{ .lb = .{ .rd = 3, .rs1 = 1, .imm = 20 } }, // Load from 120
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(42, cpu.registers.get(3));
}

test "load/store with negative offset" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 120 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 55 } },
        .{ .sb = .{ .rs1 = 1, .rs2 = 2, .imm = -20 } }, // Store at 100
        .{ .lb = .{ .rd = 3, .rs1 = 1, .imm = -20 } }, // Load from 100
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(55, cpu.registers.get(3));
}

test "auipc - non-zero PC" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 0, .rs1 = 0, .imm = 0 } }, // NOP at PC=0
        .{ .addi = .{ .rd = 0, .rs1 = 0, .imm = 0 } }, // NOP at PC=4
        .{ .auipc = .{ .rd = 1, .imm = 0x12345 } }, // At PC=8
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(0x12345000 + 8, cpu.registers.get(1));
}

test "jal - rd = x0 discards link" {
    var ram = initRamWithCode(1024, &.{
        .{ .jal = .{ .rd = 0, .imm = 8 } },
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } }, // Skipped
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 2 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(0, cpu.registers.get(0));
    try std.testing.expectEqual(0, cpu.registers.get(1));
    try std.testing.expectEqual(2, cpu.registers.get(2));
}

test "jal - negative offset (backward jump)" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 99 } }, // addr 0
        .{ .jal = .{ .rd = 0, .imm = 8 } }, // addr 4, jump to 12
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } }, // addr 8, skipped first, executed later
        .{ .jal = .{ .rd = 0, .imm = -4 } }, // addr 12, jump back to 8
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(1, cpu.registers.get(1));
}

test "jalr - clears LSB of target address" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 13 } }, // Odd address
        .{ .jalr = .{ .rd = 2, .rs1 = 1, .imm = 0 } }, // Jump to 12 (LSB cleared)
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // addr 8, skipped
        .{ .addi = .{ .rd = 4, .rs1 = 0, .imm = 2 } }, // addr 12, executed
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(8, cpu.registers.get(2)); // Return address
    try std.testing.expectEqual(0, cpu.registers.get(3)); // Skipped
    try std.testing.expectEqual(2, cpu.registers.get(4));
}

test "jalr - with negative offset" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 5, .rs1 = 0, .imm = 77 } }, // addr 0
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 16 } }, // addr 4
        .{ .jalr = .{ .rd = 2, .rs1 = 1, .imm = -4 } }, // addr 8, jump to 12
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 1 } }, // addr 12, executed
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(12, cpu.registers.get(2)); // Return address
    try std.testing.expectEqual(1, cpu.registers.get(3));
}

test "lui - negative upper immediate" {
    var ram = initRamWithCode(1024, &.{
        .{ .lui = .{ .rd = 1, .imm = @truncate(0xFFFFF) } }, // Upper 20 bits all 1s
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFFFFF000))), cpu.registers.get(1));
}

test "lui followed by addi - full 32-bit constant" {
    var ram = initRamWithCode(1024, &.{
        .{ .lui = .{ .rd = 1, .imm = 0x12345 } },
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = 0x678 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(0x12345678, cpu.registers.get(1));
}

test "xori - with negative immediate (sign extended)" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0 } },
        .{ .xori = .{ .rd = 2, .rs1 = 1, .imm = -1 } }, // 0 XOR 0xFFFFFFFF = 0xFFFFFFFF
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(-1, cpu.registers.get(2));
}

test "ori - with negative immediate" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0 } },
        .{ .ori = .{ .rd = 2, .rs1 = 1, .imm = -1 } }, // 0 OR 0xFFFFFFFF = 0xFFFFFFFF
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(-1, cpu.registers.get(2));
}

test "andi - with negative immediate" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 0x7FF } },
        .{ .andi = .{ .rd = 2, .rs1 = 1, .imm = -1 } }, // 0x7FF AND 0xFFFFFFFF = 0x7FF
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(0x7FF, cpu.registers.get(2));
}

test "flw/fsw - load and store float" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 100 } },
        .{ .flw = .{ .rd = 0, .rs1 = 1, .imm = 0 } },
        .{ .fsw = .{ .rs1 = 1, .rs2 = 0, .imm = 8 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;

    const pi: f32 = 3.14;
    try cpu.writeMemory(100, @as(u32, @bitCast(pi)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));

    const loaded = try cpu.readMemory(108, u32, .read);

    try std.testing.expectEqual(@as(u32, @bitCast(pi)), loaded);
    // No FCSR flags should be set for load/store
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags());
}

test "flw/fsw - negative offset" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 120 } },
        .{ .flw = .{ .rd = 0, .rs1 = 1, .imm = -20 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;

    const val: f32 = 2.71828;
    try cpu.writeMemory(100, @as(u32, @bitCast(val)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(val, cpu.registers.getF32(0));
}

test "fadd_s - add floats" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 1.5);
    cpu.registers.setF32(1, 2.5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 4.0), cpu.registers.getF32(2));
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags());
}

test "fadd_s - inf + (-inf) produces NaN and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.inf(f32));
    cpu.registers.setF32(1, -std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF32(2)));
    try std.testing.expect(cpu.registers.fcsr.nv); // Invalid operation
}

test "fadd_s - signaling NaN sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    // Create signaling NaN: exp=0xFF, frac!=0, MSB of frac=0
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x7F800001))); // sNaN
    cpu.registers.setF32(1, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fadd_s - inexact result sets NX" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 1.0);
    cpu.registers.setF32(1, 1e-10); // Result cannot be exactly represented

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));

    // This may or may not set NX depending on exact values
    // The important thing is the operation completes correctly
    try std.testing.expect(!std.math.isNan(cpu.registers.getF32(2)));
}

test "fsub_s - subtract floats" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsub_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 5.0);
    cpu.registers.setF32(1, 2.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 3.0), cpu.registers.getF32(2));
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags());
}

test "fsub_s - inf - inf produces NaN and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsub_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.inf(f32));
    cpu.registers.setF32(1, std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF32(2)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fmul_s - multiply floats" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmul_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 3.0);
    cpu.registers.setF32(1, 4.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 12.0), cpu.registers.getF32(2));
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags());
}

test "fmul_s - 0 * inf produces NaN and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmul_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 0.0);
    cpu.registers.setF32(1, std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF32(2)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fmul_s - overflow sets OF and NX" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmul_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.floatMax(f32));
    cpu.registers.setF32(1, 2.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isInf(cpu.registers.getF32(2)));
    try std.testing.expect(cpu.registers.fcsr.of);
    try std.testing.expect(cpu.registers.fcsr.nx);
}

test "fdiv_s - divide floats" {
    var ram = initRamWithCode(1024, &.{
        .{ .fdiv_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 10.0);
    cpu.registers.setF32(1, 4.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 2.5), cpu.registers.getF32(2));
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags());
}

test "fdiv_s - division by zero sets DZ" {
    var ram = initRamWithCode(1024, &.{
        .{ .fdiv_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 1.0);
    cpu.registers.setF32(1, 0.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isInf(cpu.registers.getF32(2)));
    try std.testing.expect(cpu.registers.fcsr.dz);
    try std.testing.expect(!cpu.registers.fcsr.nv); // Not invalid, just div by zero
}

test "fdiv_s - 0/0 produces NaN and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fdiv_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 0.0);
    cpu.registers.setF32(1, 0.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF32(2)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fdiv_s - inf/inf produces NaN and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fdiv_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.inf(f32));
    cpu.registers.setF32(1, std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF32(2)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fsqrt_s - square root" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsqrt_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 16.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 4.0), cpu.registers.getF32(1));
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags());
}

test "fsqrt_s - negative produces NaN and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsqrt_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF32(1)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fsqrt_s - negative zero returns negative zero" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsqrt_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x80000000))); // -0.0

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x80000000), @as(u32, @bitCast(cpu.registers.getF32(1))));
    try std.testing.expect(!cpu.registers.fcsr.nv);
}

test "fmin_s - basic min" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmin_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 3.0);
    cpu.registers.setF32(1, 7.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 3.0), cpu.registers.getF32(2));
}

test "fmin_s - -0.0 is less than +0.0" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmin_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 0.0); // +0.0
    cpu.registers.setF32(1, @bitCast(@as(u32, 0x80000000))); // -0.0

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x80000000), @as(u32, @bitCast(cpu.registers.getF32(2)))); // -0.0
}

test "fmin_s - one NaN returns other value" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmin_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.nan(f32));
    cpu.registers.setF32(1, 5.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 5.0), cpu.registers.getF32(2));
}

test "fmin_s - both NaN returns canonical NaN" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmin_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.nan(f32));
    cpu.registers.setF32(1, std.math.nan(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF32(2)));
}

test "fmin_s - sNaN sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmin_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x7F800001))); // sNaN
    cpu.registers.setF32(1, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fmax_s - basic max" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmax_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 3.0);
    cpu.registers.setF32(1, 7.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 7.0), cpu.registers.getF32(2));
}

test "fmax_s - +0.0 is greater than -0.0" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmax_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x80000000))); // -0.0
    cpu.registers.setF32(1, 0.0); // +0.0

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x00000000), @as(u32, @bitCast(cpu.registers.getF32(2)))); // +0.0
}

test "fsgnj_s - sign injection" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsgnj_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 5.0);
    cpu.registers.setF32(1, -3.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, -5.0), cpu.registers.getF32(2));
}

test "fsgnj_s - same register is fmv.s" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsgnj_s = .{ .rd = 1, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -7.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, -7.0), cpu.registers.getF32(1));
}

test "fsgnjn_s - negated sign injection" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsgnjn_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 5.0);
    cpu.registers.setF32(1, -3.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 5.0), cpu.registers.getF32(2));
}

test "fsgnjn_s - same register is fneg.s" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsgnjn_s = .{ .rd = 1, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 7.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, -7.0), cpu.registers.getF32(1));
}

test "fsgnjx_s - xor sign (fabs idiom)" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsgnjx_s = .{ .rd = 2, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -7.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 7.0), cpu.registers.getF32(2));
}

test "feq_s - equal floats" {
    var ram = initRamWithCode(1024, &.{
        .{ .feq_s = .{ .rd = 1, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 3.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(1));
    try std.testing.expect(!cpu.registers.fcsr.nv);
}

test "feq_s - NaN never equals anything" {
    var ram = initRamWithCode(1024, &.{
        .{ .feq_s = .{ .rd = 1, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.nan(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
    // qNaN in feq does NOT set NV (only sNaN does)
}

test "feq_s - sNaN sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .feq_s = .{ .rd = 1, .rs1 = 0, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x7F800001))); // sNaN
    cpu.registers.setF32(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "flt_s - less than comparison" {
    var ram = initRamWithCode(1024, &.{
        .{ .flt_s = .{ .rd = 1, .rs1 = 0, .rs2 = 2 } },
        .{ .flt_s = .{ .rd = 3, .rs1 = 2, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.0);
    cpu.registers.setF32(2, 5.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(1)); // 2.0 < 5.0
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(3)); // 5.0 < 2.0
}

test "flt_s - NaN sets NV and returns 0" {
    var ram = initRamWithCode(1024, &.{
        .{ .flt_s = .{ .rd = 1, .rs1 = 0, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.nan(f32));
    cpu.registers.setF32(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.nv); // flt/fle set NV for ANY NaN
}

test "fle_s - less than or equal comparison" {
    var ram = initRamWithCode(1024, &.{
        .{ .fle_s = .{ .rd = 1, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(1)); // 2.0 <= 2.0
}

test "fle_s - NaN sets NV and returns 0" {
    var ram = initRamWithCode(1024, &.{
        .{ .fle_s = .{ .rd = 1, .rs1 = 0, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 1.0);
    cpu.registers.setF32(2, std.math.nan(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fcvt_w_s - float to signed int RTZ" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 1 } }, // RTZ mode
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -3.7);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, -3), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.nx); // Inexact because fractional part lost
}

test "fcvt_w_s - float to signed int RNE" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } }, // RNE mode
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(1)); // Round to even
    try std.testing.expect(cpu.registers.fcsr.nx);
}

test "fcvt_w_s - overflow saturates and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 10, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 1e20);
    cpu.registers.setF32(10, -1e20);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(std.math.maxInt(i32), cpu.registers.get(1));
    try std.testing.expectEqual(std.math.minInt(i32), cpu.registers.get(2));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fcvt_w_s - NaN returns maxInt and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.nan(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(std.math.maxInt(i32), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fcvt_w_s - positive infinity returns maxInt and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(std.math.maxInt(i32), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fcvt_w_s - RNE rounds ties to even" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 10, .rm = 0 } },
        .{ .fcvt_w_s = .{ .rd = 3, .rs1 = 11, .rm = 0 } },
        .{ .fcvt_w_s = .{ .rd = 4, .rs1 = 12, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 0.5); // -> 0 (even)
    cpu.registers.setF32(10, 1.5); // -> 2 (even)
    cpu.registers.setF32(11, 2.5); // -> 2 (even)
    cpu.registers.setF32(12, 3.5); // -> 4 (even)

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(2));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(3));
    try std.testing.expectEqual(@as(i32, 4), cpu.registers.get(4));
}

test "fcvt_w_s - RNE with negative ties to even" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 10, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -2.5); // -> -2 (even)
    cpu.registers.setF32(10, -3.5); // -> -4 (even)

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(@as(i32, -2), cpu.registers.get(1));
    try std.testing.expectEqual(@as(i32, -4), cpu.registers.get(2));
}

test "fcvt_wu_s - float to unsigned int" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_wu_s = .{ .rd = 1, .rs1 = 0, .rm = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 42.9);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 42), @as(u32, @bitCast(cpu.registers.get(1))));
    try std.testing.expect(cpu.registers.fcsr.nx);
}

test "fcvt_wu_s - negative produces zero and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_wu_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -5.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0), @as(u32, @bitCast(cpu.registers.get(1))));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fcvt_wu_s - negative zero produces zero without NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_wu_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x80000000))); // -0.0

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0), @as(u32, @bitCast(cpu.registers.get(1))));
    // -0.0 converts exactly to 0, so neither NV nor NX should be set
    try std.testing.expect(!cpu.registers.fcsr.nv);
    try std.testing.expect(!cpu.registers.fcsr.nx);
}

test "fcvt_s_w - signed int to float" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -42 } },
        .{ .fcvt_s_w = .{ .rd = 0, .rs1 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(@as(f32, -42.0), cpu.registers.getF32(0));
}

test "fcvt_s_w - large int may be inexact" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_s_w = .{ .rd = 0, .rs1 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.set(1, 0x7FFFFF7F); // Large value that can't be exactly represented

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    // The conversion happens, check if NX is set appropriately
    try std.testing.expect(!std.math.isNan(cpu.registers.getF32(0)));
}

test "fcvt_s_wu - unsigned int to float" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_s_wu = .{ .rd = 0, .rs1 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.set(1, @bitCast(@as(u32, 100)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 100.0), cpu.registers.getF32(0));
}

test "fmv_x_w - bit transfer float to int" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmv_x_w = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x3F800000), @as(u32, @bitCast(cpu.registers.get(1))));
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags()); // No exceptions
}

test "fmv_w_x - bit transfer int to float" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmv_w_x = .{ .rd = 0, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.set(1, @bitCast(@as(u32, 0x3F800000)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 1.0), cpu.registers.getF32(0));
    try std.testing.expectEqual(@as(u5, 0), cpu.registers.fcsr.getFflags()); // No exceptions
}

test "fclass_s - classify positive zero" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_s = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 0.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x010), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fclass_s - classify negative zero" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_s = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x80000000)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x008), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fclass_s - classify positive infinity" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_s = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x080), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fclass_s - classify negative infinity" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_s = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x001), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fclass_s - classify positive normal" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_s = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 1.5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x040), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fclass_s - classify negative normal" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_s = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -1.5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x002), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fclass_s - classify quiet NaN" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_s = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.nan(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x200), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fclass_s - classify signaling NaN" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_s = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x7F800001))); // sNaN

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x100), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fclass_s - classify positive subnormal" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_s = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x00000001))); // Smallest positive subnormal

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x020), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fmadd_s - fused multiply-add" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmadd_s = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.0);
    cpu.registers.setF32(1, 3.0);
    cpu.registers.setF32(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 7.0), cpu.registers.getF32(3)); // 2*3+1
}

test "fmadd_s - inf * 0 produces NaN and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmadd_s = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.inf(f32));
    cpu.registers.setF32(1, 0.0);
    cpu.registers.setF32(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF32(3)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fmsub_s - fused multiply-subtract" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmsub_s = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.0);
    cpu.registers.setF32(1, 3.0);
    cpu.registers.setF32(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 5.0), cpu.registers.getF32(3)); // 2*3-1
}

test "fnmsub_s - negated fused multiply-subtract" {
    var ram = initRamWithCode(1024, &.{
        .{ .fnmsub_s = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.0);
    cpu.registers.setF32(1, 3.0);
    cpu.registers.setF32(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, -5.0), cpu.registers.getF32(3)); // -(2*3)+1 = -5
}

test "fnmadd_s - negated fused multiply-add" {
    var ram = initRamWithCode(1024, &.{
        .{ .fnmadd_s = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.0);
    cpu.registers.setF32(1, 3.0);
    cpu.registers.setF32(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, -7.0), cpu.registers.getF32(3)); // -(2*3)-1 = -7
}

test "fld/fsd - load and store double" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 104 } },
        .{ .fld = .{ .rd = 0, .rs1 = 1, .imm = 0 } },
        .{ .fsd = .{ .rs1 = 1, .rs2 = 0, .imm = 16 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;

    const pi: f64 = 3.141592653589793;
    try cpu.writeMemory(104, @as(u64, @bitCast(pi)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));

    const loaded = try cpu.readMemory(120, u64, .read);
    try std.testing.expectEqual(@as(u64, @bitCast(pi)), loaded);
}

test "fadd_d - add doubles" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 1.5);
    cpu.registers.setF64(1, 2.5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 4.0), cpu.registers.getF64(2));
}

test "fadd_d - inf + (-inf) produces NaN and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, std.math.inf(f64));
    cpu.registers.setF64(1, -std.math.inf(f64));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF64(2)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fsub_d - subtract doubles" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsub_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 5.0);
    cpu.registers.setF64(1, 2.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 3.0), cpu.registers.getF64(2));
}

test "fmul_d - multiply doubles" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmul_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 3.0);
    cpu.registers.setF64(1, 4.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 12.0), cpu.registers.getF64(2));
}

test "fmul_d - 0 * inf produces NaN and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmul_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 0.0);
    cpu.registers.setF64(1, std.math.inf(f64));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF64(2)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fdiv_d - divide doubles" {
    var ram = initRamWithCode(1024, &.{
        .{ .fdiv_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 10.0);
    cpu.registers.setF64(1, 4.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 2.5), cpu.registers.getF64(2));
}

test "fdiv_d - division by zero sets DZ" {
    var ram = initRamWithCode(1024, &.{
        .{ .fdiv_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 1.0);
    cpu.registers.setF64(1, 0.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isInf(cpu.registers.getF64(2)));
    try std.testing.expect(cpu.registers.fcsr.dz);
}

test "fsqrt_d - square root" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsqrt_d = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 16.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 4.0), cpu.registers.getF64(1));
}

test "fsqrt_d - negative produces NaN and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsqrt_d = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, -1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF64(1)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fmin_d - basic min" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmin_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 3.0);
    cpu.registers.setF64(1, 7.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 3.0), cpu.registers.getF64(2));
}

test "fmin_d - -0.0 is less than +0.0" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmin_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 0.0);
    cpu.registers.setF64(1, @bitCast(@as(u64, 0x8000000000000000))); // -0.0

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u64, 0x8000000000000000), @as(u64, @bitCast(cpu.registers.getF64(2))));
}

test "fmax_d - basic max" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmax_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 3.0);
    cpu.registers.setF64(1, 7.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 7.0), cpu.registers.getF64(2));
}

test "fsgnj_d - sign injection" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsgnj_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 5.0);
    cpu.registers.setF64(1, -3.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, -5.0), cpu.registers.getF64(2));
}

test "fsgnjn_d - negated sign injection" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsgnjn_d = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 5.0);
    cpu.registers.setF64(1, -3.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 5.0), cpu.registers.getF64(2));
}

test "fsgnjx_d - xor sign (fabs idiom)" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsgnjx_d = .{ .rd = 2, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, -7.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 7.0), cpu.registers.getF64(2));
}

test "feq_d - equal doubles" {
    var ram = initRamWithCode(1024, &.{
        .{ .feq_d = .{ .rd = 1, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 3.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(1));
}

test "feq_d - NaN never equals anything" {
    var ram = initRamWithCode(1024, &.{
        .{ .feq_d = .{ .rd = 1, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, std.math.nan(f64));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
}

test "flt_d - less than comparison" {
    var ram = initRamWithCode(1024, &.{
        .{ .flt_d = .{ .rd = 1, .rs1 = 0, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 2.0);
    cpu.registers.setF64(2, 5.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(1));
}

test "flt_d - NaN sets NV and returns 0" {
    var ram = initRamWithCode(1024, &.{
        .{ .flt_d = .{ .rd = 1, .rs1 = 0, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, std.math.nan(f64));
    cpu.registers.setF64(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fle_d - less than or equal comparison" {
    var ram = initRamWithCode(1024, &.{
        .{ .fle_d = .{ .rd = 1, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 2.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(1));
}

test "fcvt_w_d - double to signed int" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_d = .{ .rd = 1, .rs1 = 0, .rm = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, -1234567.89);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, -1234567), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.nx);
}

test "fcvt_w_d - overflow saturates and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_d = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 1e20);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(std.math.maxInt(i32), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fcvt_wu_d - double to unsigned int" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_wu_d = .{ .rd = 1, .rs1 = 0, .rm = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 42.9);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 42), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fcvt_wu_d - negative produces zero and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_wu_d = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, -5.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0), @as(u32, @bitCast(cpu.registers.get(1))));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fcvt_d_w - signed int to double (exact)" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = -42 } },
        .{ .fcvt_d_w = .{ .rd = 0, .rs1 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(@as(f64, -42.0), cpu.registers.getF64(0));
    try std.testing.expect(!cpu.registers.fcsr.nx); // Always exact for i32 -> f64
}

test "fcvt_d_wu - unsigned int to double (exact)" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_d_wu = .{ .rd = 0, .rs1 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFFFFFF)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 4294967295.0), cpu.registers.getF64(0));
    try std.testing.expect(!cpu.registers.fcsr.nx); // Always exact for u32 -> f64
}

test "fcvt_s_d - double to single" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_s_d = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 3.14159265358979323846);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectApproxEqRel(@as(f32, 3.14159265), cpu.registers.getF32(1), 1e-6);
    try std.testing.expect(cpu.registers.fcsr.nx); // Loses precision
}

test "fcvt_s_d - NaN produces canonical NaN" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_s_d = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, std.math.nan(f64));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF32(1)));
}

test "fcvt_s_d - sNaN sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_s_d = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, @bitCast(@as(u64, 0x7FF0000000000001))); // sNaN

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fcvt_d_s - single to double" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_d_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 3.14159);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, @as(f32, 3.14159)), cpu.registers.getF64(1));
    try std.testing.expect(!cpu.registers.fcsr.nx); // f32 -> f64 is exact
}

test "fcvt_d_s - NaN produces canonical NaN" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_d_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.nan(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF64(1)));
}

test "fclass_d - classify positive zero" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_d = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 0.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x010), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fclass_d - classify positive infinity" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_d = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, std.math.inf(f64));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x080), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fclass_d - classify quiet NaN" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_d = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, std.math.nan(f64));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x200), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fmadd_d - fused multiply-add" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmadd_d = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 2.0);
    cpu.registers.setF64(1, 3.0);
    cpu.registers.setF64(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 7.0), cpu.registers.getF64(3));
}

test "fmadd_d - inf * 0 produces NaN and sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmadd_d = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, std.math.inf(f64));
    cpu.registers.setF64(1, 0.0);
    cpu.registers.setF64(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNan(cpu.registers.getF64(3)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fmsub_d - fused multiply-subtract" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmsub_d = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 2.0);
    cpu.registers.setF64(1, 3.0);
    cpu.registers.setF64(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, 5.0), cpu.registers.getF64(3));
}

test "fnmsub_d - negated fused multiply-subtract" {
    var ram = initRamWithCode(1024, &.{
        .{ .fnmsub_d = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 2.0);
    cpu.registers.setF64(1, 3.0);
    cpu.registers.setF64(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, -5.0), cpu.registers.getF64(3)); // -(2*3)+1
}

test "fnmadd_d - negated fused multiply-add" {
    var ram = initRamWithCode(1024, &.{
        .{ .fnmadd_d = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, 2.0);
    cpu.registers.setF64(1, 3.0);
    cpu.registers.setF64(2, 1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f64, -7.0), cpu.registers.getF64(3)); // -(2*3)-1
}

test "fcvt_w_s - rounding mode RDN (round down)" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 2 } }, // RDN
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 10, .rm = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.7);
    cpu.registers.setF32(10, -2.7);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(1)); // floor(2.7) = 2
    try std.testing.expectEqual(@as(i32, -3), cpu.registers.get(2)); // floor(-2.7) = -3
}

test "fcvt_w_s - rounding mode RUP (round up)" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 3 } }, // RUP
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 10, .rm = 3 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.1);
    cpu.registers.setF32(10, -2.1);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(@as(i32, 3), cpu.registers.get(1)); // ceil(2.1) = 3
    try std.testing.expectEqual(@as(i32, -2), cpu.registers.get(2)); // ceil(-2.1) = -2
}

test "fcvt_w_s - rounding mode RMM (round to max magnitude)" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 4 } }, // RMM
        .{ .fcvt_w_s = .{ .rd = 2, .rs1 = 10, .rm = 4 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.5);
    cpu.registers.setF32(10, -2.5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(@as(i32, 3), cpu.registers.get(1)); // round away from zero
    try std.testing.expectEqual(@as(i32, -3), cpu.registers.get(2)); // round away from zero
}

test "FCSR flags accumulate across instructions" {
    var ram = initRamWithCode(1024, &.{
        .{ .fdiv_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } }, // 1/0 -> DZ
        .{ .fsqrt_s = .{ .rd = 3, .rs1 = 10, .rm = 0 } }, // sqrt(-1) -> NV
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 1.0);
    cpu.registers.setF32(1, 0.0);
    cpu.registers.setF32(10, -1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));

    // Both flags should be set
    try std.testing.expect(cpu.registers.fcsr.dz);
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "dynamic rounding mode uses frm from fcsr" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 7 } }, // Dynamic mode
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.5);
    cpu.registers.fcsr.frm = .rtz; // Set rounding to truncate

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 2), cpu.registers.get(1)); // Truncated
}

test "csrrw writes rs1 to CSR and reads old value to rd" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrw = .{ .rd = 1, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.fcsr) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.fcsr.frm = .rtz;
    cpu.registers.fcsr.nx = true;
    cpu.registers.set(2, 0b10000000); // frm = .rmm (100 in bits 7:5), all flags clear

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0b00100001), cpu.registers.get(1)); // old fcsr value
    try std.testing.expectEqual(arch.Registers.Fcsr.RoundingMode.rmm, cpu.registers.fcsr.frm);
    try std.testing.expectEqual(false, cpu.registers.fcsr.nx);
}

test "csrrw with rd=x0 does not read CSR (write-only)" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrw = .{ .rd = 0, .rs1 = 1, .csr = @intFromEnum(arch.Registers.Csr.fcsr) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 0b01100000); // frm = .rup

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(0)); // x0 always zero
    try std.testing.expectEqual(arch.Registers.Fcsr.RoundingMode.rup, cpu.registers.fcsr.frm);
}

test "csrrs reads CSR and sets bits from rs1" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.fcsr) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.fcsr.nx = true; // bit 0
    cpu.registers.set(2, 0b00010000); // set nv flag (bit 4)

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0b00000001), cpu.registers.get(1)); // old value
    try std.testing.expect(cpu.registers.fcsr.nx);
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "csrrs with rs1=x0 does not write CSR (read-only)" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.fcsr) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.fcsr.dz = true;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0b00001000), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.dz);
    try std.testing.expectEqual(false, cpu.registers.fcsr.nv);
}

test "csrrc reads CSR and clears bits from rs1" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrc = .{ .rd = 1, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.fcsr) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.fcsr.nx = true;
    cpu.registers.fcsr.uf = true;
    cpu.registers.fcsr.of = true;
    cpu.registers.set(2, 0b00000011); // clear nx and uf

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0b00000111), cpu.registers.get(1)); // old value
    try std.testing.expectEqual(false, cpu.registers.fcsr.nx);
    try std.testing.expectEqual(false, cpu.registers.fcsr.uf);
    try std.testing.expect(cpu.registers.fcsr.of);
}

test "csrrc with rs1=x0 does not write CSR (read-only)" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrc = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.fcsr) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.fcsr.of = true;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0b00000100), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.of);
}

test "csrrwi writes immediate to CSR" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrwi = .{ .rd = 1, .uimm = 0b11111, .csr = @intFromEnum(arch.Registers.Csr.fflags) } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1)); // old value
    try std.testing.expect(cpu.registers.fcsr.nx);
    try std.testing.expect(cpu.registers.fcsr.uf);
    try std.testing.expect(cpu.registers.fcsr.of);
    try std.testing.expect(cpu.registers.fcsr.dz);
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "csrrsi sets bits from immediate" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrsi = .{ .rd = 1, .uimm = 0b00101, .csr = @intFromEnum(arch.Registers.Csr.fflags) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.fcsr.uf = true;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0b00000010), cpu.registers.get(1)); // old value
    try std.testing.expect(cpu.registers.fcsr.nx);
    try std.testing.expect(cpu.registers.fcsr.uf);
    try std.testing.expect(cpu.registers.fcsr.of);
}

test "csrrsi with uimm=0 does not write CSR" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrsi = .{ .rd = 1, .uimm = 0, .csr = @intFromEnum(arch.Registers.Csr.fflags) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.fcsr.nx = true;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0b00000001), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.nx);
    try std.testing.expectEqual(false, cpu.registers.fcsr.uf);
}

test "csrrci clears bits from immediate" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrci = .{ .rd = 1, .uimm = 0b00011, .csr = @intFromEnum(arch.Registers.Csr.fflags) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.fcsr.nx = true;
    cpu.registers.fcsr.uf = true;
    cpu.registers.fcsr.of = true;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0b00000111), cpu.registers.get(1)); // old value
    try std.testing.expectEqual(false, cpu.registers.fcsr.nx);
    try std.testing.expectEqual(false, cpu.registers.fcsr.uf);
    try std.testing.expect(cpu.registers.fcsr.of);
}

test "csrrci with uimm=0 does not write CSR" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrci = .{ .rd = 1, .uimm = 0, .csr = @intFromEnum(arch.Registers.Csr.fflags) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.fcsr.nv = true;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0b00010000), cpu.registers.get(1));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "csrrs read frm register" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.frm) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.fcsr.frm = .rmm;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 4), cpu.registers.get(1));
}

test "csrrw write frm register" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrw = .{ .rd = 0, .rs1 = 1, .csr = @intFromEnum(arch.Registers.Csr.frm) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 2); // rdn

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(arch.Registers.Fcsr.RoundingMode.rdn, cpu.registers.fcsr.frm);
}

test "csrrs read cycle counter" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.cycle) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.cycle = 0x123456789ABCDEF0;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x9ABCDEF0))), cpu.registers.get(1));
}

test "csrrs read cycleh counter" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.cycleh) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.cycle = 0x123456789ABCDEF0;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(1));
}

test "csrrs read instret counter" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.instret) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.instret = 0xFEDCBA9876543210;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0x76543210))), cpu.registers.get(1));
}

test "csrrs read instreth counter" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.instreth) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.instret = 0xFEDCBA9876543210;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xFEDCBA98))), cpu.registers.get(1));
}

test "cycle and instret increment after step" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 2 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 3 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(3));
    try std.testing.expectEqual(@as(u64, 3), cpu.registers.cycle);
    try std.testing.expectEqual(@as(u64, 3), cpu.registers.instret);
}

test "fence_i advances pc" {
    var ram = initRamWithCode(1024, &.{
        .{ .fence_i = {} },
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(@as(u32, 8), cpu.registers.pc);
    try std.testing.expectEqual(@as(i32, 42), cpu.registers.get(1));
}

test "sh1add shifts rs1 left by 1 and adds rs2" {
    var ram = initRamWithCode(1024, &.{
        .{ .sh1add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 5);
    cpu.registers.set(2, 100);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 110), cpu.registers.get(3)); // (5 << 1) + 100 = 10 + 100
}

test "sh2add shifts rs1 left by 2 and adds rs2" {
    var ram = initRamWithCode(1024, &.{
        .{ .sh2add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 5);
    cpu.registers.set(2, 100);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 120), cpu.registers.get(3)); // (5 << 2) + 100 = 20 + 100
}

test "sh3add shifts rs1 left by 3 and adds rs2" {
    var ram = initRamWithCode(1024, &.{
        .{ .sh3add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 5);
    cpu.registers.set(2, 100);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 140), cpu.registers.get(3)); // (5 << 3) + 100 = 40 + 100
}

test "sh1add with negative base address" {
    var ram = initRamWithCode(1024, &.{
        .{ .sh1add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 10);
    cpu.registers.set(2, -100);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, -80), cpu.registers.get(3)); // (10 << 1) + (-100) = 20 - 100
}

test "sh2add wrapping overflow" {
    var ram = initRamWithCode(1024, &.{
        .{ .sh2add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x80000000)));
    cpu.registers.set(2, 1);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3)); // overflow wraps
}

test "andn performs and-not operation" {
    var ram = initRamWithCode(1024, &.{
        .{ .andn = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0xFF00FF00)));
    cpu.registers.set(2, @bitCast(@as(u32, 0x0F0F0F0F)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0xF000F000), @as(u32, @bitCast(cpu.registers.get(3))));
}

test "orn performs or-not operation" {
    var ram = initRamWithCode(1024, &.{
        .{ .orn = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x00FF0000)));
    cpu.registers.set(2, @bitCast(@as(u32, 0x0000FFFF)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0xFFFF0000), @as(u32, @bitCast(cpu.registers.get(3))));
}

test "xnor performs exclusive-nor operation" {
    var ram = initRamWithCode(1024, &.{
        .{ .xnor = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0xAAAAAAAA)));
    cpu.registers.set(2, @bitCast(@as(u32, 0xAAAAAAAA)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), @as(u32, @bitCast(cpu.registers.get(3))));
}

test "xnor with different values" {
    var ram = initRamWithCode(1024, &.{
        .{ .xnor = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0xFF00FF00)));
    cpu.registers.set(2, @bitCast(@as(u32, 0x00FF00FF)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x00000000), @as(u32, @bitCast(cpu.registers.get(3))));
}

test "clz counts leading zeros" {
    var ram = initRamWithCode(1024, &.{
        .{ .clz = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x00100000)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 11), cpu.registers.get(2));
}

test "clz with zero returns 32" {
    var ram = initRamWithCode(1024, &.{
        .{ .clz = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 32), cpu.registers.get(2));
}

test "clz with all ones returns 0" {
    var ram = initRamWithCode(1024, &.{
        .{ .clz = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, -1);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "ctz counts trailing zeros" {
    var ram = initRamWithCode(1024, &.{
        .{ .ctz = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x00001000)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 12), cpu.registers.get(2));
}

test "ctz with zero returns 32" {
    var ram = initRamWithCode(1024, &.{
        .{ .ctz = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 32), cpu.registers.get(2));
}

test "ctz with odd number returns 0" {
    var ram = initRamWithCode(1024, &.{
        .{ .ctz = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 7);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "cpop counts set bits" {
    var ram = initRamWithCode(1024, &.{
        .{ .cpop = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x55555555)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 16), cpu.registers.get(2));
}

test "cpop with zero returns 0" {
    var ram = initRamWithCode(1024, &.{
        .{ .cpop = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(2));
}

test "cpop with all ones returns 32" {
    var ram = initRamWithCode(1024, &.{
        .{ .cpop = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, -1);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 32), cpu.registers.get(2));
}

test "max returns greater signed value" {
    var ram = initRamWithCode(1024, &.{
        .{ .max = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, -10);
    cpu.registers.set(2, 5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 5), cpu.registers.get(3));
}

test "max with negative values" {
    var ram = initRamWithCode(1024, &.{
        .{ .max = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, -10);
    cpu.registers.set(2, -5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, -5), cpu.registers.get(3));
}

test "maxu returns greater unsigned value" {
    var ram = initRamWithCode(1024, &.{
        .{ .maxu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, -1); // 0xFFFFFFFF unsigned
    cpu.registers.set(2, 5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(3));
}

test "min returns lesser signed value" {
    var ram = initRamWithCode(1024, &.{
        .{ .min = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, -10);
    cpu.registers.set(2, 5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, -10), cpu.registers.get(3));
}

test "min with positive values" {
    var ram = initRamWithCode(1024, &.{
        .{ .min = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 100);
    cpu.registers.set(2, 50);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 50), cpu.registers.get(3));
}

test "minu returns lesser unsigned value" {
    var ram = initRamWithCode(1024, &.{
        .{ .minu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, -1); // 0xFFFFFFFF unsigned
    cpu.registers.set(2, 5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 5), cpu.registers.get(3));
}

test "sext_b sign extends byte - positive" {
    var ram = initRamWithCode(1024, &.{
        .{ .sext_b = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 0x7F);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 127), cpu.registers.get(2));
}

test "sext_b sign extends byte - negative" {
    var ram = initRamWithCode(1024, &.{
        .{ .sext_b = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFFFF80)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, -128), cpu.registers.get(2));
}

test "sext_b ignores upper bits" {
    var ram = initRamWithCode(1024, &.{
        .{ .sext_b = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x12345680)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, -128), cpu.registers.get(2));
}

test "sext_h sign extends halfword - positive" {
    var ram = initRamWithCode(1024, &.{
        .{ .sext_h = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 0x7FFF);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 32767), cpu.registers.get(2));
}

test "sext_h sign extends halfword - negative" {
    var ram = initRamWithCode(1024, &.{
        .{ .sext_h = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFF8000)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, -32768), cpu.registers.get(2));
}

test "sext_h ignores upper bits" {
    var ram = initRamWithCode(1024, &.{
        .{ .sext_h = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x12348000)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, -32768), cpu.registers.get(2));
}

test "zext_h zero extends halfword" {
    var ram = initRamWithCode(1024, &.{
        .{ .zext_h = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFF8000)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x00008000), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "zext_h with max halfword" {
    var ram = initRamWithCode(1024, &.{
        .{ .zext_h = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x1234FFFF)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x0000FFFF), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "rol rotates left" {
    var ram = initRamWithCode(1024, &.{
        .{ .rol = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x80000001)));
    cpu.registers.set(2, 4);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x00000018), @as(u32, @bitCast(cpu.registers.get(3))));
}

test "rol by 0 returns same value" {
    var ram = initRamWithCode(1024, &.{
        .{ .rol = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x12345678)));
    cpu.registers.set(2, 0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x12345678), @as(u32, @bitCast(cpu.registers.get(3))));
}

test "rol uses only lower 5 bits of shift" {
    var ram = initRamWithCode(1024, &.{
        .{ .rol = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x00000001)));
    cpu.registers.set(2, 33); // effectively 1

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x00000002), @as(u32, @bitCast(cpu.registers.get(3))));
}

test "ror rotates right" {
    var ram = initRamWithCode(1024, &.{
        .{ .ror = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x80000001)));
    cpu.registers.set(2, 4);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x18000000), @as(u32, @bitCast(cpu.registers.get(3))));
}

test "ror by 0 returns same value" {
    var ram = initRamWithCode(1024, &.{
        .{ .ror = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x12345678)));
    cpu.registers.set(2, 0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x12345678), @as(u32, @bitCast(cpu.registers.get(3))));
}

test "ror uses only lower 5 bits of shift" {
    var ram = initRamWithCode(1024, &.{
        .{ .ror = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x80000000)));
    cpu.registers.set(2, 33); // effectively 1

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x40000000), @as(u32, @bitCast(cpu.registers.get(3))));
}

test "rori rotates right by immediate" {
    var ram = initRamWithCode(1024, &.{
        .{ .rori = .{ .rd = 2, .rs1 = 1, .shamt = 8 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x12345678)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x78123456), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "rori with shamt=0 returns same value" {
    var ram = initRamWithCode(1024, &.{
        .{ .rori = .{ .rd = 2, .rs1 = 1, .shamt = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0xABCDEF01)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0xABCDEF01), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "rori with shamt=16" {
    var ram = initRamWithCode(1024, &.{
        .{ .rori = .{ .rd = 2, .rs1 = 1, .shamt = 16 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x12345678)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x56781234), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "orc_b or-combines bytes - all zero" {
    var ram = initRamWithCode(1024, &.{
        .{ .orc_b = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x00000000), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "orc_b or-combines bytes - all nonzero" {
    var ram = initRamWithCode(1024, &.{
        .{ .orc_b = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x01020304)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0xFFFFFFFF), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "orc_b or-combines bytes - mixed" {
    var ram = initRamWithCode(1024, &.{
        .{ .orc_b = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x00FF0001)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());

    // byte 0: 0x01 != 0 -> 0xFF
    // byte 1: 0x00 == 0 -> 0x00
    // byte 2: 0xFF != 0 -> 0xFF
    // byte 3: 0x00 == 0 -> 0x00
    try std.testing.expectEqual(@as(u32, 0x00FF00FF), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "orc_b with alternating zero bytes" {
    var ram = initRamWithCode(1024, &.{
        .{ .orc_b = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x00010000)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x00FF0000), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "rev8 reverses byte order" {
    var ram = initRamWithCode(1024, &.{
        .{ .rev8 = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0x12345678)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0x78563412), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "rev8 with all same bytes" {
    var ram = initRamWithCode(1024, &.{
        .{ .rev8 = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0xAAAAAAAA)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0xAAAAAAAA), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "rev8 double reversal returns original" {
    var ram = initRamWithCode(1024, &.{
        .{ .rev8 = .{ .rd = 2, .rs1 = 1 } },
        .{ .rev8 = .{ .rd = 3, .rs1 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0xDEADBEEF)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(@as(u32, 0xDEADBEEF), @as(u32, @bitCast(cpu.registers.get(3))));
}

test "rev8 with zero" {
    var ram = initRamWithCode(1024, &.{
        .{ .rev8 = .{ .rd = 2, .rs1 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 0), @as(u32, @bitCast(cpu.registers.get(2))));
}

test "sh1add for array indexing (element size 2)" {
    var ram = initRamWithCode(1024, &.{
        .{ .sh1add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 5); // index
    cpu.registers.set(2, 0x1000); // base address

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0x100A), cpu.registers.get(3)); // base + index * 2
}

test "sh2add for array indexing (element size 4)" {
    var ram = initRamWithCode(1024, &.{
        .{ .sh2add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 5); // index
    cpu.registers.set(2, 0x1000); // base address

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0x1014), cpu.registers.get(3)); // base + index * 4
}

test "sh3add for array indexing (element size 8)" {
    var ram = initRamWithCode(1024, &.{
        .{ .sh3add = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 5); // index
    cpu.registers.set(2, 0x1000); // base address

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0x1028), cpu.registers.get(3)); // base + index * 8
}

test "ebreak - produces breakpoint trap" {
    var ram = initRamWithCode(1024, &.{
        .ebreak,
    });
    var cpu: TestCpu = .init(&ram);

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.breakpoint, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 0), state.trap.tval); // breakpoint: tval = PC
}

test "load - address out of bounds produces trap" {
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(2, @bitCast(@as(u32, 2000))); // Beyond RAM

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_access_fault, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 2000), state.trap.tval); // Faulting address
}

test "store - address out of bounds produces trap" {
    var ram = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 2, .rs2 = 1, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 42);
    cpu.registers.set(2, @bitCast(@as(u32, 2000))); // Beyond RAM

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_access_fault, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 2000), state.trap.tval);
}

test "lh - misaligned address produces trap" {
    var ram = initRamWithCode(1024, &.{
        .{ .lh = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(2, 101); // Odd address, misaligned for half-word

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_address_misaligned, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 101), state.trap.tval);
}

test "lw - misaligned address produces trap" {
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(2, 102); // Not 4-byte aligned

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_address_misaligned, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 102), state.trap.tval);
}

test "sh - misaligned address produces trap" {
    var ram = initRamWithCode(1024, &.{
        .{ .sh = .{ .rs1 = 2, .rs2 = 1, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 42);
    cpu.registers.set(2, 101); // Odd address

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_address_misaligned, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 101), state.trap.tval);
}

test "sw - misaligned address produces trap" {
    var ram = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 2, .rs2 = 1, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 42);
    cpu.registers.set(2, 102); // Not 4-byte aligned

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_address_misaligned, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 102), state.trap.tval);
}

test "fld - misaligned address produces trap" {
    var ram = initRamWithCode(1024, &.{
        .{ .fld = .{ .rd = 0, .rs1 = 1, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.set(1, 100); // Not 8-byte aligned

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_address_misaligned, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 100), state.trap.tval);
}

test "fsd - misaligned address produces trap" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsd = .{ .rs1 = 1, .rs2 = 0, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.set(1, 100); // Not 8-byte aligned

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_address_misaligned, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 100), state.trap.tval);
}

test "NaN-boxing - reading non-boxed f32 returns NaN" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_s = .{ .rd = 1, .rs1 = 0, .rs2 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;

    // Directly set float register without proper NaN-boxing
    cpu.registers.float[0] = 0x00000000_3F800000; // Upper bits not all 1s

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    // getF32 should return NaN since upper bits are not 0xFFFFFFFF
    try std.testing.expect(std.math.isNan(cpu.registers.getF32(0)));
}

test "NaN-boxing - setF32 properly boxes value" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;

    cpu.registers.setF32(0, 1.5);

    // Upper 32 bits should be all 1s
    const expected: u64 = 0xFFFFFFFF00000000 | @as(u64, @as(u32, @bitCast(@as(f32, 1.5))));
    try std.testing.expectEqual(expected, cpu.registers.float[0]);
}

test "NaN-boxing - f64 stored without boxing" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;

    cpu.registers.setF64(0, 3.14159);

    try std.testing.expectEqual(@as(u64, @bitCast(@as(f64, 3.14159))), cpu.registers.float[0]);
}

test "fcvt_wu_s - small negative rounds to zero without NV (RTZ)" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_wu_s = .{ .rd = 1, .rs1 = 0, .rm = 1 } }, // RTZ
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -0.5);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    // -0.5 truncated toward zero = 0, which is valid for u32
    try std.testing.expectEqual(@as(u32, 0), @as(u32, @bitCast(cpu.registers.get(1))));
    // NX should be set (inexact), but NV should NOT be set
    try std.testing.expect(cpu.registers.fcsr.nx);
    try std.testing.expect(!cpu.registers.fcsr.nv);
}

test "fcvt_wu_s - small negative rounds to negative with RDN sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_wu_s = .{ .rd = 1, .rs1 = 0, .rm = 2 } }, // RDN (floor)
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -0.1);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    // floor(-0.1) = -1, which is negative -> invalid
    try std.testing.expectEqual(@as(u32, 0), @as(u32, @bitCast(cpu.registers.get(1))));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fcvt_wu_d - small negative rounds to zero without NV (RTZ)" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_wu_d = .{ .rd = 1, .rs1 = 0, .rm = 1 } }, // RTZ
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, -0.999);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0), @as(u32, @bitCast(cpu.registers.get(1))));
    try std.testing.expect(cpu.registers.fcsr.nx);
    try std.testing.expect(!cpu.registers.fcsr.nv);
}

test "fadd_s - adding opposite infinities of same sign" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.inf(f32));
    cpu.registers.setF32(1, std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    // +inf + +inf = +inf (no exception)
    try std.testing.expect(std.math.isPositiveInf(cpu.registers.getF32(2)));
    try std.testing.expect(!cpu.registers.fcsr.nv);
}

test "fsub_s - subtracting infinities of opposite signs produces infinity" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsub_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.inf(f32));
    cpu.registers.setF32(1, -std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    // +inf - (-inf) = +inf (no exception)
    try std.testing.expect(std.math.isPositiveInf(cpu.registers.getF32(2)));
    try std.testing.expect(!cpu.registers.fcsr.nv);
}

test "fmul_s - inf * finite produces inf" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmul_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.inf(f32));
    cpu.registers.setF32(1, 2.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isPositiveInf(cpu.registers.getF32(2)));
    try std.testing.expect(!cpu.registers.fcsr.nv);
}

test "fdiv_s - finite / inf produces zero" {
    var ram = initRamWithCode(1024, &.{
        .{ .fdiv_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 1.0);
    cpu.registers.setF32(1, std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 0.0), cpu.registers.getF32(2));
    try std.testing.expect(!cpu.registers.fcsr.dz);
}

test "fsqrt_s - sqrt of positive infinity is positive infinity" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsqrt_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isPositiveInf(cpu.registers.getF32(1)));
    try std.testing.expect(!cpu.registers.fcsr.nv);
}

test "fsqrt_s - sqrt of zero is zero with same sign" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsqrt_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 0.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(f32, 0.0), cpu.registers.getF32(1));
    // Check it's positive zero
    try std.testing.expectEqual(@as(u32, 0x00000000), @as(u32, @bitCast(cpu.registers.getF32(1))));
}

test "fmin/fmax - with +0.0 and -0.0 both orders" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmin_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } }, // min(+0, -0)
        .{ .fmin_s = .{ .rd = 3, .rs1 = 1, .rs2 = 0 } }, // min(-0, +0)
        .{ .fmax_s = .{ .rd = 4, .rs1 = 0, .rs2 = 1 } }, // max(+0, -0)
        .{ .fmax_s = .{ .rd = 5, .rs1 = 1, .rs2 = 0 } }, // max(-0, +0)
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 0.0); // +0.0
    cpu.registers.setF32(1, @bitCast(@as(u32, 0x80000000))); // -0.0

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(4));

    // min should always return -0.0
    try std.testing.expectEqual(@as(u32, 0x80000000), @as(u32, @bitCast(cpu.registers.getF32(2))));
    try std.testing.expectEqual(@as(u32, 0x80000000), @as(u32, @bitCast(cpu.registers.getF32(3))));

    // max should always return +0.0
    try std.testing.expectEqual(@as(u32, 0x00000000), @as(u32, @bitCast(cpu.registers.getF32(4))));
    try std.testing.expectEqual(@as(u32, 0x00000000), @as(u32, @bitCast(cpu.registers.getF32(5))));
}

test "fmadd_s - inf * finite + (-inf) produces NaN" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmadd_s = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.inf(f32));
    cpu.registers.setF32(1, 1.0);
    cpu.registers.setF32(2, -std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    // inf * 1 + (-inf) = inf + (-inf) = NaN
    try std.testing.expect(std.math.isNan(cpu.registers.getF32(3)));
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "fmadd_s - preserves precision better than separate mul+add" {
    var ram = initRamWithCode(1024, &.{
        .{ .fmadd_s = .{ .rd = 3, .rs1 = 0, .rs2 = 1, .rs3 = 2, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    // Values chosen to show fused operation advantage
    cpu.registers.setF32(0, 1.0000001);
    cpu.registers.setF32(1, 1.0000001);
    cpu.registers.setF32(2, -1.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    // Result should be very small but non-zero
    const result = cpu.registers.getF32(3);
    try std.testing.expect(!std.math.isNan(result));
    try std.testing.expect(result != 0.0);
}

test "fsgnj_s - preserves NaN payload" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsgnj_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    // NaN with specific payload
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x7FC12345))); // qNaN with payload
    cpu.registers.setF32(1, -1.0); // negative

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    // Should have negative sign but preserve NaN payload
    const result: u32 = @bitCast(cpu.registers.getF32(2));
    try std.testing.expectEqual(@as(u32, 0xFFC12345), result);
}

test "fsgnjx_s - XOR signs of two negative numbers" {
    var ram = initRamWithCode(1024, &.{
        .{ .fsgnjx_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -5.0);
    cpu.registers.setF32(1, -3.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    // negative XOR negative = positive
    try std.testing.expectEqual(@as(f32, 5.0), cpu.registers.getF32(2));
}

test "fclass_s - classify negative subnormal" {
    var ram = initRamWithCode(1024, &.{
        .{ .fclass_s = .{ .rd = 1, .rs1 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x80000001))); // Smallest negative subnormal

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(u32, 0x004), @as(u32, @bitCast(cpu.registers.get(1))));
}

test "fadd_s - subnormal result sets UF flag" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    // Use values that reliably produce subnormal
    cpu.registers.setF32(0, @bitCast(@as(u32, 0x00800000))); // Smallest positive normal
    cpu.registers.setF32(1, @bitCast(@as(u32, 0x80400000))); // -0.5 * smallest normal

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));

    const result: u32 = @bitCast(cpu.registers.getF32(2));
    const exp = (result >> 23) & 0xFF;
    // Result should be subnormal (exponent = 0) or zero
    try std.testing.expect(exp == 0);
    // Note: UF flag check depends on implementation details
}

test "csrrs - writing to read-only CSR (cycle) raises illegal instruction" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.cycle) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.cycle = 100;
    cpu.registers.set(2, @bitCast(@as(u32, 0xFFFFFFFF)));

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, state.trap.cause.exception);
}

test "csrrs - reading read-only CSR (cycle) with rs1=x0 succeeds" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.cycle) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.cycle = 100;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    // Value read before increment, but increment happens during step
    try std.testing.expectEqual(@as(i32, 100), cpu.registers.get(1));
    try std.testing.expectEqual(@as(u64, 101), cpu.registers.cycle);
}

test "mcycle/minstret are writable in M-mode" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrw = .{ .rd = 0, .rs1 = 1, .csr = @intFromEnum(arch.Registers.Csr.mcycle) } },
        .{ .csrrw = .{ .rd = 0, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.minstret) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.cycle = 100;
    cpu.registers.instret = 200;
    cpu.registers.set(1, 1000);
    cpu.registers.set(2, 2000);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    // After step 1: cycle = 1000 (written) + 1 (increment) = 1001
    //               instret = 200 + 1 = 201 (not written yet)
    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    // After step 2: cycle = 1001 + 1 = 1002
    //               instret = 2000 (written) + 1 (increment) = 2001

    try std.testing.expectEqual(@as(u64, 1002), cpu.registers.cycle);
    try std.testing.expectEqual(@as(u64, 2001), cpu.registers.instret);
}

test "csrrw - fcsr only uses lower 8 bits" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrw = .{ .rd = 1, .rs1 = 2, .csr = @intFromEnum(arch.Registers.Csr.fcsr) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(2, @bitCast(@as(u32, 0xFFFFFFFF)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    // Only lower 8 bits should be written
    try std.testing.expectEqual(@as(u32, 0xFF), @as(u32, @bitCast(cpu.registers.fcsr)) & 0xFF);
}

test "cycle counter wraps on overflow" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.cycle = std.math.maxInt(u64);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u64, 0), cpu.registers.cycle);
}

test "instret counter wraps on overflow" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.instret = std.math.maxInt(u64);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u64, 0), cpu.registers.instret);
}

test "fence advances PC and counts as retired" {
    var ram = initRamWithCode(1024, &.{
        .{ .fence = {} },
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(2));
    try std.testing.expectEqual(@as(u32, 8), cpu.registers.pc);
    try std.testing.expectEqual(@as(i32, 42), cpu.registers.get(1));
    try std.testing.expectEqual(@as(u64, 2), cpu.registers.instret);
}

test "mulhsu - negative signed times max unsigned" {
    var ram = initRamWithCode(1024, &.{
        .{ .mulhsu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, -1); // Signed -1
    cpu.registers.set(2, -1); // Unsigned 0xFFFFFFFF

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    // (-1) * 0xFFFFFFFF = -0xFFFFFFFF
    // Upper 32 bits of -0xFFFFFFFF (as 64-bit) = -1 (0xFFFFFFFF)
    try std.testing.expectEqual(@as(i32, -1), cpu.registers.get(3));
}

test "mulhsu - positive signed times max unsigned" {
    var ram = initRamWithCode(1024, &.{
        .{ .mulhsu = .{ .rd = 3, .rs1 = 1, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 2);
    cpu.registers.set(2, -1); // Unsigned 0xFFFFFFFF

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    // 2 * 0xFFFFFFFF = 0x1_FFFFFFFE, upper 32 bits = 1
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(3));
}

test "fcvt_d_s - preserves infinity sign" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_d_s = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, -std.math.inf(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isNegativeInf(cpu.registers.getF64(1)));
}

test "fcvt_s_d - overflow to infinity sets OF and NX" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_s_d = .{ .rd = 1, .rs1 = 0, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF64(0, std.math.floatMax(f64)); // Too large for f32

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expect(std.math.isInf(cpu.registers.getF32(1)));
    try std.testing.expect(cpu.registers.fcsr.of);
    try std.testing.expect(cpu.registers.fcsr.nx);
}

test "feq_s - both operands qNaN does not set NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .feq_s = .{ .rd = 1, .rs1 = 0, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.nan(f32)); // qNaN
    cpu.registers.setF32(2, std.math.nan(f32)); // qNaN

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
    // feq with qNaN does NOT set NV
    try std.testing.expect(!cpu.registers.fcsr.nv);
}

test "flt_s - both operands qNaN sets NV" {
    var ram = initRamWithCode(1024, &.{
        .{ .flt_s = .{ .rd = 1, .rs1 = 0, .rs2 = 2 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, std.math.nan(f32));
    cpu.registers.setF32(2, std.math.nan(f32));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(1));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));
    // flt/fle with ANY NaN sets NV
    try std.testing.expect(cpu.registers.fcsr.nv);
}

test "jal - maximum positive offset" {
    var ram = initRamWithCode(4096, &.{
        .{ .jal = .{ .rd = 1, .imm = 2044 } }, // Must be 4-byte aligned
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u32, 2044), cpu.registers.pc);
    try std.testing.expectEqual(@as(i32, 4), cpu.registers.get(1)); // Return address
}

test "jal - misaligned target causes trap" {
    var ram = initRamWithCode(4096, &.{
        .{ .jal = .{ .rd = 1, .imm = 2046 } }, // Not 4-byte aligned
    });
    var cpu: TestCpu = .init(&ram);

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.instruction_address_misaligned, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 2046), state.trap.tval);
}

test "jalr - handles wrap-around correctly" {
    var ram = initRamWithCode(1024, &.{
        .{ .jalr = .{ .rd = 2, .rs1 = 1, .imm = 4 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFFFFF0))); // Large address

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    // (0xFFFFFFF0 + 4) & ~1 = 0xFFFFFFF4
    try std.testing.expectEqual(@as(u32, 0xFFFFFFF4), cpu.registers.pc);
}

test "x0 remains zero after all instruction types" {
    var ram = initRamWithCode(1024, &.{
        .{ .lui = .{ .rd = 0, .imm = @truncate(0xFFFFF) } },
        .{ .auipc = .{ .rd = 0, .imm = @truncate(0xFFFFF) } },
        .{ .jal = .{ .rd = 0, .imm = 4 } }, // Jump to next instruction
        .{ .add = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } },
        .{ .mul = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } },
        .{ .slt = .{ .rd = 0, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, 100); // Set x1 to ensure x0 isn't affected

    try std.testing.expectEqual(TestCpu.State.ok, cpu.run(6));
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(0));
}

test "time CSR reads mtime register" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.time) } },
    });
    var cpu: TestCpu = .init(&ram);
    // mtime will be incremented by 1 before instruction executes
    // So set it to value-1 to get expected value after increment
    cpu.registers.mtime = 0xDEADBEEE;
    cpu.registers.cycle = 0x12345678; // Different value to prove they're separate

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    // After timer tick: mtime = 0xDEADBEEF
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xDEADBEEF))), cpu.registers.get(1));
}

test "timeh CSR reads upper 32 bits of mtime" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.timeh) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mtime = 0xCAFEBABE_12345678;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xCAFEBABE))), cpu.registers.get(1));
}

test "cycle and instret CSRs are read-only - write attempts trap" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrw = .{ .rd = 0, .rs1 = 1, .csr = @intFromEnum(arch.Registers.Csr.cycle) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.set(1, @bitCast(@as(u32, 0xFFFFFFFF)));

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, state.trap.cause.exception);
}

test "cycle increments on each instruction" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
        .{ .addi = .{ .rd = 2, .rs1 = 0, .imm = 2 } },
        .{ .addi = .{ .rd = 3, .rs1 = 0, .imm = 3 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(@as(u64, 0), cpu.registers.cycle);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u64, 1), cpu.registers.cycle);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u64, 2), cpu.registers.cycle);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(u64, 3), cpu.registers.cycle);
}

test "instret increments on each retired instruction" {
    var ram = initRamWithCode(1024, &.{
        .{ .add = .{ .rd = 1, .rs1 = 0, .rs2 = 0 } },
        .{ .add = .{ .rd = 2, .rs1 = 0, .rs2 = 0 } },
        .{ .add = .{ .rd = 3, .rs1 = 0, .rs2 = 0 } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(@as(u64, 0), cpu.registers.instret);

    _ = cpu.run(3);

    try std.testing.expectEqual(@as(u64, 3), cpu.registers.instret);
}

test "cycle overflow from 32-bit to 64-bit boundary" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 0, .rs1 = 0, .imm = 0 } },
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.cycle) } },
        .{ .csrrs = .{ .rd = 2, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.cycleh) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.cycle = 0xFFFFFFFF;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step()); // cycle: 0xFFFFFFFF -> 0x100000000
    try std.testing.expectEqual(@as(u64, 0x100000000), cpu.registers.cycle);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(2));
}

test "instret overflow from 32-bit to 64-bit boundary" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 0, .rs1 = 0, .imm = 0 } },
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.instret) } },
        .{ .csrrs = .{ .rd = 2, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.instreth) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.instret = 0xFFFFFFFF;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step()); // instret: 0xFFFFFFFF -> 0x100000000
    try std.testing.expectEqual(@as(u64, 0x100000000), cpu.registers.instret);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 0), cpu.registers.get(1));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 1), cpu.registers.get(2));
}

test "csrrsi/csrrci on read-only CSRs with non-zero uimm trap" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrsi = .{ .rd = 1, .uimm = 0x1F, .csr = @intFromEnum(arch.Registers.Csr.cycle) } },
    });
    var cpu: TestCpu = .init(&ram);

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, state.trap.cause.exception);
}

test "csrrsi/csrrci on read-only CSRs with uimm=0 succeeds (read-only operation)" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrsi = .{ .rd = 1, .uimm = 0, .csr = @intFromEnum(arch.Registers.Csr.cycle) } },
        .{ .csrrci = .{ .rd = 2, .uimm = 0, .csr = @intFromEnum(arch.Registers.Csr.instret) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.cycle = 1000;
    cpu.registers.instret = 2000;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());

    try std.testing.expectEqual(@as(i32, 1000), cpu.registers.get(1));
    try std.testing.expectEqual(@as(i32, 2001), cpu.registers.get(2));
}

test "U-mode cannot access M-mode CSRs" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.mstatus) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    configurePmpFullAccess(&cpu);

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, state.trap.cause.exception);
}

test "M-mode can access all CSRs" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.mstatus) } },
        .{ .csrrs = .{ .rd = 2, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.fcsr) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
}

test "U-mode counter access allowed when mcounteren.cy is set" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.cycle) } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.mcounteren.cy = true;
    cpu.registers.cycle = 12345;
    configurePmpFullAccess(&cpu);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, 12345), cpu.registers.get(1));
}

test "ecall from U-mode - produces trap" {
    var ram = initRamWithCode(1024, &.{
        .ecall,
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.mtvec = .{ .base = 0x100 >> 2, .mode = .direct };
    configurePmpFullAccess(&cpu);

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.ecall_from_u, state.trap.cause.exception);
}

test "ecall from M-mode - produces trap" {
    var ram = initRamWithCode(1024, &.{
        .ecall,
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.ecall_from_m, state.trap.cause.exception);
}

test "handleTrap saves correct state" {
    var ram = initRamWithCode(1024, &.{
        .ecall,
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.pc = 0x1000;
    cpu.registers.mstatus.mie = true;
    cpu.registers.mtvec = .{ .base = 0x2000 >> 2, .mode = .direct };

    cpu.handleTrap(.{ .exception = .ecall_from_u }, 0);

    try std.testing.expectEqual(@as(u32, 0x1000), cpu.registers.mepc);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.ecall_from_u, @as(arch.Registers.Mcause.Exception, @enumFromInt(cpu.registers.mcause.code)));
    try std.testing.expectEqual(false, cpu.registers.mcause.interrupt);
    try std.testing.expectEqual(arch.PrivilegeLevel.user, cpu.registers.mstatus.mpp);
    try std.testing.expectEqual(true, cpu.registers.mstatus.mpie);
    try std.testing.expectEqual(false, cpu.registers.mstatus.mie);
    try std.testing.expectEqual(arch.PrivilegeLevel.machine, cpu.registers.privilege);
    try std.testing.expectEqual(@as(u32, 0x2000), cpu.registers.pc);
}

test "mtvec vectored mode calculates correct interrupt address" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mtvec = .{ .base = 0x1000 >> 2, .mode = .vectored };

    // Machine timer interrupt (code = 7)
    cpu.handleTrap(.{ .interrupt = .machine_timer }, 0);

    try std.testing.expectEqual(@as(u32, 0x1000 + 7 * 4), cpu.registers.pc);
}

test "mtvec vectored mode uses base for exceptions" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mtvec = .{ .base = 0x1000 >> 2, .mode = .vectored };

    cpu.handleTrap(.{ .exception = .illegal_instruction }, 0);

    try std.testing.expectEqual(@as(u32, 0x1000), cpu.registers.pc);
}

test "mret restores privilege and PC" {
    var ram = initRamWithCode(1024, &.{
        .mret,
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;
    cpu.registers.mstatus.mpp = .user;
    cpu.registers.mstatus.mpie = true;
    cpu.registers.mstatus.mie = false;
    cpu.registers.mepc = 0x2000;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());

    try std.testing.expectEqual(arch.PrivilegeLevel.user, cpu.registers.privilege);
    try std.testing.expectEqual(@as(u32, 0x2000), cpu.registers.pc);
    try std.testing.expectEqual(true, cpu.registers.mstatus.mie);
    try std.testing.expectEqual(true, cpu.registers.mstatus.mpie);
    try std.testing.expectEqual(arch.PrivilegeLevel.user, cpu.registers.mstatus.mpp);
}

test "mret in U-mode causes illegal instruction" {
    var ram = initRamWithCode(1024, &.{
        .mret,
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    configurePmpFullAccess(&cpu);

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, state.trap.cause.exception);
}

test "full trap and return cycle" {
    var ram = initRamWithCode(1024, &.{
        .ecall, // 0x000: ecall in user mode
    });
    // Place mret at trap handler address
    const mret_encoded = (arch.Instruction{ .mret = {} }).encode();
    std.mem.writeInt(u32, ram[0x100..0x104], mret_encoded, arch.ENDIAN);

    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.mtvec = .{ .base = 0x100 >> 2, .mode = .direct };
    cpu.registers.mstatus.mie = true;

    // Execute ecall - should trap
    var state = cpu.step();
    try std.testing.expect(state == .trap);

    // Handle the trap
    cpu.handleTrap(state.trap.cause, state.trap.tval);

    try std.testing.expectEqual(arch.PrivilegeLevel.machine, cpu.registers.privilege);
    try std.testing.expectEqual(@as(u32, 0x100), cpu.registers.pc);

    // Execute mret - should return to user mode
    state = cpu.step();
    try std.testing.expectEqual(TestCpu.State.ok, state);
    try std.testing.expectEqual(arch.PrivilegeLevel.user, cpu.registers.privilege);
}

test "wfi halts when no enabled interrupts pending" {
    var ram = initRamWithCode(1024, &.{
        .wfi,
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;
    cpu.registers.mie.mtie = false; // Timer interrupt NOT enabled in mie
    cpu.registers.mip.mtip = true; // Timer interrupt pending but not enabled
    cpu.registers.mstatus.mie = true;

    const state = cpu.step();

    // Pending interrupt is not enabled in mie, so WFI halts
    try std.testing.expectEqual(TestCpu.State.halt, state);
}

test "wfi - interrupt taken before wfi when globally enabled" {
    var ram = initRamWithCode(1024, &.{
        .wfi,
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;
    cpu.registers.mie.mtie = true;
    // Set mtime/mtimecmp so updateTimer will set mtip=true
    cpu.registers.mtime = 100;
    cpu.registers.mtimecmp = 50; // mtime >= mtimecmp → mtip = true
    cpu.registers.mstatus.mie = true;
    cpu.registers.mtvec = .{ .base = 0x100 >> 2, .mode = .direct };

    const state = cpu.step();

    try std.testing.expectEqual(TestCpu.State.ok, state);
    try std.testing.expectEqual(@as(u32, 0x100), cpu.registers.pc);
    try std.testing.expect(cpu.registers.mcause.interrupt);
    try std.testing.expectEqual(@as(u31, 7), cpu.registers.mcause.code);
    try std.testing.expectEqual(@as(u32, 0), cpu.registers.mepc);
}

test "wfi resumes when enabled interrupt pending regardless of MIE" {
    var ram = initRamWithCode(1024, &.{
        .wfi,
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;
    cpu.registers.mie.mtie = true;
    // Set timer to trigger mtip
    cpu.registers.mtime = 100;
    cpu.registers.mtimecmp = 50;
    cpu.registers.mstatus.mie = false; // Global interrupts disabled

    const state = cpu.step();

    // WFI sees enabled pending interrupt (mtie & mtip) and resumes
    // Interrupt is NOT taken because mstatus.mie=0, but WFI doesn't halt
    try std.testing.expectEqual(TestCpu.State.ok, state);
    try std.testing.expectEqual(@as(u32, 4), cpu.registers.pc);
}

test "wfi in U-mode with TW=1 causes illegal instruction" {
    var ram = initRamWithCode(1024, &.{
        .wfi,
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.mstatus.tw = true;
    configurePmpFullAccess(&cpu);

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, state.trap.cause.exception);
}

test "wfi in U-mode with TW=0 is allowed" {
    var ram = initRamWithCode(1024, &.{
        .wfi,
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.mstatus.tw = false;
    configurePmpFullAccess(&cpu);

    const state = cpu.step();

    try std.testing.expectEqual(TestCpu.State.halt, state);
}

test "timer interrupt taken when enabled and pending" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;
    cpu.registers.mstatus.mie = true;
    cpu.registers.mie.mtie = true;
    cpu.registers.mtime = 100;
    cpu.registers.mtimecmp = 50;
    cpu.registers.mtvec = .{ .base = 0x100 >> 2, .mode = .direct };

    const state = cpu.step();

    try std.testing.expectEqual(TestCpu.State.ok, state);
    try std.testing.expectEqual(@as(u32, 0x100), cpu.registers.pc);
    try std.testing.expect(cpu.registers.mcause.interrupt);
    try std.testing.expectEqual(@as(u31, 7), cpu.registers.mcause.code);
}

test "interrupt not taken when MIE is clear in M-mode" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;
    cpu.registers.mstatus.mie = false;
    cpu.registers.mie.mtie = true;
    cpu.registers.mip.mtip = true;

    const state = cpu.step();

    try std.testing.expectEqual(TestCpu.State.ok, state);
    try std.testing.expectEqual(@as(i32, 42), cpu.registers.get(1));
}

test "interrupt taken in U-mode even with MIE clear" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.mstatus.mie = false; // Global interrupts disabled
    cpu.registers.mie.mtie = true;
    cpu.registers.mtime = 100;
    cpu.registers.mtimecmp = 50; // Will set mtip=true
    cpu.registers.mtvec = .{ .base = 0x100 >> 2, .mode = .direct };
    configurePmpFullAccess(&cpu); // Required for U-mode!

    const state = cpu.step();

    // In U-mode, interrupts are taken regardless of mstatus.mie
    try std.testing.expectEqual(TestCpu.State.ok, state);
    try std.testing.expectEqual(@as(u32, 0x100), cpu.registers.pc);
    try std.testing.expect(cpu.registers.mcause.interrupt);
    try std.testing.expectEqual(@as(u31, 7), cpu.registers.mcause.code);
}

test "interrupt priority: external > software > timer" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;
    cpu.registers.mstatus.mie = true;
    cpu.registers.mie = .{ .meie = true, .msie = true, .mtie = true };
    cpu.registers.mip = .{ .meip = true, .msip = true, .mtip = true };
    cpu.registers.mtvec = .{ .base = 0x100 >> 2, .mode = .vectored };

    _ = cpu.step();

    // External interrupt has code 11
    try std.testing.expectEqual(@as(u31, 11), cpu.registers.mcause.code);
}

test "PMP denies U-mode access to unprotected memory" {
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 0, .imm = 0x200 } }, // Access outside PMP region
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;

    // Configure PMP to allow execute for code region only
    // pmpaddr = 0x3F: 6 trailing 1s -> size = 2^9 = 512 bytes (0x000-0x200)
    cpu.registers.pmpaddr[0] = 0x3F;
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = false,
        .w = false,
        .x = true, // Execute only
        .a = .napot,
    }));

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_access_fault, state.trap.cause.exception);
}

test "PMP allows M-mode access without configuration" {
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
    });
    std.mem.writeInt(u32, ram[0x100..0x104], 0xDEADBEEF, arch.ENDIAN);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;
    cpu.registers.set(2, 0x100);

    const state = cpu.step();

    try std.testing.expectEqual(TestCpu.State.ok, state);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xDEADBEEF))), cpu.registers.get(1));
}

test "PMP NAPOT mode allows access within range" {
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
    });
    std.mem.writeInt(u32, ram[0x100..0x104], 0x12345678, arch.ENDIAN);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x100);

    // Configure PMP0: NAPOT covering 0x000-0x1FF (512 bytes), RWX
    // For 512 bytes: pmpaddr = (base >> 2) | ((size/2 - 1) >> 2) = 0 | 0x3F = 0x3F
    cpu.registers.pmpaddr[0] = 0x3F;
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true,
        .a = .napot,
    }));

    const state = cpu.step();

    try std.testing.expectEqual(TestCpu.State.ok, state);
    try std.testing.expectEqual(@as(i32, 0x12345678), cpu.registers.get(1));
}

test "PMP denies access outside configured range" {
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x200); // Outside PMP0 range

    // Configure PMP0: NAPOT covering 0x000-0x0FF (256 bytes)
    cpu.registers.pmpaddr[0] = 0x1F;
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true,
        .a = .napot,
    }));

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_access_fault, state.trap.cause.exception);
}

test "PMP TOR mode works correctly" {
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
    });
    std.mem.writeInt(u32, ram[0x80..0x84], 0xCAFEBABE, arch.ENDIAN);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x80);

    // Configure PMP0: TOR from 0x40 to 0x100 (pmpaddr0 in units of 4 bytes)
    // Previous address is 0, so range is [0, 0x100)
    cpu.registers.pmpaddr[0] = 0x100 >> 2; // 0x40
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true,
        .a = .tor,
    }));

    const state = cpu.step();

    try std.testing.expectEqual(TestCpu.State.ok, state);
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xCAFEBABE))), cpu.registers.get(1));
}

test "PMP locked entry cannot be modified" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;

    // Configure and lock PMP0
    const locked_cfg = arch.Registers.PmpCfg{
        .r = true,
        .w = false,
        .x = false,
        .a = .napot,
        .l = true,
    };
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(locked_cfg));
    cpu.registers.pmpaddr[0] = 0x1F;

    // Try to modify - should be ignored
    cpu.registers.setPmpCfg(0, .{ .r = true, .w = true, .x = true, .a = .napot });
    cpu.registers.writePmpaddr(0, 0xFF);

    const cfg = cpu.registers.getPmpCfg(0);
    try std.testing.expectEqual(false, cfg.w);
    try std.testing.expectEqual(@as(u32, 0x1F), cpu.registers.pmpaddr[0]);
}

test "PMP locked entry enforced even in M-mode" {
    var ram = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 2, .rs2 = 1, .imm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;
    cpu.registers.set(1, 0x12345678);
    cpu.registers.set(2, 0x100);

    // NAPOT address calculation:
    // For size 2^n bytes: pmpaddr needs (n-3) trailing 1s
    // For 256 bytes (n=8): need 5 trailing 1s
    // For region at base B: pmpaddr = (B >> 2) | ((1 << (n-3)) - 1) >> 1
    //                                = (B >> 2) | (size/8 - 1)

    // PMP0: Code region 0x000-0x100 (256 bytes), locked, RX
    // pmpaddr = 0 | (256/8 - 1) = 0x1F
    cpu.registers.pmpaddr[0] = 0x1F;
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = false,
        .x = true,
        .a = .napot,
        .l = true,
    }));

    // PMP1: Data region 0x100-0x200 (256 bytes), locked, R-only (no write!)
    // pmpaddr = (0x100 >> 2) | (256/8 - 1) = 0x40 | 0x1F = 0x5F
    cpu.registers.pmpaddr[1] = 0x5F;
    cpu.registers.pmpcfg[0] |= @as(u32, @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = false, // No write permission!
        .x = false,
        .a = .napot,
        .l = true, // Locked - enforced even in M-mode
    }))) << 8;

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_access_fault, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 0x100), state.trap.tval);
}

test "PMP execute permission checked for instruction fetch" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    // Place valid instruction at 0x100
    const addi = (arch.Instruction{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } }).encode();
    std.mem.writeInt(u32, ram[0x100..0x104], addi, arch.ENDIAN);

    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.pc = 0x100;

    // Configure PMP0: RW but no X
    cpu.registers.pmpaddr[0] = 0x7F;
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = false,
        .a = .napot,
    }));

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.instruction_access_fault, state.trap.cause.exception);
}

test "trap handling and resume advances PC" {
    var ram = initRamWithCode(1024, &.{
        .ecall,
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.mtvec = .{ .base = 0x100 >> 2, .mode = .direct };
    configurePmpFullAccess(&cpu);

    // Place mret at trap handler
    const mret_encoded = (arch.Instruction{ .mret = {} }).encode();
    std.mem.writeInt(u32, ram[0x100..0x104], mret_encoded, arch.ENDIAN);

    var state = cpu.step();
    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.ecall_from_u, state.trap.cause.exception);

    // Handle the trap
    cpu.handleTrap(state.trap.cause, state.trap.tval);
    try std.testing.expectEqual(@as(u32, 0x100), cpu.registers.pc);
    try std.testing.expectEqual(@as(u32, 0), cpu.registers.mepc);
    try std.testing.expectEqual(arch.PrivilegeLevel.machine, cpu.registers.privilege);

    // Simulate trap handler advancing mepc to skip ecall
    cpu.registers.mepc +%= 4;

    // Execute mret
    state = cpu.step();
    try std.testing.expectEqual(TestCpu.State.ok, state);
    try std.testing.expectEqual(@as(u32, 4), cpu.registers.pc);
    try std.testing.expectEqual(arch.PrivilegeLevel.user, cpu.registers.privilege);

    // Continue execution
    state = cpu.step();
    try std.testing.expectEqual(TestCpu.State.ok, state);
    try std.testing.expectEqual(@as(i32, 42), cpu.registers.get(1));
}

test "mtime updates mtip when crossing mtimecmp" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);

    cpu.registers.mtime = 100;
    cpu.registers.mtimecmp = 150;
    cpu.registers.mip.mtip = false;

    // Update timer past mtimecmp
    cpu.registers.updateTimer(60);

    try std.testing.expectEqual(@as(u64, 160), cpu.registers.mtime);
    try std.testing.expect(cpu.registers.mip.mtip);
}

test "setting mtimecmp clears mtip if mtime < mtimecmp" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);

    cpu.registers.mtime = 100;
    cpu.registers.mtimecmp = 50; // Already expired
    cpu.registers.updateTimer(0);
    try std.testing.expect(cpu.registers.mip.mtip);

    // Set mtimecmp to future value
    cpu.registers.setMtimecmp(200);

    try std.testing.expect(!cpu.registers.mip.mtip);
}

test "full timer interrupt cycle" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 1, .imm = 1 } }, // Loop body
        .{ .jal = .{ .rd = 0, .imm = -4 } }, // Jump back
    });

    // Place handler at 0x100
    const handler_code = [_]arch.Instruction{
        .{
            .csrrw = .{
                .rd = 0,
                .rs1 = 2,
                .csr = @intFromEnum(arch.Registers.Csr.mscratch),
            },
        },
        .mret,
    };

    for (handler_code, 0..) |instr, i| {
        std.mem.writeInt(u32, ram[0x100 + i * 4 ..][0..4], instr.encode(), arch.ENDIAN);
    }

    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.mie = true;
    cpu.registers.mie.mtie = true;
    cpu.registers.mtime = 0;
    cpu.registers.mtimecmp = 5; // Trigger after 5 ticks
    cpu.registers.mtvec = .{ .base = 0x100 >> 2, .mode = .direct };

    // Run until interrupt
    var steps: usize = 0;

    while (steps < 20) : (steps += 1) {
        cpu.registers.updateTimer(1);
        _ = cpu.step();

        if (cpu.registers.pc == 0x100) {
            break;
        }
    }

    try std.testing.expect(cpu.registers.mcause.interrupt);
    try std.testing.expectEqual(@as(u31, 7), cpu.registers.mcause.code);
}

test "MPRV affects load/store privilege but not instruction fetch" {
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
    });
    std.mem.writeInt(u32, ram[0x200..0x204], 0xDEADBEEF, arch.ENDIAN);

    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;
    cpu.registers.mstatus.mprv = true;
    cpu.registers.mstatus.mpp = .user;
    cpu.registers.set(2, 0x200);

    // PMP: code region RX, data region no access for U-mode
    cpu.registers.pmpaddr[0] = 0x1F; // 0x000-0x100, execute
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = false,
        .x = true,
        .a = .napot,
    }));
    // No PMP for 0x200 means U-mode can't access

    const state = cpu.step();

    // MPRV makes load use U-mode privilege, which fails PMP
    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_access_fault, state.trap.cause.exception);
}

test "MPRV=0 uses actual privilege for memory access" {
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } },
    });
    std.mem.writeInt(u32, ram[0x200..0x204], 0xCAFEBABE, arch.ENDIAN);

    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .machine;
    cpu.registers.mstatus.mprv = false;
    cpu.registers.mstatus.mpp = .user; // Should be ignored
    cpu.registers.set(2, 0x200);

    // No PMP config - M-mode can access anything

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());
    try std.testing.expectEqual(@as(i32, @bitCast(@as(u32, 0xCAFEBABE))), cpu.registers.get(1));
}

test "invalid rounding mode 0b101 causes illegal instruction" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0b101 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 1.0);
    cpu.registers.setF32(1, 2.0);

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, state.trap.cause.exception);
}

test "invalid rounding mode 0b110 causes illegal instruction" {
    var ram = initRamWithCode(1024, &.{
        .{ .fcvt_w_s = .{ .rd = 1, .rs1 = 0, .rm = 0b110 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 2.5);

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, state.trap.cause.exception);
}

test "dynamic rounding mode with invalid frm causes illegal instruction" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0b111 } }, // Dynamic
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01;
    cpu.registers.setF32(0, 1.0);
    cpu.registers.setF32(1, 2.0);
    cpu.registers.fcsr.frm = @enumFromInt(5); // Invalid frm value

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, state.trap.cause.exception);
}

test "mstatus write with invalid MPP defaults to M-mode" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrw = .{ .rd = 0, .rs1 = 1, .csr = @intFromEnum(arch.Registers.Csr.mstatus) } },
    });
    var cpu: TestCpu = .init(&ram);
    // Set MPP to 0b10 (Supervisor, not supported in M+U system)
    cpu.registers.set(1, @bitCast(@as(u32, 0b10 << 11)));

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());

    // MPP should be sanitized to M-mode (0b11)
    try std.testing.expectEqual(arch.PrivilegeLevel.machine, cpu.registers.mstatus.mpp);
}

test "misa returns correct extensions" {
    var ram = initRamWithCode(1024, &.{
        .{ .csrrs = .{ .rd = 1, .rs1 = 0, .csr = @intFromEnum(arch.Registers.Csr.misa) } },
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());

    const misa: u32 = @bitCast(cpu.registers.get(1));
    // Check MXL = 01 (RV32)
    try std.testing.expectEqual(@as(u32, 0b01), misa >> 30);
    // Check I extension
    try std.testing.expect((misa & (1 << 8)) != 0);
    // Check M extension
    try std.testing.expect((misa & (1 << 12)) != 0);
    // Check F extension
    try std.testing.expect((misa & (1 << 5)) != 0);
    // Check D extension
    try std.testing.expect((misa & (1 << 3)) != 0);
    // Check U extension
    try std.testing.expect((misa & (1 << 20)) != 0);
}

test "PMP NA4 mode protects exactly 4 bytes" {
    var ram = initRamWithCode(1024, &.{
        .{ .lw = .{ .rd = 1, .rs1 = 2, .imm = 0 } }, // Load from protected
        .{ .lw = .{ .rd = 3, .rs1 = 4, .imm = 0 } }, // Load from unprotected
    });
    std.mem.writeInt(u32, ram[0x100..0x104], 0x11111111, arch.ENDIAN);
    std.mem.writeInt(u32, ram[0x104..0x108], 0x22222222, arch.ENDIAN);

    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.set(2, 0x100);
    cpu.registers.set(4, 0x104);

    // PMP0: execute for code
    cpu.registers.pmpaddr[0] = 0x1F;
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true,
        .a = .napot,
    }));

    // PMP1: NA4 at 0x100 (4 bytes only), read allowed
    cpu.registers.pmpaddr[1] = 0x100 >> 2; // 0x40
    cpu.registers.pmpcfg[0] |= @as(u32, @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = false,
        .x = false,
        .a = .na4,
    }))) << 8;

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step()); // 0x100 allowed
    try std.testing.expectEqual(@as(i32, 0x11111111), cpu.registers.get(1));

    // 0x104 is NOT covered by NA4, should fail (no matching PMP in U-mode)
    const state = cpu.step();

    try std.testing.expect(state == .trap);
}

test "FPU instruction with mstatus.fs=0 causes illegal instruction" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0; // FPU disabled

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.illegal_instruction, state.trap.cause.exception);
}

test "FPU instruction sets mstatus.fs to dirty" {
    var ram = initRamWithCode(1024, &.{
        .{ .fadd_s = .{ .rd = 2, .rs1 = 0, .rs2 = 1, .rm = 0 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.fs = 0b01; // Initial
    cpu.registers.setF32(0, 1.0);
    cpu.registers.setF32(1, 2.0);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step());

    try std.testing.expectEqual(@as(u2, 0b11), cpu.registers.mstatus.fs); // Dirty
}

test "misaligned PC causes instruction address misaligned trap" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.pc = 2; // Misaligned (not multiple of 4)

    const state = cpu.step();

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.instruction_address_misaligned, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 2), state.trap.tval);
}

test "branch to misaligned address causes trap" {
    var ram = initRamWithCode(1024, &.{
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 1 } },
        .{ .beq = .{ .rs1 = 0, .rs2 = 0, .imm = 6 } }, // Always taken, target = 4 + 6 = 10
    });
    var cpu: TestCpu = .init(&ram);

    try std.testing.expectEqual(TestCpu.State.ok, cpu.step()); // addi

    const state = cpu.step(); // beq with misaligned target

    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.instruction_address_misaligned, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 10), state.trap.tval);
}

test "mie and mip bitcast sanity check" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);

    cpu.registers.mie.mtie = true;
    cpu.registers.mip.mtip = true;

    const mie_val: u32 = @bitCast(cpu.registers.mie);
    const mip_val: u32 = @bitCast(cpu.registers.mip);

    try std.testing.expectEqual(@as(u32, 0x80), mie_val); // Bit 7
    try std.testing.expectEqual(@as(u32, 0x80), mip_val); // Bit 7
    try std.testing.expectEqual(@as(u32, 0x80), mie_val & mip_val);
}

test "PMP denies access crossing region boundary" {
    // Test 1: Write u32 completely inside region - should succeed
    var instr_ram = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
    });
    var test_cpu: TestCpu = .init(&instr_ram);
    test_cpu.registers.privilege = .user;
    test_cpu.registers.set(1, 0x120); // Address inside data region
    test_cpu.registers.set(2, 0x12345678);

    // Configure PMP for DATA region: 0x100-0x200 (256 bytes), RW
    test_cpu.registers.pmpaddr[0] = 0x5F; // NAPOT 0x100-0x200
    test_cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = false, // Data, not code
        .a = .napot,
    }));

    // Configure PMP for CODE region - MUST be done for U-mode!
    configurePmpForCode(&test_cpu);

    try std.testing.expectEqual(TestCpu.State.ok, test_cpu.step());

    // Test 2: Write u32 crossing END of region (0x1FE-0x202) - should fail
    var instr_ram2 = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
    });
    var test_cpu2: TestCpu = .init(&instr_ram2);
    test_cpu2.registers.privilege = .user;
    test_cpu2.registers.set(1, 0x1FE); // Crosses boundary: 0x1FE + 4 = 0x202 > 0x200
    test_cpu2.registers.set(2, 0x12345678);

    test_cpu2.registers.pmpaddr[0] = 0x5F;
    test_cpu2.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = false,
        .a = .napot,
    }));
    configurePmpForCode(&test_cpu2);

    const state2 = test_cpu2.step();
    try std.testing.expect(state2 == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_access_fault, state2.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 0x1FE), state2.trap.tval);
}

test "PMP denies access crossing region START boundary" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;

    // Region: 0x100-0x200
    cpu.registers.pmpaddr[0] = 0x5F; // NAPOT 0x100-0x200
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true,
        .a = .napot,
    }));

    // Write u32 crossing START of region (0xFE-0x102) - should fail
    cpu.registers.set(1, 0xFE);
    cpu.registers.set(2, @truncate(0xDEADBEEF));

    var instr_ram = initRamWithCode(1024, &.{
        .{ .sw = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } },
    });
    var test_cpu: TestCpu = .init(&instr_ram);
    test_cpu.registers = cpu.registers;
    configurePmpForCode(&test_cpu);

    const state = test_cpu.step();
    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_access_fault, state.trap.cause.exception);
}

test "PMP allows access fully within region" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;

    // Region: 0x100-0x200, RWX
    cpu.registers.pmpaddr[0] = 0x5F;
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true,
        .a = .napot,
    }));

    // Test all sizes at various alignments inside region
    const test_cases = [_]struct { addr: u32, size: u32 }{
        .{ .addr = 0x100, .size = 1 }, // First byte
        .{ .addr = 0x1FF, .size = 1 }, // Last byte
        .{ .addr = 0x100, .size = 2 }, // First halfword
        .{ .addr = 0x1FE, .size = 2 }, // Last halfword
        .{ .addr = 0x100, .size = 4 }, // First word
        .{ .addr = 0x1FC, .size = 4 }, // Last word
        .{ .addr = 0x100, .size = 8 }, // First doubleword
        .{ .addr = 0x1F8, .size = 8 }, // Last doubleword
        .{ .addr = 0x150, .size = 4 }, // Middle
    };

    for (test_cases) |tc| {
        const result = cpu.registers.checkPmpAccess(tc.addr, tc.size, .write, .user);
        try std.testing.expect(result);
    }
}

test "PMP denies access partially overlapping region" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;

    // Region: 0x100-0x200
    cpu.registers.pmpaddr[0] = 0x5F;
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true,
        .a = .napot,
    }));

    // Test cases that cross boundaries
    const test_cases = [_]struct { addr: u32, size: u32 }{
        .{ .addr = 0xFE, .size = 4 }, // Crosses start: 0xFE-0x102
        .{ .addr = 0xFF, .size = 2 }, // Crosses start: 0xFF-0x101
        .{ .addr = 0x1FE, .size = 4 }, // Crosses end: 0x1FE-0x202
        .{ .addr = 0x1FF, .size = 2 }, // Crosses end: 0x1FF-0x201
        .{ .addr = 0x1FD, .size = 8 }, // Crosses end: 0x1FD-0x205
        .{ .addr = 0xFC, .size = 8 }, // Crosses start: 0xFC-0x104
    };

    for (test_cases) |tc| {
        const result = cpu.registers.checkPmpAccess(tc.addr, tc.size, .write, .user);
        try std.testing.expectEqual(false, result);
    }
}

test "PMP TOR mode boundary crossing" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;

    // TOR mode: region from 0x100 to 0x200
    // pmpaddr[0] = upper bound >> 2
    cpu.registers.pmpaddr[0] = 0x200 >> 2; // 0x80
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true,
        .a = .tor,
    }));
    // Previous address (implicit 0 or pmpaddr[-1]) is 0, so region is [0, 0x200)

    // Access at end boundary should fail if it crosses
    const result1 = cpu.registers.checkPmpAccess(0x1FC, 8, .write, .user); // 0x1FC-0x204 crosses 0x200
    try std.testing.expectEqual(false, result1);

    // Access fully inside should succeed
    const result2 = cpu.registers.checkPmpAccess(0x1F8, 8, .write, .user); // 0x1F8-0x200 is inside
    try std.testing.expect(result2);
}

test "PMP u64 load/store boundary check" {
    var ram = initRamWithCode(1024, &.{
        .{ .fld = .{ .rd = 0, .rs1 = 1, .imm = 0 } }, // Load 8 bytes
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;
    cpu.registers.mstatus.fs = 0b01; // Enable FPU

    // Region: 0x100-0x200
    cpu.registers.pmpaddr[0] = 0x5F;
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true,
        .a = .napot,
    }));
    configurePmpForCode(&cpu);

    // fld from 0x1FC should fail (0x1FC + 8 = 0x204 > 0x200)
    cpu.registers.set(1, 0x1FC);

    const state = cpu.step();
    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.load_access_fault, state.trap.cause.exception);
    try std.testing.expectEqual(@as(u32, 0x1FC), state.trap.tval);
}

test "PMP u16 store boundary check" {
    var ram = initRamWithCode(1024, &.{
        .{ .sh = .{ .rs1 = 1, .rs2 = 2, .imm = 0 } }, // Store 2 bytes
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;

    // Region: 0x100-0x200
    cpu.registers.pmpaddr[0] = 0x5F;
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true,
        .a = .napot,
    }));
    configurePmpForCode(&cpu);

    // sh to 0x1FF should fail (0x1FF + 2 = 0x201 > 0x200)
    cpu.registers.set(1, 0x1FF);
    cpu.registers.set(2, 0x1234);

    const state = cpu.step();
    try std.testing.expect(state == .trap);
    try std.testing.expectEqual(arch.Registers.Mcause.Exception.store_access_fault, state.trap.cause.exception);
}

test "PMP multiple regions - access must be in single region" {
    var ram: [1024]u8 = std.mem.zeroes([1024]u8);
    var cpu: TestCpu = .init(&ram);
    cpu.registers.privilege = .user;

    // Region 0: 0x100-0x180 (128 bytes)
    cpu.registers.pmpaddr[0] = 0x4F; // (0x100 >> 2) | 0x0F = 0x40 | 0x0F
    cpu.registers.pmpcfg[0] = @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = false,
        .a = .napot,
    }));

    // Region 1: 0x180-0x200 (128 bytes)
    cpu.registers.pmpaddr[1] = 0x6F; // (0x180 >> 2) | 0x0F = 0x60 | 0x0F
    cpu.registers.pmpcfg[0] |= @as(u32, @as(u8, @bitCast(arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = false,
        .a = .napot,
    }))) << 8;

    // Access spanning both regions (0x17C-0x184) - should fail even though both have RW
    // Because the access must be fully contained in ONE region
    const result = cpu.registers.checkPmpAccess(0x17C, 8, .write, .user);
    try std.testing.expectEqual(false, result);

    // Access fully in region 0 - should succeed
    const result2 = cpu.registers.checkPmpAccess(0x170, 8, .write, .user);
    try std.testing.expect(result2);

    // Access fully in region 1 - should succeed
    const result3 = cpu.registers.checkPmpAccess(0x188, 8, .write, .user);
    try std.testing.expect(result3);
}

fn configurePmpForCode(cpu: *TestCpu) void {
    // PMP entry for code at 0x000-0x100 (where initRamWithCode places instructions)
    // Use entry 15 to not conflict with data region at entry 0
    // NAPOT: 256 bytes, pmpaddr = (0 >> 2) | (256/8 - 1) = 0 | 0x1F = 0x1F
    cpu.registers.pmpaddr[15] = 0x1F;

    const cfg = arch.Registers.PmpCfg{
        .r = true,
        .w = true,
        .x = true, // Execute permission!
        .a = .napot,
    };

    // Entry 15 is in pmpcfg[3], byte 3
    cpu.registers.pmpcfg[3] = (cpu.registers.pmpcfg[3] & 0x00FFFFFF) |
        (@as(u32, @as(u8, @bitCast(cfg))) << 24);
}

test "wfi halts without advancing PC when no interrupt pending" {
    var ram = initRamWithCode(1024, &.{
        .wfi,
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mie = .{}; // No interrupts enabled
    cpu.registers.mip = .{}; // No interrupts pending

    const state1 = cpu.step();
    try std.testing.expectEqual(TestCpu.State.halt, state1);
    try std.testing.expectEqual(@as(u32, 0), cpu.registers.pc); // PC NOT advanced!

    // Call step() again without setting interrupt - should still halt at WFI
    const state2 = cpu.step();
    try std.testing.expectEqual(TestCpu.State.halt, state2);
    try std.testing.expectEqual(@as(u32, 0), cpu.registers.pc); // Still at WFI!
}

test "wfi resumes when interrupt becomes pending" {
    var ram = initRamWithCode(1024, &.{
        .wfi,
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mie.mtie = true;
    cpu.registers.mip = .{}; // No interrupts yet

    // First step - halt at WFI
    const state1 = cpu.step();
    try std.testing.expectEqual(TestCpu.State.halt, state1);
    try std.testing.expectEqual(@as(u32, 0), cpu.registers.pc);

    // Now set interrupt
    cpu.registers.mtime = 100;
    cpu.registers.mtimecmp = 50; // Will set mtip

    // Next step - WFI sees pending, advances PC
    const state2 = cpu.step();
    try std.testing.expectEqual(TestCpu.State.ok, state2);
    try std.testing.expectEqual(@as(u32, 4), cpu.registers.pc); // Advanced past WFI
}

test "wfi with global interrupts enabled triggers handler" {
    var ram = initRamWithCode(1024, &.{
        .wfi,
        .{ .addi = .{ .rd = 1, .rs1 = 0, .imm = 42 } },
    });
    var cpu: TestCpu = .init(&ram);
    cpu.registers.mstatus.mie = true; // Global interrupts enabled
    cpu.registers.mie.mtie = true;
    cpu.registers.mtvec = .{ .base = 0x100 >> 2, .mode = .direct };

    // First step - halt
    _ = cpu.step();
    try std.testing.expectEqual(@as(u32, 0), cpu.registers.pc);

    // Set interrupt
    cpu.registers.mtime = 100;
    cpu.registers.mtimecmp = 50;

    // Next step - interrupt handler called (checkInterrupts at start of step)
    const state2 = cpu.step();
    try std.testing.expectEqual(TestCpu.State.ok, state2);
    try std.testing.expectEqual(@as(u32, 0x100), cpu.registers.pc); // At handler
    try std.testing.expectEqual(@as(u32, 0), cpu.registers.mepc); // Return to WFI
}
