const std = @import("std");

const arch = @import("../../arch.zig");
const jit = @import("../../jit.zig");
const CodeArena = @import("../code_arena.zig").CodeArena;
const EngineConfig = @import("../engine_config.zig").EngineConfig;

pub fn Compiler(comptime config: EngineConfig) type {
    comptime {
        if (config.jit.max_block_size == 0) {
            @compileError("max_block_size must be > 0");
        }
        if (config.jit.max_block_size > 1024) {
            @compileError("max_block_size too large (max 1024)");
        }
        if (config.jit.code_arena_size < 4096) {
            @compileError("code_arena_size too small");
        }
    }

    return struct {
        pub const Emitter = struct {
            buffer: []u8,
            index: usize,

            pub const Register = enum(u8) {
                x0,
                x1,
                x2,
                x3,
                x4,
                x5,
                x6,
                x7,
                x8,
                x9,
                x10,
                x11,
                x12,
                x13,
                x14,
                x15,
                x16,
                x17,
                x18,
                x19,
                x20,
                x21,
                x22,
                x23,
                x24,
                x25,
                x26,
                x27,
                x28,
                x29,
                x30,
                sp,
                xzr,

                pub inline fn encode(this: Register) u5 {
                    const val = @intFromEnum(this);
                    if (val >= 31) return 31;
                    return @intCast(val);
                }
            };

            pub const Condition = enum(u4) {
                eq = 0b0000,
                ne = 0b0001,
                cs = 0b0010,
                cc = 0b0011,
                mi = 0b0100,
                pl = 0b0101,
                vs = 0b0110,
                vc = 0b0111,
                hi = 0b1000,
                ls = 0b1001,
                ge = 0b1010,
                lt = 0b1011,
                gt = 0b1100,
                le = 0b1101,
                al = 0b1110,

                pub inline fn invert(this: Condition) Condition {
                    return @enumFromInt(@intFromEnum(this) ^ 1);
                }
            };

            pub inline fn init(buffer: []u8) Emitter {
                return .{ .buffer = buffer, .index = 0 };
            }

            pub inline fn reset(this: *Emitter) void {
                this.index = 0;
            }

            pub inline fn getCode(this: *const Emitter) []const u8 {
                return this.buffer[0..this.index];
            }

            pub inline fn currentOffset(this: *const Emitter) usize {
                return this.index;
            }

            pub inline fn remainingCapacity(this: *const Emitter) usize {
                return this.buffer.len - this.index;
            }

            inline fn emit(this: *Emitter, inst: u32) void {
                std.debug.assert(this.index + 4 <= this.buffer.len);

                std.mem.writeInt(u32, this.buffer[this.index..][0..4], inst, .little);
                this.index += 4;
            }

            pub inline fn movz32(this: *Emitter, rd: Register, imm16: u16, shift: u5) void {
                std.debug.assert(shift == 0 or shift == 16);

                const hw: u1 = if (shift >= 16) 1 else 0;
                const inst: u32 = 0b0_10_100101_00_0000000000000000_00000 |
                    (@as(u32, hw) << 21) |
                    (@as(u32, imm16) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn movk32(this: *Emitter, rd: Register, imm16: u16, shift: u5) void {
                std.debug.assert(shift == 0 or shift == 16);

                const hw: u1 = if (shift >= 16) 1 else 0;
                const inst: u32 = 0b0_11_100101_00_0000000000000000_00000 |
                    (@as(u32, hw) << 21) |
                    (@as(u32, imm16) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn movn32(this: *Emitter, rd: Register, imm16: u16, shift: u5) void {
                std.debug.assert(shift == 0 or shift == 16);

                const hw: u1 = if (shift >= 16) 1 else 0;
                const inst: u32 = 0b0_00_100101_00_0000000000000000_00000 |
                    (@as(u32, hw) << 21) |
                    (@as(u32, imm16) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn movImm32(this: *Emitter, rd: Register, imm: u32) void {
                const lo: u16 = @truncate(imm);
                const hi: u16 = @truncate(imm >> 16);

                if (hi == 0) {
                    this.movz32(rd, lo, 0);
                } else if (lo == 0) {
                    this.movz32(rd, hi, 16);
                } else if (hi == 0xFFFF) {
                    this.movn32(rd, ~lo, 0);
                } else {
                    this.movz32(rd, lo, 0);
                    this.movk32(rd, hi, 16);
                }
            }

            pub inline fn movz64(this: *Emitter, rd: Register, imm16: u16, shift: u6) void {
                std.debug.assert(shift == 0 or shift == 16 or shift == 32 or shift == 48);

                const hw: u2 = @intCast(shift / 16);
                const inst: u32 = 0b1_10_100101_00_0000000000000000_00000 |
                    (@as(u32, hw) << 21) |
                    (@as(u32, imm16) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn movk64(this: *Emitter, rd: Register, imm16: u16, shift: u6) void {
                std.debug.assert(shift == 0 or shift == 16 or shift == 32 or shift == 48);

                const hw: u2 = @intCast(shift / 16);
                const inst: u32 = 0b1_11_100101_00_0000000000000000_00000 |
                    (@as(u32, hw) << 21) |
                    (@as(u32, imm16) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn movImm64(this: *Emitter, rd: Register, imm: u64) void {
                const parts: [4]u16 = .{
                    @truncate(imm),
                    @truncate(imm >> 16),
                    @truncate(imm >> 32),
                    @truncate(imm >> 48),
                };

                var first: ?usize = null;

                for (0..4) |i| {
                    if (parts[i] != 0) {
                        first = i;

                        break;
                    }
                }

                if (first == null) {
                    this.movz64(rd, 0, 0);

                    return;
                }

                this.movz64(rd, parts[first.?], @as(u6, @intCast(first.?)) * 16);

                for ((first.? + 1)..4) |i| {
                    if (parts[i] != 0) {
                        this.movk64(rd, parts[i], @as(u6, @intCast(i)) * 16);
                    }
                }
            }

            pub inline fn movReg32(this: *Emitter, rd: Register, rm: Register) void {
                this.orrReg32(rd, .xzr, rm);
            }

            pub inline fn movReg64(this: *Emitter, rd: Register, rm: Register) void {
                const inst: u32 = 0b1_01_01010_00_0_00000_000000_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, Register.xzr.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn addImm32(this: *Emitter, rd: Register, rn: Register, imm12: u12) void {
                const inst: u32 = 0b0_0_0_10001_00_000000000000_00000_00000 |
                    (@as(u32, imm12) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn addImm64(this: *Emitter, rd: Register, rn: Register, imm12: u12) void {
                const inst: u32 = 0b1_0_0_10001_00_000000000000_00000_00000 |
                    (@as(u32, imm12) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn addReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_0_0_01011_00_0_00000_000000_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn addReg64(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b1_0_0_01011_00_0_00000_000000_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn addLsl32(this: *Emitter, rd: Register, rn: Register, rm: Register, shift: u5) void {
                const inst: u32 = 0b0_0_0_01011_00_0_00000_000000_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, shift) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn subImm32(this: *Emitter, rd: Register, rn: Register, imm12: u12) void {
                const inst: u32 = 0b0_1_0_10001_00_000000000000_00000_00000 |
                    (@as(u32, imm12) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn subReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_1_0_01011_00_0_00000_000000_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn negReg32(this: *Emitter, rd: Register, rm: Register) void {
                const inst: u32 = 0b0_1_0_01011_00_0_00000_000000_11111_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn andReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_00_01010_00_0_00000_000000_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn orrReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_01_01010_00_0_00000_000000_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn eorReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_10_01010_00_0_00000_000000_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn mvnReg32(this: *Emitter, rd: Register, rm: Register) void {
                const inst: u32 = 0b0_01_01010_00_1_00000_000000_11111_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn bicReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_00_01010_00_1_00000_000000_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn ornReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_01_01010_00_1_00000_000000_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn eonReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_10_01010_00_1_00000_000000_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn orrReg64(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0xAA000000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn lslvReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_0_0_11010110_00000_0010_00_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn lsrvReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_0_0_11010110_00000_0010_01_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn asrvReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_0_0_11010110_00000_0010_10_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn rorvReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0x1AC02C00 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn lslImm32(this: *Emitter, rd: Register, rn: Register, shift: u5) void {
                if (shift == 0) {
                    this.movReg32(rd, rn);

                    return;
                }

                const immr: u6 = @intCast((@as(u6, 32) -% @as(u6, shift)) & 0x1F);
                const imms: u6 = @intCast(31 - @as(u6, shift));
                const inst: u32 = 0b0_10_100110_0_000000_000000_00000_00000 |
                    (@as(u32, immr) << 16) |
                    (@as(u32, imms) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn lsrImm32(this: *Emitter, rd: Register, rn: Register, shift: u5) void {
                if (shift == 0) {
                    this.movReg32(rd, rn);

                    return;
                }

                const inst: u32 = 0b0_10_100110_0_000000_011111_00000_00000 |
                    (@as(u32, shift) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn asrImm32(this: *Emitter, rd: Register, rn: Register, shift: u5) void {
                if (shift == 0) {
                    this.movReg32(rd, rn);

                    return;
                }

                const inst: u32 = 0b0_00_100110_0_000000_011111_00000_00000 |
                    (@as(u32, shift) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn lsrImm64(this: *Emitter, rd: Register, rn: Register, shift: u6) void {
                if (shift == 0) {
                    this.movReg64(rd, rn);

                    return;
                }

                const inst: u32 = 0b1_10_100110_1_000000_111111_00000_00000 |
                    (@as(u32, shift) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn rorImm32(this: *Emitter, rd: Register, rs: Register, shift: u5) void {
                const inst: u32 = 0x13800000 |
                    (@as(u32, rs.encode()) << 16) |
                    (@as(u32, shift) << 10) |
                    (@as(u32, rs.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn sxtb32(this: *Emitter, rd: Register, rn: Register) void {
                const inst: u32 = 0b0_00_100110_0_000000_000111_00000_00000 |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn sxth32(this: *Emitter, rd: Register, rn: Register) void {
                const inst: u32 = 0b0_00_100110_0_000000_001111_00000_00000 |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn uxtb32(this: *Emitter, rd: Register, rn: Register) void {
                const inst: u32 = 0b0_10_100110_0_000000_000111_00000_00000 |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn uxth32(this: *Emitter, rd: Register, rn: Register) void {
                const inst: u32 = 0b0_10_100110_0_000000_001111_00000_00000 |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn cmpReg32(this: *Emitter, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_1_1_01011_00_0_00000_000000_00000_11111 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5);

                this.emit(inst);
            }

            pub inline fn cmpImm32(this: *Emitter, rn: Register, imm12: u12) void {
                const inst: u32 = 0b0_1_1_10001_00_000000000000_00000_11111 |
                    (@as(u32, imm12) << 10) |
                    (@as(u32, rn.encode()) << 5);

                this.emit(inst);
            }

            pub inline fn tstReg32(this: *Emitter, rn: Register, rm: Register) void {
                const inst: u32 = 0b0_11_01010_00_0_00000_000000_00000_11111 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5);

                this.emit(inst);
            }

            pub inline fn cset(this: *Emitter, rd: Register, cond: Condition) void {
                const inv_cond = cond.invert();
                const inst: u32 = 0b0_0_0_11010100_11111_0000_0_1_11111_00000 |
                    (@as(u32, @intFromEnum(inv_cond)) << 12) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn csel32(this: *Emitter, rd: Register, rn: Register, rm: Register, cond: Condition) void {
                const inst: u32 = 0b0_0_0_11010100_00000_0000_0_0_00000_00000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, @intFromEnum(cond)) << 12) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn ldrOffset32(this: *Emitter, rt: Register, rn: Register, offset: u14) void {
                std.debug.assert(offset % 4 == 0);

                const imm12: u12 = @intCast(offset / 4);
                const inst: u32 = 0b10_111_0_01_01_000000000000_00000_00000 |
                    (@as(u32, imm12) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rt.encode());

                this.emit(inst);
            }

            pub inline fn strOffset32(this: *Emitter, rt: Register, rn: Register, offset: u14) void {
                std.debug.assert(offset % 4 == 0);

                const imm12: u12 = @intCast(offset / 4);
                const inst: u32 = 0b10_111_0_01_00_000000000000_00000_00000 |
                    (@as(u32, imm12) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rt.encode());

                this.emit(inst);
            }

            pub inline fn ldrOffset64(this: *Emitter, rt: Register, rn: Register, offset: u15) void {
                const imm12: u12 = @intCast(offset / 8);
                const inst: u32 = 0b11_111_0_01_01_000000000000_00000_00000 |
                    (@as(u32, imm12) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rt.encode());

                this.emit(inst);
            }

            pub inline fn strOffset64(this: *Emitter, rt: Register, rn: Register, offset: u15) void {
                const imm12: u12 = @intCast(offset / 8);
                const inst: u32 = 0b11_111_0_01_00_000000000000_00000_00000 |
                    (@as(u32, imm12) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rt.encode());

                this.emit(inst);
            }

            pub inline fn stpPre64(this: *Emitter, rt1: Register, rt2: Register, rn: Register, offset: i10) void {
                std.debug.assert(@rem(offset, 8) == 0);
                std.debug.assert(offset >= -512 and offset <= 504);

                const imm7: u7 = @bitCast(@as(i7, @intCast(@divExact(offset, 8))));
                const inst: u32 = 0b10_101_0_011_0_0000000_00000_00000_00000 |
                    (@as(u32, imm7) << 15) |
                    (@as(u32, rt2.encode()) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rt1.encode());

                this.emit(inst);
            }

            pub inline fn ldpPost64(this: *Emitter, rt1: Register, rt2: Register, rn: Register, offset: i10) void {
                std.debug.assert(@rem(offset, 8) == 0);
                std.debug.assert(offset >= -512 and offset <= 504);

                const imm7: u7 = @bitCast(@as(i7, @intCast(@divExact(offset, 8))));
                const inst: u32 = 0b10_101_0_001_1_0000000_00000_00000_00000 |
                    (@as(u32, imm7) << 15) |
                    (@as(u32, rt2.encode()) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rt1.encode());

                this.emit(inst);
            }

            pub inline fn ret(this: *Emitter) void {
                this.emit(0xD65F03C0);
            }

            pub inline fn bl(this: *Emitter, offset: i28) void {
                std.debug.assert(@mod(offset, 4) == 0);

                const imm26: u26 = @bitCast(@as(i26, @intCast(@divExact(offset, 4))));
                const inst: u32 = 0b1_00101_00000000000000000000000000 | @as(u32, imm26);

                this.emit(inst);
            }

            pub inline fn blr(this: *Emitter, rn: Register) void {
                const inst: u32 = 0xD63F0000 | (@as(u32, rn.encode()) << 5);
                this.emit(inst);
            }

            pub inline fn b(this: *Emitter, offset: i28) void {
                std.debug.assert(@mod(offset, 4) == 0);

                const imm26: u26 = @bitCast(@as(i26, @intCast(@divExact(offset, 4))));
                const inst: u32 = 0b0_00101_00000000000000000000000000 | @as(u32, imm26);

                this.emit(inst);
            }

            pub inline fn bCond(this: *Emitter, cond: Condition, offset: i21) void {
                std.debug.assert(@mod(offset, 4) == 0);

                const imm19: u19 = @bitCast(@as(i19, @intCast(@divExact(offset, 4))));
                const inst: u32 = 0b0101010_0_0000000000000000000_0_0000 |
                    (@as(u32, imm19) << 5) |
                    @as(u32, @intFromEnum(cond));

                this.emit(inst);
            }

            pub inline fn bne(this: *Emitter, offset: i21) void {
                const imm19: u32 = @bitCast(@as(i32, offset >> 2) & 0x7FFFF);
                this.emit(0x54000001 | (imm19 << 5));
            }

            pub inline fn beq(this: *Emitter, offset: i21) void {
                const imm19: u32 = @bitCast(@as(i32, offset >> 2) & 0x7FFFF);
                this.emit(0x54000000 | (imm19 << 5));
            }

            pub inline fn patchBranch(this: *Emitter, branch_offset: usize, target_offset: usize) void {
                const delta = @as(i32, @intCast(target_offset)) - @as(i32, @intCast(branch_offset));
                const imm19: u32 = @bitCast((delta >> 2) & 0x7FFFF);
                const ptr: *u32 = @ptrCast(@alignCast(&this.buffer[branch_offset]));
                const existing = ptr.*;

                ptr.* = (existing & 0xFF00001F) | (imm19 << 5);
            }

            pub inline fn patchB(this: *Emitter, branch_offset: usize, target_offset: usize) void {
                const delta = @as(i32, @intCast(target_offset)) - @as(i32, @intCast(branch_offset));
                const imm26: u26 = @bitCast(@as(i26, @intCast(@divExact(delta, 4))));
                const ptr: *u32 = @ptrCast(@alignCast(&this.buffer[branch_offset]));

                ptr.* = 0x14000000 | @as(u32, imm26);
            }

            pub inline fn clz32(this: *Emitter, rd: Register, rn: Register) void {
                const inst: u32 = 0x5AC01000 |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn rbit32(this: *Emitter, rd: Register, rn: Register) void {
                const inst: u32 = 0x5AC00000 |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn rev32(this: *Emitter, rd: Register, rn: Register) void {
                const inst: u32 = 0x5AC00800 |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn mulReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0x1B007C00 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn msubReg32(this: *Emitter, rd: Register, rn: Register, rm: Register, ra: Register) void {
                const inst: u32 = 0x1B008000 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, ra.encode()) << 10) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn smull(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0x9B207C00 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn umull(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0x9BA07C00 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn sdivReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0x1AC00C00 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }

            pub inline fn udivReg32(this: *Emitter, rd: Register, rn: Register, rm: Register) void {
                const inst: u32 = 0x1AC00800 |
                    (@as(u32, rm.encode()) << 16) |
                    (@as(u32, rn.encode()) << 5) |
                    @as(u32, rd.encode());

                this.emit(inst);
            }
        };

        const Self = @This();

        pub const BlockFn = CodeArena.BlockFn;

        const offsets = config.callbacks.get_offsets();

        comptime {
            if (offsets.regs > 65535 or offsets.pc > 65535 or offsets.float > 65535) {
                @compileError("Field offsets too large for efficient code generation");
            }
        }

        const EmitResult = enum {
            next,
            end_block,
            epilogue_emitted,
        };

        const cpu_ptr = Emitter.Register.x19;
        const regs_base = Emitter.Register.x20;
        const float_base = Emitter.Register.x21;

        const scratch1 = Emitter.Register.x9;
        const scratch2 = Emitter.Register.x10;
        const scratch3 = Emitter.Register.x11;
        const scratch4 = Emitter.Register.x12;

        const prologue_size: usize = 20;
        const epilogue_size: usize = 32;
        const update_counters_size: usize = 80;
        const trap_size: usize = 64;
        const max_instruction_size: usize = 512;
        const safety_margin: usize = 128;
        const instruction_overhead: usize = max_instruction_size + update_counters_size + epilogue_size + safety_margin;
        const max_code_per_block: usize = prologue_size +
            (@as(usize, config.jit.max_block_size) * instruction_overhead) +
            update_counters_size + epilogue_size + safety_margin;

        emit: Emitter,
        instruction_count: u32,
        cycle_count: u64,

        pub inline fn init() Self {
            return .{
                .emit = undefined,
                .instruction_count = 0,
                .cycle_count = 0,
            };
        }

        pub inline fn deinit(this: *Self) void {
            _ = this;
        }

        pub fn compileBlock(
            this: *Self,
            arena: *CodeArena,
            cpu: *anyopaque,
            start_pc: u32,
        ) error{OutOfCodeMemory}!BlockFn {
            const buffer = arena.beginBlock(max_code_per_block) orelse {
                return error.OutOfCodeMemory;
            };

            this.emit = Emitter.init(buffer);
            this.instruction_count = 0;
            this.cycle_count = 0;

            this.emitPrologue();

            var pc = start_pc;
            var needs_epilogue = true;

            while (this.instruction_count < config.jit.max_block_size) {
                if (this.emit.remainingCapacity() < instruction_overhead) {
                    break;
                }

                const raw = config.callbacks.read_instruction(cpu, pc) orelse {
                    this.emitUpdateCounters();
                    this.emitTrapConst(pc, .instruction_access_fault, pc);
                    needs_epilogue = false;

                    break;
                };

                const inst = arch.Instruction.decode(raw) catch {
                    this.emitUpdateCounters();
                    this.emitTrapConst(pc, .illegal_instruction, raw);
                    needs_epilogue = false;

                    break;
                };

                this.instruction_count += 1;

                if (comptime config.hooks.instruction_cost) |cost_fn| {
                    this.cycle_count += cost_fn(inst);
                } else {
                    this.cycle_count += 1;
                }

                const emit_result = this.emitInstruction(inst, pc);

                pc +%= 4;

                switch (emit_result) {
                    .next => continue,
                    .end_block => break,
                    .epilogue_emitted => {
                        needs_epilogue = false;

                        break;
                    },
                }
            }

            if (needs_epilogue) {
                this.emitUpdateCounters();
                this.emitEpilogue(pc, .ok);
            }

            const code_len = this.emit.getCode().len;
            return arena.commitBlock(code_len);
        }

        inline fn emitPrologue(this: *Self) void {
            this.emit.stpPre64(.x19, .x20, .sp, -16);
            this.emit.stpPre64(.x21, .x30, .sp, -16);
            this.emit.movReg64(cpu_ptr, .x0);
            this.emit.addImm64(regs_base, cpu_ptr, offsets.regs);
            this.emit.addImm64(float_base, cpu_ptr, offsets.float);
        }

        inline fn emitEpilogue(this: *Self, new_pc: u32, result: EngineConfig.State) void {
            this.emit.movImm32(scratch1, new_pc);
            this.emitStoreField32(offsets.pc, scratch1);
            this.emitEpilogueNoPc(result);
        }

        inline fn emitEpilogueNoPc(this: *Self, result: EngineConfig.State) void {
            this.emit.movImm32(.x0, @intFromEnum(result));
            this.emit.ldpPost64(.x21, .x30, .sp, 16);
            this.emit.ldpPost64(.x19, .x20, .sp, 16);
            this.emit.ret();
        }

        inline fn emitTrapConst(this: *Self, pc: u32, cause: arch.Registers.Mcause.Exception, tval: u32) void {
            this.emit.movImm32(scratch1, @intFromEnum(cause));
            this.emitStoreField32(offsets.trap_cause, scratch1);
            this.emit.movImm32(scratch1, tval);
            this.emitStoreField32(offsets.trap_tval, scratch1);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitTrapRuntime(this: *Self, pc: u32, cause: arch.Registers.Mcause.Exception) void {
            this.emitStoreField32(offsets.trap_tval, scratch1);
            this.emit.movImm32(scratch2, @intFromEnum(cause));
            this.emitStoreField32(offsets.trap_cause, scratch2);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitUpdateCounters(this: *Self) void {
            const inst_count = this.instruction_count;
            const cycles = this.cycle_count;

            if (inst_count == 0) {
                return;
            }

            this.emitAdd64FieldLarge(offsets.cycle, cycles);
            this.emitAdd64Field(offsets.instret, inst_count);

            if (comptime config.vars.timer_ticks_per_cycle > 0) {
                const mtime_increment = cycles * config.vars.timer_ticks_per_cycle;
                this.emitAdd64FieldLarge(offsets.mtime, mtime_increment);
            }
        }

        inline fn emitAdd64Field(this: *Self, field_offset: usize, value: u32) void {
            this.emitLoadFieldAddr(scratch1, field_offset);
            this.emit.ldrOffset64(scratch2, scratch1, 0);

            if (value <= 4095) {
                this.emit.addImm64(scratch2, scratch2, @intCast(value));
            } else {
                this.emit.movImm32(scratch3, value);
                this.emit.addReg64(scratch2, scratch2, scratch3);
            }

            this.emit.strOffset64(scratch2, scratch1, 0);
        }

        inline fn emitAdd64FieldLarge(this: *Self, field_offset: usize, value: u64) void {
            this.emitLoadFieldAddr(scratch1, field_offset);
            this.emit.ldrOffset64(scratch2, scratch1, 0);

            if (value <= 4095) {
                this.emit.addImm64(scratch2, scratch2, @intCast(value));
            } else {
                this.emit.movImm64(scratch3, value);
                this.emit.addReg64(scratch2, scratch2, scratch3);
            }

            this.emit.strOffset64(scratch2, scratch1, 0);
        }

        inline fn emitLoadFieldAddr(this: *Self, dest: Emitter.Register, field_offset: usize) void {
            if (field_offset <= 4095) {
                this.emit.addImm64(dest, cpu_ptr, @intCast(field_offset));
            } else if (field_offset <= 0xFFFFFFFF) {
                this.emit.movImm32(dest, @intCast(field_offset));
                this.emit.addReg64(dest, cpu_ptr, dest);
            } else {
                this.emit.movImm64(dest, field_offset);
                this.emit.addReg64(dest, cpu_ptr, dest);
            }
        }

        inline fn emitLoadField32(this: *Self, dest: Emitter.Register, field_offset: usize) void {
            if (field_offset <= 16380) {
                this.emit.ldrOffset32(dest, cpu_ptr, @intCast(field_offset));
            } else {
                this.emitLoadFieldAddr(scratch4, field_offset);
                this.emit.ldrOffset32(dest, scratch4, 0);
            }
        }

        inline fn emitStoreField32(this: *Self, field_offset: usize, src: Emitter.Register) void {
            if (field_offset <= 16380) {
                this.emit.strOffset32(src, cpu_ptr, @intCast(field_offset));
            } else {
                this.emitLoadFieldAddr(scratch4, field_offset);
                this.emit.strOffset32(src, scratch4, 0);
            }
        }

        inline fn loadGuestReg(this: *Self, host_reg: Emitter.Register, guest_reg: u8) void {
            const safe_reg = guest_reg & 0x1F;

            if (safe_reg == 0) {
                this.emit.movImm32(host_reg, 0);
            } else {
                const offset: u14 = @as(u14, safe_reg) * 4;
                this.emit.ldrOffset32(host_reg, regs_base, offset);
            }
        }

        inline fn storeGuestReg(this: *Self, guest_reg: u8, host_reg: Emitter.Register) void {
            const safe_reg = guest_reg & 0x1F;

            if (safe_reg == 0) {
                return;
            }

            const offset: u14 = @as(u14, safe_reg) * 4;
            this.emit.strOffset32(host_reg, regs_base, offset);
        }

        inline fn emitAddImmediate(this: *Self, rd: Emitter.Register, rn: Emitter.Register, imm: i32) void {
            if (imm == 0) {
                if (rd != rn) this.emit.movReg32(rd, rn);
            } else if (imm > 0 and imm <= 4095) {
                this.emit.addImm32(rd, rn, @intCast(imm));
            } else if (imm < 0 and imm >= -4095) {
                this.emit.subImm32(rd, rn, @intCast(-imm));
            } else {
                this.emit.movImm32(scratch4, @bitCast(imm));
                this.emit.addReg32(rd, rn, scratch4);
            }
        }

        inline fn addPcOffset(pc: u32, offset: i32) u32 {
            const pc_signed: i32 = @bitCast(pc);

            return @bitCast(pc_signed +% offset);
        }

        inline fn emitInstruction(this: *Self, inst: arch.Instruction, pc: u32) EmitResult {
            switch (inst) {
                // I
                .lui => |i| this.emitLUI(i),
                .auipc => |i| this.emitAUIPC(i, pc),
                .addi => |i| this.emitADDI(i),
                .slti => |i| this.emitSLTI(i),
                .sltiu => |i| this.emitSLTIU(i),
                .xori => |i| this.emitXORI(i),
                .ori => |i| this.emitORI(i),
                .andi => |i| this.emitANDI(i),
                .slli => |i| this.emitSLLI(i),
                .srli => |i| this.emitSRLI(i),
                .srai => |i| this.emitSRAI(i),
                .add => |i| this.emitADD(i),
                .sub => |i| this.emitSUB(i),
                .sll => |i| this.emitSLL(i),
                .slt => |i| this.emitSLT(i),
                .sltu => |i| this.emitSLTU(i),
                .xor => |i| this.emitXOR(i),
                .srl => |i| this.emitSRL(i),
                .sra => |i| this.emitSRA(i),
                .@"or" => |i| this.emitOR(i),
                .@"and" => |i| this.emitAND(i),
                .jal => |i| {
                    this.emitUpdateCounters();
                    this.emitJAL(i, pc);

                    return .epilogue_emitted;
                },
                .jalr => |i| {
                    this.emitUpdateCounters();
                    this.emitJALR(i, pc);

                    return .epilogue_emitted;
                },
                .beq => |i| {
                    this.emitUpdateCounters();
                    this.emitBranch(i, pc, .eq);

                    return .epilogue_emitted;
                },
                .bne => |i| {
                    this.emitUpdateCounters();
                    this.emitBranch(i, pc, .ne);

                    return .epilogue_emitted;
                },
                .blt => |i| {
                    this.emitUpdateCounters();
                    this.emitBranch(i, pc, .lt);

                    return .epilogue_emitted;
                },
                .bge => |i| {
                    this.emitUpdateCounters();
                    this.emitBranch(i, pc, .ge);

                    return .epilogue_emitted;
                },
                .bltu => |i| {
                    this.emitUpdateCounters();
                    this.emitBranch(i, pc, .cc);

                    return .epilogue_emitted;
                },
                .bgeu => |i| {
                    this.emitUpdateCounters();
                    this.emitBranch(i, pc, .cs);

                    return .epilogue_emitted;
                },
                .lb => |i| this.emitLoad(i, pc, .byte_signed),
                .lh => |i| this.emitLoad(i, pc, .half_signed),
                .lw => |i| this.emitLoad(i, pc, .word),
                .lbu => |i| this.emitLoad(i, pc, .byte_unsigned),
                .lhu => |i| this.emitLoad(i, pc, .half_unsigned),
                .sb => |i| this.emitStore(i, pc, .byte),
                .sh => |i| this.emitStore(i, pc, .half),
                .sw => |i| this.emitStore(i, pc, .word),
                .ecall => {
                    this.emitUpdateCounters();
                    this.emitEcall(pc);

                    return .epilogue_emitted;
                },
                .ebreak => {
                    this.emitUpdateCounters();
                    this.emitEbreak(pc);

                    return .epilogue_emitted;
                },
                .fence => {},
                // M
                .mul => |i| this.emitMUL(i),
                .mulh => |i| this.emitMULH(i),
                .mulhsu => |i| this.emitMULHSU(i),
                .mulhu => |i| this.emitMULHU(i),
                .div => |i| this.emitDIV(i),
                .divu => |i| this.emitDIVU(i),
                .rem => |i| this.emitREM(i),
                .remu => |i| this.emitREMU(i),
                // F
                .flw => |i| this.emitFLW(i, pc),
                .fsw => |i| this.emitFSW(i, pc),
                .fmadd_s => |i| this.emitFpFmaOp(i, pc, .fmadd),
                .fmsub_s => |i| this.emitFpFmaOp(i, pc, .fmsub),
                .fnmadd_s => |i| this.emitFpFmaOp(i, pc, .fnmadd),
                .fnmsub_s => |i| this.emitFpFmaOp(i, pc, .fnmsub),
                .fadd_s => |i| this.emitFpBinaryOp(i, pc, i.rm, .add),
                .fsub_s => |i| this.emitFpBinaryOp(i, pc, i.rm, .sub),
                .fmul_s => |i| this.emitFpBinaryOp(i, pc, i.rm, .mul),
                .fdiv_s => |i| this.emitFpBinaryOp(i, pc, i.rm, .div),
                .fsqrt_s => |i| this.emitFpUnaryOp(i, pc, .sqrt),
                .fsgnj_s => |i| this.emitFSGNJ_S(i, pc),
                .fsgnjn_s => |i| this.emitFSGNJN_S(i, pc),
                .fsgnjx_s => |i| this.emitFSGNJX_S(i, pc),
                .fmin_s => |i| this.emitFpBinaryOp(i, pc, 0, .min),
                .fmax_s => |i| this.emitFpBinaryOp(i, pc, 0, .max),
                .fcvt_w_s => |i| this.emitFpUnaryOp(i, pc, .fcvt_w_s),
                .fcvt_wu_s => |i| this.emitFpUnaryOp(i, pc, .fcvt_wu_s),
                .fmv_x_w => |i| this.emitFMV_X_W(i, pc),
                .feq_s => |i| this.emitFpCmpOp(i, pc, .eq),
                .flt_s => |i| this.emitFpCmpOp(i, pc, .lt),
                .fle_s => |i| this.emitFpCmpOp(i, pc, .le),
                .fclass_s => |i| this.emitFCLASS_S(i, pc),
                .fcvt_s_w => |i| this.emitFpUnaryOp(i, pc, .fcvt_s_w),
                .fcvt_s_wu => |i| this.emitFpUnaryOp(i, pc, .fcvt_s_wu),
                .fmv_w_x => |i| this.emitFMV_W_X(i, pc),
                // Zicsr
                .csrrw => |i| {
                    this.emitCSR(i, pc, .rw, true);

                    return .end_block;
                },
                .csrrs => |i| {
                    this.emitCSR(i, pc, .rs, i.rs1 != 0);

                    return .end_block;
                },
                .csrrc => |i| {
                    this.emitCSR(i, pc, .rc, i.rs1 != 0);

                    return .end_block;
                },
                .csrrwi => |i| {
                    this.emitCSRI(i, pc, .rw, true);

                    return .end_block;
                },
                .csrrsi => |i| {
                    this.emitCSRI(i, pc, .rs, i.uimm != 0);

                    return .end_block;
                },
                .csrrci => |i| {
                    this.emitCSRI(i, pc, .rc, i.uimm != 0);

                    return .end_block;
                },
                // Zifencei
                .fence_i => {
                    this.emitUpdateCounters();
                    this.emitEpilogue(pc +% 4, .ok);

                    return .epilogue_emitted;
                },
                // Zba
                .sh1add => |i| this.emitSHxADD(i, 1),
                .sh2add => |i| this.emitSHxADD(i, 2),
                .sh3add => |i| this.emitSHxADD(i, 3),
                // Zbb
                .andn => |i| this.emitANDN(i),
                .orn => |i| this.emitORN(i),
                .xnor => |i| this.emitXNOR(i),
                .clz => |i| this.emitCLZ(i),
                .ctz => |i| this.emitCTZ(i),
                .cpop => |i| this.emitCPOP(i),
                .max => |i| this.emitMAX(i),
                .maxu => |i| this.emitMAXU(i),
                .min => |i| this.emitMIN(i),
                .minu => |i| this.emitMINU(i),
                .sext_b => |i| this.emitSEXTB(i),
                .sext_h => |i| this.emitSEXTH(i),
                .zext_h => |i| this.emitZEXTH(i),
                .rol => |i| this.emitROL(i),
                .ror => |i| this.emitROR(i),
                .rori => |i| this.emitRORI(i),
                .orc_b => |i| this.emitORCB(i),
                .rev8 => |i| this.emitREV8(i),
                // Privileged
                .mret => {
                    this.emitUpdateCounters();
                    this.emitMRET(pc);

                    return .epilogue_emitted;
                },
                .wfi => {
                    this.emitUpdateCounters();
                    this.emitWFI(pc);

                    return .epilogue_emitted;
                },
            }

            return .next;
        }

        inline fn emitLUI(this: *Self, i: anytype) void {
            const value: u32 = @bitCast(@as(i32, i.imm) << 12);
            this.emit.movImm32(scratch1, value);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitAUIPC(this: *Self, i: anytype, pc: u32) void {
            const offset: u32 = @bitCast(@as(i32, i.imm) << 12);
            this.emit.movImm32(scratch1, pc +% offset);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitADDI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emitAddImmediate(scratch1, scratch1, i.imm);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLTI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.movImm32(scratch2, @bitCast(i.imm));
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.cset(scratch1, .lt);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLTIU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.movImm32(scratch2, @bitCast(i.imm));
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.cset(scratch1, .cc);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitXORI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.imm == -1) {
                this.emit.mvnReg32(scratch1, scratch1);
            } else if (i.imm != 0) {
                this.emit.movImm32(scratch2, @bitCast(i.imm));
                this.emit.eorReg32(scratch1, scratch1, scratch2);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitORI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.imm != 0) {
                this.emit.movImm32(scratch2, @bitCast(i.imm));
                this.emit.orrReg32(scratch1, scratch1, scratch2);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitANDI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.movImm32(scratch2, @bitCast(i.imm));
            this.emit.andReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLLI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.shamt != 0) {
                this.emit.lslImm32(scratch1, scratch1, i.shamt);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSRLI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.shamt != 0) {
                this.emit.lsrImm32(scratch1, scratch1, i.shamt);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSRAI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.shamt != 0) {
                this.emit.asrImm32(scratch1, scratch1, i.shamt);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitADD(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.addReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSUB(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.subReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLL(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.lslvReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLT(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.cset(scratch1, .lt);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLTU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.cset(scratch1, .cc);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitXOR(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.eorReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSRL(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.lsrvReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSRA(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.asrvReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitOR(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.orrReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitAND(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.andReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitJAL(this: *Self, i: anytype, pc: u32) void {
            const target = addPcOffset(pc, i.imm);

            if (comptime config.runtime.enable_branch_alignment) {
                if (target % 4 != 0) {
                    this.emit.movImm32(scratch1, @intFromEnum(arch.Registers.Mcause.Exception.instruction_address_misaligned));
                    this.emitStoreField32(offsets.trap_cause, scratch1);
                    this.emit.movImm32(scratch1, target);
                    this.emitStoreField32(offsets.trap_tval, scratch1);
                    this.emitEpilogue(pc, .trap);

                    return;
                }
            }

            if (i.rd != 0) {
                this.emit.movImm32(scratch1, pc +% 4);
                this.storeGuestReg(i.rd, scratch1);
            }

            this.emit.movImm32(scratch1, target);
            this.emitStoreField32(offsets.pc, scratch1);
            this.emitEpilogueNoPc(.ok);
        }

        inline fn emitJALR(this: *Self, i: anytype, pc: u32) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.rd != 0) {
                this.emit.movImm32(scratch2, pc +% 4);
                this.storeGuestReg(i.rd, scratch2);
            }

            this.emitAddImmediate(scratch1, scratch1, i.imm);
            this.emit.movImm32(scratch2, 0xFFFFFFFE);
            this.emit.andReg32(scratch1, scratch1, scratch2);

            if (comptime config.runtime.enable_branch_alignment) {
                this.emit.movImm32(scratch2, 0x3);
                this.emit.tstReg32(scratch1, scratch2);

                const aligned_branch = this.emit.getCode().len;
                this.emit.beq(0);

                this.emitTrapRuntime(pc, .instruction_address_misaligned);

                this.emit.patchBranch(aligned_branch, this.emit.getCode().len);
            }

            this.emitStoreField32(offsets.pc, scratch1);
            this.emitEpilogueNoPc(.ok);
        }

        inline fn emitBranch(this: *Self, i: anytype, pc: u32, comptime cond: Emitter.Condition) void {
            const taken_pc = addPcOffset(pc, i.imm);
            const not_taken_pc = pc +% 4;

            if (comptime config.runtime.enable_branch_alignment) {
                if (taken_pc % 4 != 0) {
                    this.loadGuestReg(scratch1, i.rs1);
                    this.loadGuestReg(scratch2, i.rs2);
                    this.emit.cmpReg32(scratch1, scratch2);

                    const not_taken_branch = this.emit.getCode().len;
                    this.emit.bCond(cond.invert(), 0);

                    this.emitTrapConst(pc, .instruction_address_misaligned, taken_pc);

                    this.emit.patchBranch(not_taken_branch, this.emit.getCode().len);
                    this.emitEpilogue(not_taken_pc, .ok);

                    return;
                }
            }

            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);

            this.emit.movImm32(scratch1, taken_pc);
            this.emit.movImm32(scratch2, not_taken_pc);
            this.emit.csel32(scratch1, scratch1, scratch2, cond);

            this.emitStoreField32(offsets.pc, scratch1);
            this.emitEpilogueNoPc(.ok);
        }

        const LoadSize = enum { byte_signed, byte_unsigned, half_signed, half_unsigned, word };
        const StoreSize = enum { byte, half, word };

        inline fn emitLoad(this: *Self, i: anytype, pc: u32, comptime size: LoadSize) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emitAddImmediate(scratch1, scratch1, i.imm);

            this.emit.movReg64(.x0, cpu_ptr);
            this.emit.movReg32(.x1, scratch1);

            const callback = switch (size) {
                .byte_signed, .byte_unsigned => config.memory_callbacks.read_byte,
                .half_signed, .half_unsigned => config.memory_callbacks.read_half,
                .word => config.memory_callbacks.read_word,
            };

            this.emit.movImm64(scratch2, @intFromPtr(callback));
            this.emit.blr(scratch2);

            this.emit.lsrImm64(scratch2, .x0, 32);
            this.emit.cmpImm32(scratch2, 0);

            const ok_branch = this.emit.getCode().len;
            this.emit.beq(0);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);

            this.emit.patchBranch(ok_branch, this.emit.getCode().len);

            switch (size) {
                .byte_signed => this.emit.sxtb32(scratch1, .x0),
                .half_signed => this.emit.sxth32(scratch1, .x0),
                .byte_unsigned => this.emit.uxtb32(scratch1, .x0),
                .half_unsigned => this.emit.uxth32(scratch1, .x0),
                .word => this.emit.movReg32(scratch1, .x0),
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitStore(this: *Self, i: anytype, pc: u32, comptime size: StoreSize) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emitAddImmediate(scratch1, scratch1, i.imm);
            this.loadGuestReg(scratch2, i.rs2);

            this.emit.movReg64(.x0, cpu_ptr);
            this.emit.movReg32(.x1, scratch1);

            switch (size) {
                .byte => this.emit.uxtb32(.x2, scratch2),
                .half => this.emit.uxth32(.x2, scratch2),
                .word => this.emit.movReg32(.x2, scratch2),
            }

            const callback = switch (size) {
                .byte => config.memory_callbacks.write_byte,
                .half => config.memory_callbacks.write_half,
                .word => config.memory_callbacks.write_word,
            };

            this.emit.movImm64(scratch3, @intFromPtr(callback));
            this.emit.blr(scratch3);

            this.emit.cmpImm32(.x0, 0);

            const ok_branch = this.emit.getCode().len;
            this.emit.beq(0);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);

            this.emit.patchBranch(ok_branch, this.emit.getCode().len);
        }

        inline fn emitEcall(this: *Self, pc: u32) void {
            const ecall_from_u: u32 = @intFromEnum(arch.Registers.Mcause.Exception.ecall_from_u);
            const ecall_from_m: u32 = @intFromEnum(arch.Registers.Mcause.Exception.ecall_from_m);

            this.emitLoadField32(scratch1, offsets.privilege);
            this.emit.cmpImm32(scratch1, 0);
            this.emit.movImm32(scratch1, ecall_from_u);
            this.emit.movImm32(scratch2, ecall_from_m);
            this.emit.csel32(scratch3, scratch1, scratch2, .eq);

            this.emitStoreField32(offsets.trap_cause, scratch3);
            this.emit.movImm32(scratch1, 0);
            this.emitStoreField32(offsets.trap_tval, scratch1);

            if (comptime config.hooks.ecall) |hook| {
                this.emit.movReg64(.x0, cpu_ptr);
                this.emitLoadField32(.x1, offsets.trap_cause);
                this.emit.movImm64(scratch1, @intFromPtr(hook));
                this.emit.blr(scratch1);
                this.emitHookActionDispatch(pc);
            } else {
                this.emitEpilogue(pc, .trap);
            }
        }

        inline fn emitEbreak(this: *Self, pc: u32) void {
            this.emit.movImm32(scratch1, @intFromEnum(arch.Registers.Mcause.Exception.breakpoint));
            this.emitStoreField32(offsets.trap_cause, scratch1);
            this.emit.movImm32(scratch1, pc);
            this.emitStoreField32(offsets.trap_tval, scratch1);

            if (comptime config.hooks.ebreak) |hook| {
                this.emit.movReg64(.x0, cpu_ptr);
                this.emit.movImm64(scratch1, @intFromPtr(hook));
                this.emit.blr(scratch1);
                this.emitHookActionDispatch(pc);
            } else {
                this.emitEpilogue(pc, .trap);
            }
        }

        inline fn emitHookActionDispatch(this: *Self, pc: u32) void {
            this.emit.cmpImm32(.x0, @intFromEnum(EngineConfig.Hooks.Action.skip));
            const skip_branch = this.emit.getCode().len;
            this.emit.beq(0);

            this.emit.cmpImm32(.x0, @intFromEnum(EngineConfig.Hooks.Action.halt));
            const halt_branch = this.emit.getCode().len;
            this.emit.beq(0);

            this.emitEpilogue(pc, .trap);

            this.emit.patchBranch(skip_branch, this.emit.getCode().len);
            this.emitEpilogue(pc +% 4, .ok);

            this.emit.patchBranch(halt_branch, this.emit.getCode().len);
            this.emitEpilogue(pc, .halt);
        }

        inline fn emitMUL(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.mulReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMULH(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.smull(scratch1, scratch1, scratch2);
            this.emit.lsrImm64(scratch1, scratch1, 32);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMULHSU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.umull(scratch3, scratch1, scratch2);
            this.emit.lsrImm64(scratch3, scratch3, 32);
            this.emit.subReg32(scratch4, scratch3, scratch2);
            this.emit.cmpImm32(scratch1, 0);
            this.emit.csel32(scratch1, scratch4, scratch3, .lt);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMULHU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.umull(scratch1, scratch1, scratch2);
            this.emit.lsrImm64(scratch1, scratch1, 32);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitDIV(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpImm32(scratch2, 0);
            this.emit.sdivReg32(scratch3, scratch1, scratch2);
            this.emit.movImm32(scratch4, 0xFFFFFFFF);
            this.emit.csel32(scratch1, scratch4, scratch3, .eq);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitDIVU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpImm32(scratch2, 0);
            this.emit.udivReg32(scratch3, scratch1, scratch2);
            this.emit.movImm32(scratch4, 0xFFFFFFFF);
            this.emit.csel32(scratch1, scratch4, scratch3, .eq);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitREM(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.sdivReg32(scratch3, scratch1, scratch2);
            this.emit.msubReg32(scratch1, scratch3, scratch2, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitREMU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.udivReg32(scratch3, scratch1, scratch2);
            this.emit.msubReg32(scratch1, scratch3, scratch2, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitCSR(this: *Self, i: anytype, pc: u32, comptime op: EngineConfig.Callbacks.CsrOp, do_write: bool) void {
            this.emitUpdateCounters();

            this.loadGuestReg(scratch1, i.rs1);

            this.emit.movReg64(.x0, cpu_ptr);
            this.emit.movImm32(.x1, i.csr);
            this.emit.movReg32(.x2, scratch1);
            this.emit.movImm32(.x3, @intFromEnum(op));
            this.emit.movImm32(.x4, if (do_write) 1 else 0);

            this.emit.movImm64(scratch2, @intFromPtr(config.callbacks.csr_op));
            this.emit.blr(scratch2);

            this.emitCSRResultCheck(i.rd, pc);
        }

        inline fn emitCSRI(this: *Self, i: anytype, pc: u32, comptime op: EngineConfig.Callbacks.CsrOp, do_write: bool) void {
            this.emitUpdateCounters();

            this.emit.movReg64(.x0, cpu_ptr);
            this.emit.movImm32(.x1, i.csr);
            this.emit.movImm32(.x2, @as(u32, i.uimm));
            this.emit.movImm32(.x3, @intFromEnum(op));
            this.emit.movImm32(.x4, if (do_write) 1 else 0);

            this.emit.movImm64(scratch2, @intFromPtr(config.callbacks.csr_op));
            this.emit.blr(scratch2);

            this.emitCSRResultCheck(i.rd, pc);
        }

        inline fn emitCSRResultCheck(this: *Self, rd: u8, pc: u32) void {
            this.emit.lsrImm64(scratch2, .x0, 32);
            this.emit.cmpImm32(scratch2, 0);

            const trap_branch = this.emit.getCode().len;
            this.emit.bne(0);

            if (rd != 0) {
                this.emit.movReg32(scratch1, .x0);
                this.storeGuestReg(rd, scratch1);
            }

            this.emitEpilogue(pc +% 4, .ok);

            this.emit.patchBranch(trap_branch, this.emit.getCode().len);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitSHxADD(this: *Self, i: anytype, comptime shift: u2) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.addLsl32(scratch1, scratch2, scratch1, shift);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitANDN(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.bicReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitORN(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.ornReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitXNOR(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.eonReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitCLZ(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.clz32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitCTZ(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.rbit32(scratch1, scratch1);
            this.emit.clz32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitCPOP(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            this.emit.lsrImm32(scratch2, scratch1, 1);
            this.emit.movImm32(scratch3, 0x55555555);
            this.emit.andReg32(scratch2, scratch2, scratch3);
            this.emit.subReg32(scratch1, scratch1, scratch2);

            this.emit.movImm32(scratch3, 0x33333333);
            this.emit.andReg32(scratch2, scratch1, scratch3);
            this.emit.lsrImm32(scratch1, scratch1, 2);
            this.emit.andReg32(scratch1, scratch1, scratch3);
            this.emit.addReg32(scratch1, scratch1, scratch2);

            this.emit.lsrImm32(scratch2, scratch1, 4);
            this.emit.addReg32(scratch1, scratch1, scratch2);
            this.emit.movImm32(scratch3, 0x0F0F0F0F);
            this.emit.andReg32(scratch1, scratch1, scratch3);

            this.emit.lsrImm32(scratch2, scratch1, 8);
            this.emit.addReg32(scratch1, scratch1, scratch2);

            this.emit.lsrImm32(scratch2, scratch1, 16);
            this.emit.addReg32(scratch1, scratch1, scratch2);
            this.emit.movImm32(scratch2, 0x3F);
            this.emit.andReg32(scratch1, scratch1, scratch2);

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMAX(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.csel32(scratch1, scratch1, scratch2, .gt);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMAXU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.csel32(scratch1, scratch1, scratch2, .hi);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMIN(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.csel32(scratch1, scratch1, scratch2, .lt);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMINU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.csel32(scratch1, scratch1, scratch2, .cc);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSEXTB(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.sxtb32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSEXTH(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.sxth32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitZEXTH(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.uxth32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitROL(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.negReg32(scratch2, scratch2);
            this.emit.rorvReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitROR(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.rorvReg32(scratch1, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitRORI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.shamt != 0) {
                this.emit.rorImm32(scratch1, scratch1, i.shamt);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitORCB(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            this.emit.lsrImm32(scratch2, scratch1, 1);
            this.emit.movImm32(scratch3, 0x7F7F7F7F);
            this.emit.andReg32(scratch2, scratch2, scratch3);
            this.emit.orrReg32(scratch1, scratch1, scratch2);

            this.emit.lsrImm32(scratch2, scratch1, 2);
            this.emit.movImm32(scratch3, 0x3F3F3F3F);
            this.emit.andReg32(scratch2, scratch2, scratch3);
            this.emit.orrReg32(scratch1, scratch1, scratch2);

            this.emit.lsrImm32(scratch2, scratch1, 4);
            this.emit.movImm32(scratch3, 0x0F0F0F0F);
            this.emit.andReg32(scratch2, scratch2, scratch3);
            this.emit.orrReg32(scratch1, scratch1, scratch2);

            this.emit.lslImm32(scratch2, scratch1, 1);
            this.emit.movImm32(scratch3, 0xFEFEFEFE);
            this.emit.andReg32(scratch2, scratch2, scratch3);
            this.emit.orrReg32(scratch1, scratch1, scratch2);

            this.emit.lslImm32(scratch2, scratch1, 2);
            this.emit.movImm32(scratch3, 0xFCFCFCFC);
            this.emit.andReg32(scratch2, scratch2, scratch3);
            this.emit.orrReg32(scratch1, scratch1, scratch2);

            this.emit.lslImm32(scratch2, scratch1, 4);
            this.emit.movImm32(scratch3, 0xF0F0F0F0);
            this.emit.andReg32(scratch2, scratch2, scratch3);
            this.emit.orrReg32(scratch1, scratch1, scratch2);

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitREV8(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.rev32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn loadFpRegRaw(this: *Self, host_reg: Emitter.Register, fp_reg: u8) void {
            const safe_reg = fp_reg & 0x1F;
            const offset: u15 = @as(u15, safe_reg) * 8;

            this.emit.ldrOffset64(host_reg, float_base, offset);
        }

        inline fn storeFpRegRaw(this: *Self, fp_reg: u8, host_reg: Emitter.Register) void {
            const safe_reg = fp_reg & 0x1F;
            const offset: u15 = @as(u15, safe_reg) * 8;

            this.emit.strOffset64(host_reg, float_base, offset);
        }

        inline fn storeFpReg32Boxed(this: *Self, fp_reg: u8, host_reg: Emitter.Register) void {
            this.emit.movImm64(scratch3, 0xFFFFFFFF00000000);
            this.emit.movReg32(scratch4, host_reg);
            this.emit.orrReg64(scratch3, scratch3, scratch4);
            this.storeFpRegRaw(fp_reg, scratch3);
        }

        inline fn emitCheckFpAccess(this: *Self, pc: u32) void {
            this.emitLoadField32(scratch1, offsets.mstatus);
            this.emit.lsrImm32(scratch2, scratch1, 13);
            this.emit.movImm32(scratch3, 0x3);
            this.emit.andReg32(scratch2, scratch2, scratch3);
            this.emit.cmpImm32(scratch2, 0);

            const ok_branch = this.emit.getCode().len;
            this.emit.bne(0);

            this.emitUpdateCounters();
            this.emitTrapConst(pc, .illegal_instruction, 0);

            this.emit.patchBranch(ok_branch, this.emit.getCode().len);
        }

        inline fn emitMarkFpDirty(this: *Self) void {
            this.emitLoadField32(scratch1, offsets.mstatus);
            this.emit.movImm32(scratch2, 0x6000);
            this.emit.orrReg32(scratch1, scratch1, scratch2);
            this.emit.movImm32(scratch2, 0x80000000);
            this.emit.orrReg32(scratch1, scratch1, scratch2);
            this.emitStoreField32(offsets.mstatus, scratch1);
        }

        inline fn emitFLW(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadGuestReg(scratch1, i.rs1);
            this.emitAddImmediate(scratch1, scratch1, i.imm);

            this.emit.movReg64(.x0, cpu_ptr);
            this.emit.movReg32(.x1, scratch1);

            this.emit.movImm64(scratch2, @intFromPtr(config.memory_callbacks.read_word));
            this.emit.blr(scratch2);

            this.emit.lsrImm64(scratch2, .x0, 32);
            this.emit.cmpImm32(scratch2, 0);

            const ok_branch = this.emit.getCode().len;
            this.emit.beq(0);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);

            this.emit.patchBranch(ok_branch, this.emit.getCode().len);

            this.storeFpReg32Boxed(i.rd, .x0);
            this.emitMarkFpDirty();
        }

        inline fn emitFSW(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadGuestReg(scratch1, i.rs1);
            this.emitAddImmediate(scratch1, scratch1, i.imm);
            this.loadFpRegRaw(scratch2, i.rs2);

            this.emit.movReg64(.x0, cpu_ptr);
            this.emit.movReg32(.x1, scratch1);
            this.emit.movReg32(.x2, scratch2);

            this.emit.movImm64(scratch3, @intFromPtr(config.memory_callbacks.write_word));
            this.emit.blr(scratch3);

            this.emit.cmpImm32(.x0, 0);

            const ok_branch = this.emit.getCode().len;
            this.emit.beq(0);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);

            this.emit.patchBranch(ok_branch, this.emit.getCode().len);
        }

        inline fn emitFMV_X_W(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadFpRegRaw(scratch1, i.rs1);

            this.emit.lsrImm64(scratch2, scratch1, 32);
            this.emit.movImm32(scratch3, 0xFFFFFFFF);
            this.emit.cmpReg32(scratch2, scratch3);

            this.emit.movImm32(scratch2, 0x7FC00000);
            this.emit.csel32(scratch1, scratch1, scratch2, .eq);

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitFMV_W_X(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);
            this.loadGuestReg(scratch1, i.rs1);
            this.storeFpReg32Boxed(i.rd, scratch1);
            this.emitMarkFpDirty();
        }

        inline fn emitFSGNJ_S(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadFpRegRaw(scratch1, i.rs1);
            this.emit.lsrImm64(scratch2, scratch1, 32);
            this.emit.movImm32(scratch3, 0xFFFFFFFF);
            this.emit.cmpReg32(scratch2, scratch3);
            this.emit.movImm32(scratch2, 0x7FC00000);
            this.emit.csel32(scratch1, scratch1, scratch2, .eq);

            this.loadFpRegRaw(scratch2, i.rs2);

            this.emit.movImm32(scratch3, 0x7FFFFFFF);
            this.emit.andReg32(scratch1, scratch1, scratch3);
            this.emit.movImm32(scratch3, 0x80000000);
            this.emit.andReg32(scratch2, scratch2, scratch3);
            this.emit.orrReg32(scratch1, scratch1, scratch2);

            this.storeFpReg32Boxed(i.rd, scratch1);
            this.emitMarkFpDirty();
        }

        inline fn emitFSGNJN_S(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadFpRegRaw(scratch1, i.rs1);
            this.emit.lsrImm64(scratch2, scratch1, 32);
            this.emit.movImm32(scratch3, 0xFFFFFFFF);
            this.emit.cmpReg32(scratch2, scratch3);
            this.emit.movImm32(scratch2, 0x7FC00000);
            this.emit.csel32(scratch1, scratch1, scratch2, .eq);

            this.loadFpRegRaw(scratch2, i.rs2);

            this.emit.movImm32(scratch3, 0x7FFFFFFF);
            this.emit.andReg32(scratch1, scratch1, scratch3);
            this.emit.mvnReg32(scratch2, scratch2);
            this.emit.movImm32(scratch3, 0x80000000);
            this.emit.andReg32(scratch2, scratch2, scratch3);
            this.emit.orrReg32(scratch1, scratch1, scratch2);

            this.storeFpReg32Boxed(i.rd, scratch1);
            this.emitMarkFpDirty();
        }

        inline fn emitFSGNJX_S(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadFpRegRaw(scratch1, i.rs1);
            this.emit.lsrImm64(scratch2, scratch1, 32);
            this.emit.movImm32(scratch3, 0xFFFFFFFF);
            this.emit.cmpReg32(scratch2, scratch3);
            this.emit.movImm32(scratch2, 0x7FC00000);
            this.emit.csel32(scratch1, scratch1, scratch2, .eq);

            this.loadFpRegRaw(scratch2, i.rs2);

            this.emit.movImm32(scratch3, 0x80000000);
            this.emit.andReg32(scratch2, scratch2, scratch3);
            this.emit.eorReg32(scratch1, scratch1, scratch2);

            this.storeFpReg32Boxed(i.rd, scratch1);
            this.emitMarkFpDirty();
        }

        inline fn emitFCLASS_S(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadFpRegRaw(scratch1, i.rs1);

            this.emit.lsrImm64(scratch2, scratch1, 32);
            this.emit.movImm32(scratch3, 0xFFFFFFFF);
            this.emit.cmpReg32(scratch2, scratch3);

            const nan_boxed = this.emit.getCode().len;
            this.emit.beq(0);

            this.emit.movImm32(scratch1, 0x200);
            this.storeGuestReg(i.rd, scratch1);

            const done_branch = this.emit.getCode().len;
            this.emit.b(0);

            this.emit.patchBranch(nan_boxed, this.emit.getCode().len);

            this.emit.movReg64(.x0, cpu_ptr);
            this.emit.movImm32(.x1, @intFromEnum(EngineConfig.Callbacks.UnaryOpS.fclass));
            this.emit.movImm32(.x2, i.rd);
            this.emit.movImm32(.x3, i.rs1);
            this.emit.movImm32(.x4, 0);

            this.emit.movImm64(scratch2, @intFromPtr(config.callbacks.unary_s));
            this.emit.blr(scratch2);

            this.emit.cmpImm32(.x0, 0);

            const ok_branch = this.emit.getCode().len;
            this.emit.beq(0);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);

            this.emit.patchBranch(ok_branch, this.emit.getCode().len);
            this.emit.patchB(done_branch, this.emit.getCode().len);
        }

        inline fn emitFpBinaryOp(this: *Self, i: anytype, pc: u32, rm: u3, comptime op: EngineConfig.Callbacks.BinaryOpS) void {
            this.emitCheckFpAccess(pc);

            this.emit.movReg64(.x0, cpu_ptr);
            this.emit.movImm32(.x1, @intFromEnum(op));
            this.emit.movImm32(.x2, i.rd);
            this.emit.movImm32(.x3, i.rs1);
            this.emit.movImm32(.x4, i.rs2);
            this.emit.movImm32(.x5, rm);

            this.emit.movImm64(scratch1, @intFromPtr(config.callbacks.binary_s));
            this.emit.blr(scratch1);

            this.emitFpResultCheck(pc);
        }

        inline fn emitFpUnaryOp(this: *Self, i: anytype, pc: u32, comptime op: EngineConfig.Callbacks.UnaryOpS) void {
            this.emitCheckFpAccess(pc);

            this.emit.movReg64(.x0, cpu_ptr);
            this.emit.movImm32(.x1, @intFromEnum(op));
            this.emit.movImm32(.x2, i.rd);
            this.emit.movImm32(.x3, i.rs1);
            this.emit.movImm32(.x4, i.rm);

            this.emit.movImm64(scratch1, @intFromPtr(config.callbacks.unary_s));
            this.emit.blr(scratch1);

            this.emitFpResultCheck(pc);
        }

        inline fn emitFpFmaOp(this: *Self, i: anytype, pc: u32, comptime op: EngineConfig.Callbacks.FmaOpS) void {
            this.emitCheckFpAccess(pc);

            this.emit.movReg64(.x0, cpu_ptr);
            this.emit.movImm32(.x1, @intFromEnum(op));
            this.emit.movImm32(.x2, i.rd);
            this.emit.movImm32(.x3, i.rs1);
            this.emit.movImm32(.x4, i.rs2);
            this.emit.movImm32(.x5, i.rs3);
            this.emit.movImm32(.x6, i.rm);

            this.emit.movImm64(scratch1, @intFromPtr(config.callbacks.fma_s));
            this.emit.blr(scratch1);

            this.emitFpResultCheck(pc);
        }

        inline fn emitFpCmpOp(this: *Self, i: anytype, pc: u32, comptime op: EngineConfig.Callbacks.CmpOpS) void {
            this.emitCheckFpAccess(pc);

            this.emit.movReg64(.x0, cpu_ptr);
            this.emit.movImm32(.x1, @intFromEnum(op));
            this.emit.movImm32(.x2, i.rd);
            this.emit.movImm32(.x3, i.rs1);
            this.emit.movImm32(.x4, i.rs2);

            this.emit.movImm64(scratch1, @intFromPtr(config.callbacks.cmp_s));
            this.emit.blr(scratch1);

            this.emitFpResultCheck(pc);
        }

        inline fn emitFpResultCheck(this: *Self, pc: u32) void {
            this.emit.cmpImm32(.x0, 0);

            const ok_branch = this.emit.getCode().len;
            this.emit.beq(0);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);

            this.emit.patchBranch(ok_branch, this.emit.getCode().len);
        }

        inline fn emitMRET(this: *Self, pc: u32) void {
            this.emit.movReg64(.x0, cpu_ptr);

            this.emit.movImm64(scratch1, @intFromPtr(config.callbacks.mret));
            this.emit.blr(scratch1);

            this.emit.movImm32(scratch1, 0xFFFFFFFF);
            this.emit.cmpReg32(.x0, scratch1);

            const trap_branch = this.emit.getCode().len;
            this.emit.beq(0);

            this.emitStoreField32(offsets.pc, .x0);
            this.emitEpilogueNoPc(.ok);

            this.emit.patchBranch(trap_branch, this.emit.getCode().len);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitWFI(this: *Self, pc: u32) void {
            this.emit.movReg64(.x0, cpu_ptr);

            this.emit.movImm64(scratch1, @intFromPtr(config.callbacks.wfi));
            this.emit.blr(scratch1);

            this.emit.movReg32(scratch2, .x0);

            this.emit.cmpImm32(scratch2, @intFromEnum(EngineConfig.State.trap));

            const is_trap = this.emit.getCode().len;
            this.emit.beq(0);

            this.emit.movImm32(scratch1, pc +% 4);
            this.emitStoreField32(offsets.pc, scratch1);
            this.emit.movReg32(.x0, scratch2);
            this.emit.ldpPost64(.x21, .x30, .sp, 16);
            this.emit.ldpPost64(.x19, .x20, .sp, 16);
            this.emit.ret();

            this.emit.patchBranch(is_trap, this.emit.getCode().len);
            this.emitEpilogue(pc, .trap);
        }
    };
}
