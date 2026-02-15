const std = @import("std");
const builtin = @import("builtin");

const arch = @import("../../arch.zig");
const jit = @import("../../jit.zig");
const CodeArena = @import("../code_arena.zig").CodeArena;
const EngineConfig = @import("../engine_config.zig").EngineConfig;

pub fn Compiler(comptime config: EngineConfig) type {
    return struct {
        const Self = @This();

        pub const BlockFn = CodeArena.BlockFn;

        const offsets = config.callbacks.get_offsets();

        const EmitResult = enum {
            next,
            end_block,
            epilogue_emitted,
        };

        const cpu_features = builtin.cpu.features;
        const has_popcnt = std.Target.x86.featureSetHas(cpu_features, .popcnt);
        const has_lzcnt = std.Target.x86.featureSetHas(cpu_features, .lzcnt);
        const has_bmi = std.Target.x86.featureSetHas(cpu_features, .bmi);
        const has_bmi2 = std.Target.x86.featureSetHas(cpu_features, .bmi2);

        const max_code_per_block = 1024 + config.jit.max_block_size * 96;

        pub const Emitter = struct {
            buffer: []u8,
            offset: usize,

            pub const Register = enum(u4) {
                rax = 0,
                rcx = 1,
                rdx = 2,
                rbx = 3,
                rsp = 4,
                rbp = 5,
                rsi = 6,
                rdi = 7,
                r8 = 8,
                r9 = 9,
                r10 = 10,
                r11 = 11,
                r12 = 12,
                r13 = 13,
                r14 = 14,
                r15 = 15,

                pub inline fn lowBits(self: Register) u3 {
                    return @truncate(@intFromEnum(self));
                }

                pub inline fn needsRex(self: Register) bool {
                    return @intFromEnum(self) >= 8;
                }
            };

            pub const Condition = enum(u4) {
                o = 0x0,
                no = 0x1,
                b = 0x2,
                ae = 0x3,
                e = 0x4,
                ne = 0x5,
                be = 0x6,
                a = 0x7,
                s = 0x8,
                ns = 0x9,
                p = 0xA,
                np = 0xB,
                l = 0xC,
                ge = 0xD,
                le = 0xE,
                g = 0xF,

                pub const cc = Condition.b;
                pub const cs = Condition.ae;
                pub const eq = Condition.e;
                pub const lt = Condition.l;
                pub const gt = Condition.g;
                pub const hi = Condition.a;

                pub fn invert(self: Condition) Condition {
                    return @enumFromInt(@intFromEnum(self) ^ 1);
                }
            };

            pub inline fn init(buffer: []u8) Emitter {
                return .{
                    .buffer = buffer,
                    .offset = 0,
                };
            }

            pub inline fn getCode(self: *const Emitter) []u8 {
                return self.buffer[0..self.offset];
            }

            inline fn emit8(self: *Emitter, byte: u8) void {
                self.buffer[self.offset] = byte;
                self.offset += 1;
            }

            inline fn emit16(self: *Emitter, value: u16) void {
                std.mem.writeInt(u16, self.buffer[self.offset..][0..2], value, .little);
                self.offset += 2;
            }

            inline fn emit32(self: *Emitter, value: u32) void {
                std.mem.writeInt(u32, self.buffer[self.offset..][0..4], value, .little);
                self.offset += 4;
            }

            inline fn emit64(self: *Emitter, value: u64) void {
                std.mem.writeInt(u64, self.buffer[self.offset..][0..8], value, .little);
                self.offset += 8;
            }

            inline fn rex(self: *Emitter, w: bool, r: Register, x: bool, b: Register) void {
                const byte: u8 = 0x40 |
                    (@as(u8, if (w) 1 else 0) << 3) |
                    (@as(u8, if (r.needsRex()) 1 else 0) << 2) |
                    (@as(u8, if (x) 1 else 0) << 1) |
                    @as(u8, if (b.needsRex()) 1 else 0);

                if (byte != 0x40) {
                    self.emit8(byte);
                }
            }

            inline fn rexW(self: *Emitter, r: Register, b: Register) void {
                self.rex(true, r, false, b);
            }

            inline fn rexOptional(self: *Emitter, r: Register, b: Register) void {
                self.rex(false, r, false, b);
            }

            inline fn modRM(self: *Emitter, mod: u2, reg: u3, rm: u3) void {
                self.emit8((@as(u8, mod) << 6) | (@as(u8, reg) << 3) | rm);
            }

            inline fn modRMReg(self: *Emitter, reg: Register, rm: Register) void {
                self.modRM(0b11, reg.lowBits(), rm.lowBits());
            }

            inline fn sib(self: *Emitter, scale: u2, index: u3, base: u3) void {
                self.emit8((@as(u8, scale) << 6) | (@as(u8, index) << 3) | base);
            }

            pub inline fn movImm32(self: *Emitter, rd: Register, imm: u32) void {
                if (imm == 0) {
                    self.rexOptional(rd, rd);
                    self.emit8(0x31);
                    self.modRMReg(rd, rd);
                } else {
                    if (rd.needsRex()) {
                        self.emit8(0x41);
                    }

                    self.emit8(0xB8 + @as(u8, rd.lowBits()));
                    self.emit32(imm);
                }
            }

            pub inline fn movImm64(self: *Emitter, rd: Register, imm: u64) void {
                if (imm == 0) {
                    self.movImm32(rd, 0);
                } else if (imm <= 0xFFFFFFFF) {
                    self.movImm32(rd, @truncate(imm));
                } else if (@as(i64, @bitCast(imm)) >= -0x80000000 and @as(i64, @bitCast(imm)) <= 0x7FFFFFFF) {
                    self.rexW(Register.rax, rd);
                    self.emit8(0xC7);
                    self.modRM(0b11, 0, rd.lowBits());
                    self.emit32(@truncate(imm));
                } else {
                    self.emit8(0x48 | @as(u8, if (rd.needsRex()) 1 else 0));
                    self.emit8(0xB8 + @as(u8, rd.lowBits()));
                    self.emit64(imm);
                }
            }

            pub inline fn movReg32(self: *Emitter, rd: Register, rs: Register) void {
                if (rd == rs) {
                    return;
                }

                self.rexOptional(rs, rd);
                self.emit8(0x89);
                self.modRMReg(rs, rd);
            }

            pub inline fn movReg64(self: *Emitter, rd: Register, rs: Register) void {
                if (rd == rs) {
                    return;
                }

                self.rexW(rs, rd);
                self.emit8(0x89);
                self.modRMReg(rs, rd);
            }

            pub inline fn movMemToReg32(self: *Emitter, rd: Register, base: Register, offset: i32) void {
                self.rexOptional(rd, base);
                self.emit8(0x8B);
                self.emitMemOperand(rd, base, offset);
            }

            pub inline fn movMemToReg64(self: *Emitter, rd: Register, base: Register, offset: i32) void {
                self.rexW(rd, base);
                self.emit8(0x8B);
                self.emitMemOperand(rd, base, offset);
            }

            pub inline fn movRegToMem32(self: *Emitter, base: Register, offset: i32, rs: Register) void {
                self.rexOptional(rs, base);
                self.emit8(0x89);
                self.emitMemOperand(rs, base, offset);
            }

            pub inline fn movRegToMem64(self: *Emitter, base: Register, offset: i32, rs: Register) void {
                self.rexW(rs, base);
                self.emit8(0x89);
                self.emitMemOperand(rs, base, offset);
            }

            pub inline fn movzxMem8ToReg32(self: *Emitter, rd: Register, base: Register, offset: i32) void {
                self.rexOptional(rd, base);
                self.emit8(0x0F);
                self.emit8(0xB6);
                self.emitMemOperand(rd, base, offset);
            }

            pub inline fn movzxMem16ToReg32(self: *Emitter, rd: Register, base: Register, offset: i32) void {
                self.rexOptional(rd, base);
                self.emit8(0x0F);
                self.emit8(0xB7);
                self.emitMemOperand(rd, base, offset);
            }

            pub inline fn movsxMem8ToReg32(self: *Emitter, rd: Register, base: Register, offset: i32) void {
                self.rexOptional(rd, base);
                self.emit8(0x0F);
                self.emit8(0xBE);
                self.emitMemOperand(rd, base, offset);
            }

            pub inline fn movsxMem16ToReg32(self: *Emitter, rd: Register, base: Register, offset: i32) void {
                self.rexOptional(rd, base);
                self.emit8(0x0F);
                self.emit8(0xBF);
                self.emitMemOperand(rd, base, offset);
            }

            pub inline fn movRegToMem8(self: *Emitter, base: Register, offset: i32, rs: Register) void {
                if (rs.needsRex() or base.needsRex() or
                    rs == .rsp or rs == .rbp or rs == .rsi or rs == .rdi)
                {
                    self.emit8(0x40 |
                        (@as(u8, if (rs.needsRex()) 1 else 0) << 2) |
                        @as(u8, if (base.needsRex()) 1 else 0));
                }

                self.emit8(0x88);
                self.emitMemOperand(rs, base, offset);
            }

            pub inline fn movRegToMem16(self: *Emitter, base: Register, offset: i32, rs: Register) void {
                self.emit8(0x66);
                self.rexOptional(rs, base);
                self.emit8(0x89);
                self.emitMemOperand(rs, base, offset);
            }

            inline fn emitMemOperand(self: *Emitter, reg: Register, base: Register, offset: i32) void {
                const reg_bits = reg.lowBits();
                const base_bits = base.lowBits();

                if (base == .rsp or base == .r12) {
                    if (offset == 0) {
                        self.modRM(0b00, reg_bits, 0b100);
                        self.sib(0, 0b100, base_bits);
                    } else if (offset >= -128 and offset <= 127) {
                        self.modRM(0b01, reg_bits, 0b100);
                        self.sib(0, 0b100, base_bits);
                        self.emit8(@bitCast(@as(i8, @truncate(offset))));
                    } else {
                        self.modRM(0b10, reg_bits, 0b100);
                        self.sib(0, 0b100, base_bits);
                        self.emit32(@bitCast(offset));
                    }
                } else if (base == .rbp or base == .r13) {
                    if (offset >= -128 and offset <= 127) {
                        self.modRM(0b01, reg_bits, base_bits);
                        self.emit8(@bitCast(@as(i8, @truncate(offset))));
                    } else {
                        self.modRM(0b10, reg_bits, base_bits);
                        self.emit32(@bitCast(offset));
                    }
                } else {
                    if (offset == 0) {
                        self.modRM(0b00, reg_bits, base_bits);
                    } else if (offset >= -128 and offset <= 127) {
                        self.modRM(0b01, reg_bits, base_bits);
                        self.emit8(@bitCast(@as(i8, @truncate(offset))));
                    } else {
                        self.modRM(0b10, reg_bits, base_bits);
                        self.emit32(@bitCast(offset));
                    }
                }
            }

            pub inline fn addReg32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rs, rd);
                self.emit8(0x01);
                self.modRMReg(rs, rd);
            }

            pub inline fn addReg64(self: *Emitter, rd: Register, rs: Register) void {
                self.rexW(rs, rd);
                self.emit8(0x01);
                self.modRMReg(rs, rd);
            }

            pub inline fn addImm32(self: *Emitter, rd: Register, imm: i32) void {
                if (imm == 0) {
                    return;
                }

                self.rexOptional(Register.rax, rd);

                if (imm >= -128 and imm <= 127) {
                    self.emit8(0x83);
                    self.modRM(0b11, 0, rd.lowBits());
                    self.emit8(@bitCast(@as(i8, @truncate(imm))));
                } else {
                    self.emit8(0x81);
                    self.modRM(0b11, 0, rd.lowBits());
                    self.emit32(@bitCast(imm));
                }
            }

            pub inline fn addImm64(self: *Emitter, rd: Register, imm: i32) void {
                if (imm == 0) {
                    return;
                }

                self.rexW(Register.rax, rd);

                if (imm >= -128 and imm <= 127) {
                    self.emit8(0x83);
                    self.modRM(0b11, 0, rd.lowBits());
                    self.emit8(@bitCast(@as(i8, @truncate(imm))));
                } else {
                    self.emit8(0x81);
                    self.modRM(0b11, 0, rd.lowBits());
                    self.emit32(@bitCast(imm));
                }
            }

            pub inline fn subReg32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rs, rd);
                self.emit8(0x29);
                self.modRMReg(rs, rd);
            }

            pub inline fn subReg64(self: *Emitter, rd: Register, rs: Register) void {
                self.rexW(rs, rd);
                self.emit8(0x29);
                self.modRMReg(rs, rd);
            }

            pub inline fn subImm32(self: *Emitter, rd: Register, imm: i32) void {
                if (imm == 0) {
                    return;
                }

                self.rexOptional(Register.rax, rd);

                if (imm >= -128 and imm <= 127) {
                    self.emit8(0x83);
                    self.modRM(0b11, 5, rd.lowBits());
                    self.emit8(@bitCast(@as(i8, @truncate(imm))));
                } else {
                    self.emit8(0x81);
                    self.modRM(0b11, 5, rd.lowBits());
                    self.emit32(@bitCast(imm));
                }
            }

            pub inline fn negReg32(self: *Emitter, rd: Register) void {
                self.rexOptional(Register.rax, rd);
                self.emit8(0xF7);
                self.modRM(0b11, 3, rd.lowBits());
            }

            pub inline fn negReg64(self: *Emitter, rd: Register) void {
                self.rexW(Register.rax, rd);
                self.emit8(0xF7);
                self.modRM(0b11, 3, rd.lowBits());
            }

            pub inline fn andReg32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rs, rd);
                self.emit8(0x21);
                self.modRMReg(rs, rd);
            }

            pub inline fn andReg64(self: *Emitter, rd: Register, rs: Register) void {
                self.rexW(rs, rd);
                self.emit8(0x21);
                self.modRMReg(rs, rd);
            }

            pub inline fn andImm32(self: *Emitter, rd: Register, imm: i32) void {
                self.rexOptional(Register.rax, rd);

                if (imm >= -128 and imm <= 127) {
                    self.emit8(0x83);
                    self.modRM(0b11, 4, rd.lowBits());
                    self.emit8(@bitCast(@as(i8, @truncate(imm))));
                } else {
                    self.emit8(0x81);
                    self.modRM(0b11, 4, rd.lowBits());
                    self.emit32(@bitCast(imm));
                }
            }

            pub inline fn orReg32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rs, rd);
                self.emit8(0x09);
                self.modRMReg(rs, rd);
            }

            pub inline fn orReg64(self: *Emitter, rd: Register, rs: Register) void {
                self.rexW(rs, rd);
                self.emit8(0x09);
                self.modRMReg(rs, rd);
            }

            pub inline fn orImm32(self: *Emitter, rd: Register, imm: i32) void {
                self.rexOptional(Register.rax, rd);

                if (imm >= -128 and imm <= 127) {
                    self.emit8(0x83);
                    self.modRM(0b11, 1, rd.lowBits());
                    self.emit8(@bitCast(@as(i8, @truncate(imm))));
                } else {
                    self.emit8(0x81);
                    self.modRM(0b11, 1, rd.lowBits());
                    self.emit32(@bitCast(imm));
                }
            }

            pub inline fn xorReg32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rs, rd);
                self.emit8(0x31);
                self.modRMReg(rs, rd);
            }

            pub inline fn xorReg64(self: *Emitter, rd: Register, rs: Register) void {
                self.rexW(rs, rd);
                self.emit8(0x31);
                self.modRMReg(rs, rd);
            }

            pub inline fn notReg32(self: *Emitter, rd: Register) void {
                self.rexOptional(Register.rax, rd);
                self.emit8(0xF7);
                self.modRM(0b11, 2, rd.lowBits());
            }

            pub inline fn notReg64(self: *Emitter, rd: Register) void {
                self.rexW(Register.rax, rd);
                self.emit8(0xF7);
                self.modRM(0b11, 2, rd.lowBits());
            }

            pub inline fn andnReg32(self: *Emitter, rd: Register, rs1: Register, rs2: Register) void {
                self.emitVex2(rd, rs1, rs2, false);
                self.emit8(0xF2);
                self.modRMReg(rd, rs2);
            }

            inline fn emitVex2(self: *Emitter, r: Register, vvvv: Register, b: Register, w: bool) void {
                const r_bit: u8 = if (r.needsRex()) 0 else 0x80;
                const x_bit: u8 = 0x40;
                const b_bit: u8 = if (b.needsRex()) 0 else 0x20;
                const vvvv_bits: u8 = (~@as(u8, @intFromEnum(vvvv)) & 0xF) << 3;
                const l_bit: u8 = 0;
                const pp_bits: u8 = 0;

                if (!r.needsRex() and !b.needsRex() and !w) {
                    self.emit8(0xC5);
                    self.emit8(r_bit | vvvv_bits | l_bit | pp_bits);
                } else {
                    self.emit8(0xC4);
                    self.emit8(r_bit | x_bit | b_bit | 0x02);
                    self.emit8((@as(u8, if (w) 1 else 0) << 7) | vvvv_bits | l_bit | pp_bits);
                }
            }

            pub inline fn shlImm32(self: *Emitter, rd: Register, imm: u5) void {
                self.rexOptional(Register.rax, rd);

                if (imm == 1) {
                    self.emit8(0xD1);
                    self.modRM(0b11, 4, rd.lowBits());
                } else {
                    self.emit8(0xC1);
                    self.modRM(0b11, 4, rd.lowBits());
                    self.emit8(imm);
                }
            }

            pub inline fn shrImm32(self: *Emitter, rd: Register, imm: u5) void {
                self.rexOptional(Register.rax, rd);

                if (imm == 1) {
                    self.emit8(0xD1);
                    self.modRM(0b11, 5, rd.lowBits());
                } else {
                    self.emit8(0xC1);
                    self.modRM(0b11, 5, rd.lowBits());
                    self.emit8(imm);
                }
            }

            pub inline fn shrImm64(self: *Emitter, rd: Register, imm: u6) void {
                self.rexW(Register.rax, rd);

                if (imm == 1) {
                    self.emit8(0xD1);
                    self.modRM(0b11, 5, rd.lowBits());
                } else {
                    self.emit8(0xC1);
                    self.modRM(0b11, 5, rd.lowBits());
                    self.emit8(imm);
                }
            }

            pub inline fn sarImm32(self: *Emitter, rd: Register, imm: u5) void {
                self.rexOptional(Register.rax, rd);

                if (imm == 1) {
                    self.emit8(0xD1);
                    self.modRM(0b11, 7, rd.lowBits());
                } else {
                    self.emit8(0xC1);
                    self.modRM(0b11, 7, rd.lowBits());
                    self.emit8(imm);
                }
            }

            pub inline fn shlCl32(self: *Emitter, rd: Register) void {
                self.rexOptional(Register.rax, rd);
                self.emit8(0xD3);
                self.modRM(0b11, 4, rd.lowBits());
            }

            pub inline fn shrCl32(self: *Emitter, rd: Register) void {
                self.rexOptional(Register.rax, rd);
                self.emit8(0xD3);
                self.modRM(0b11, 5, rd.lowBits());
            }

            pub inline fn sarCl32(self: *Emitter, rd: Register) void {
                self.rexOptional(Register.rax, rd);
                self.emit8(0xD3);
                self.modRM(0b11, 7, rd.lowBits());
            }

            pub inline fn rolImm32(self: *Emitter, rd: Register, imm: u5) void {
                self.rexOptional(Register.rax, rd);

                if (imm == 1) {
                    self.emit8(0xD1);
                    self.modRM(0b11, 0, rd.lowBits());
                } else {
                    self.emit8(0xC1);
                    self.modRM(0b11, 0, rd.lowBits());
                    self.emit8(imm);
                }
            }

            pub inline fn rorImm32(self: *Emitter, rd: Register, imm: u5) void {
                self.rexOptional(Register.rax, rd);

                if (imm == 1) {
                    self.emit8(0xD1);
                    self.modRM(0b11, 1, rd.lowBits());
                } else {
                    self.emit8(0xC1);
                    self.modRM(0b11, 1, rd.lowBits());
                    self.emit8(imm);
                }
            }

            pub inline fn rolCl32(self: *Emitter, rd: Register) void {
                self.rexOptional(Register.rax, rd);
                self.emit8(0xD3);
                self.modRM(0b11, 0, rd.lowBits());
            }

            pub inline fn rorCl32(self: *Emitter, rd: Register) void {
                self.rexOptional(Register.rax, rd);
                self.emit8(0xD3);
                self.modRM(0b11, 1, rd.lowBits());
            }

            pub inline fn imul32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rd, rs);
                self.emit8(0x0F);
                self.emit8(0xAF);
                self.modRMReg(rd, rs);
            }

            pub inline fn imul64(self: *Emitter, rd: Register, rs: Register) void {
                self.rexW(rd, rs);
                self.emit8(0x0F);
                self.emit8(0xAF);
                self.modRMReg(rd, rs);
            }

            pub inline fn imulFull32(self: *Emitter, rs: Register) void {
                self.rexOptional(Register.rax, rs);
                self.emit8(0xF7);
                self.modRM(0b11, 5, rs.lowBits());
            }

            pub inline fn mulFull32(self: *Emitter, rs: Register) void {
                self.rexOptional(Register.rax, rs);
                self.emit8(0xF7);
                self.modRM(0b11, 4, rs.lowBits());
            }

            pub inline fn imulFull64(self: *Emitter, rs: Register) void {
                self.rexW(Register.rax, rs);
                self.emit8(0xF7);
                self.modRM(0b11, 5, rs.lowBits());
            }

            pub inline fn mulFull64(self: *Emitter, rs: Register) void {
                self.rexW(Register.rax, rs);
                self.emit8(0xF7);
                self.modRM(0b11, 4, rs.lowBits());
            }

            pub inline fn idiv32(self: *Emitter, rs: Register) void {
                self.rexOptional(Register.rax, rs);
                self.emit8(0xF7);
                self.modRM(0b11, 7, rs.lowBits());
            }

            pub inline fn div32(self: *Emitter, rs: Register) void {
                self.rexOptional(Register.rax, rs);
                self.emit8(0xF7);
                self.modRM(0b11, 6, rs.lowBits());
            }

            pub inline fn cdq(self: *Emitter) void {
                self.emit8(0x99);
            }

            pub inline fn cmpReg32(self: *Emitter, r1: Register, r2: Register) void {
                self.rexOptional(r2, r1);
                self.emit8(0x39);
                self.modRMReg(r2, r1);
            }

            pub inline fn cmpImm32(self: *Emitter, rd: Register, imm: i32) void {
                self.rexOptional(Register.rax, rd);

                if (imm >= -128 and imm <= 127) {
                    self.emit8(0x83);
                    self.modRM(0b11, 7, rd.lowBits());
                    self.emit8(@bitCast(@as(i8, @truncate(imm))));
                } else {
                    self.emit8(0x81);
                    self.modRM(0b11, 7, rd.lowBits());
                    self.emit32(@bitCast(imm));
                }
            }

            pub inline fn testReg32(self: *Emitter, r1: Register, r2: Register) void {
                self.rexOptional(r2, r1);
                self.emit8(0x85);
                self.modRMReg(r2, r1);
            }

            pub inline fn testImm32(self: *Emitter, rd: Register, imm: u32) void {
                self.rexOptional(Register.rax, rd);

                if (rd == .rax) {
                    self.emit8(0xA9);
                } else {
                    self.emit8(0xF7);
                    self.modRM(0b11, 0, rd.lowBits());
                }

                self.emit32(imm);
            }

            pub inline fn setcc(self: *Emitter, cond: Condition, rd: Register) void {
                if (rd.needsRex() or rd == .rsp or rd == .rbp or rd == .rsi or rd == .rdi) {
                    self.emit8(0x40 | @as(u8, if (rd.needsRex()) 1 else 0));
                }

                self.emit8(0x0F);
                self.emit8(0x90 + @as(u8, @intFromEnum(cond)));
                self.modRM(0b11, 0, rd.lowBits());
            }

            pub inline fn cmovcc32(self: *Emitter, cond: Condition, rd: Register, rs: Register) void {
                self.rexOptional(rd, rs);
                self.emit8(0x0F);
                self.emit8(0x40 + @as(u8, @intFromEnum(cond)));
                self.modRMReg(rd, rs);
            }

            pub inline fn bswap32(self: *Emitter, rd: Register) void {
                if (rd.needsRex()) {
                    self.emit8(0x41);
                }

                self.emit8(0x0F);
                self.emit8(0xC8 + @as(u8, rd.lowBits()));
            }

            pub inline fn bsf32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rd, rs);
                self.emit8(0x0F);
                self.emit8(0xBC);
                self.modRMReg(rd, rs);
            }

            pub inline fn bsr32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rd, rs);
                self.emit8(0x0F);
                self.emit8(0xBD);
                self.modRMReg(rd, rs);
            }

            pub inline fn lzcnt32(self: *Emitter, rd: Register, rs: Register) void {
                self.emit8(0xF3);
                self.rexOptional(rd, rs);
                self.emit8(0x0F);
                self.emit8(0xBD);
                self.modRMReg(rd, rs);
            }

            pub inline fn tzcnt32(self: *Emitter, rd: Register, rs: Register) void {
                self.emit8(0xF3);
                self.rexOptional(rd, rs);
                self.emit8(0x0F);
                self.emit8(0xBC);
                self.modRMReg(rd, rs);
            }

            pub inline fn popcnt32(self: *Emitter, rd: Register, rs: Register) void {
                self.emit8(0xF3);
                self.rexOptional(rd, rs);
                self.emit8(0x0F);
                self.emit8(0xB8);
                self.modRMReg(rd, rs);
            }

            pub inline fn movsx8to32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rd, rs);
                self.emit8(0x0F);
                self.emit8(0xBE);
                self.modRMReg(rd, rs);
            }

            pub inline fn movsx16to32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rd, rs);
                self.emit8(0x0F);
                self.emit8(0xBF);
                self.modRMReg(rd, rs);
            }

            pub inline fn movzx8to32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rd, rs);
                self.emit8(0x0F);
                self.emit8(0xB6);
                self.modRMReg(rd, rs);
            }

            pub inline fn movzx16to32(self: *Emitter, rd: Register, rs: Register) void {
                self.rexOptional(rd, rs);
                self.emit8(0x0F);
                self.emit8(0xB7);
                self.modRMReg(rd, rs);
            }

            pub inline fn push64(self: *Emitter, rs: Register) void {
                if (rs.needsRex()) {
                    self.emit8(0x41);
                }

                self.emit8(0x50 + @as(u8, rs.lowBits()));
            }

            pub inline fn pop64(self: *Emitter, rd: Register) void {
                if (rd.needsRex()) {
                    self.emit8(0x41);
                }

                self.emit8(0x58 + @as(u8, rd.lowBits()));
            }

            pub inline fn ret(self: *Emitter) void {
                self.emit8(0xC3);
            }

            pub inline fn call(self: *Emitter, rs: Register) void {
                if (rs.needsRex()) {
                    self.emit8(0x41);
                }

                self.emit8(0xFF);
                self.modRM(0b11, 2, rs.lowBits());
            }

            pub inline fn jmp(self: *Emitter, offset: i32) void {
                if (offset >= -128 and offset <= 127) {
                    self.emit8(0xEB);
                    self.emit8(@bitCast(@as(i8, @truncate(offset))));
                } else {
                    self.emit8(0xE9);
                    self.emit32(@bitCast(offset));
                }
            }

            pub inline fn jmpReg(self: *Emitter, rs: Register) void {
                if (rs.needsRex()) {
                    self.emit8(0x41);
                }

                self.emit8(0xFF);
                self.modRM(0b11, 4, rs.lowBits());
            }

            pub inline fn jcc(self: *Emitter, cond: Condition, offset: i32) void {
                if (offset >= -128 and offset <= 127) {
                    self.emit8(0x70 + @intFromEnum(cond));
                    self.emit8(@bitCast(@as(i8, @truncate(offset))));
                } else {
                    self.emit8(0x0F);
                    self.emit8(0x80 + @intFromEnum(cond));
                    self.emit32(@bitCast(offset));
                }
            }

            pub inline fn jccPlaceholder(self: *Emitter, cond: Condition) usize {
                self.emit8(0x0F);
                self.emit8(0x80 + @as(u8, @intFromEnum(cond)));

                const patch_offset = self.offset;

                self.emit32(0);

                return patch_offset;
            }

            pub inline fn jmpPlaceholder(self: *Emitter) usize {
                self.emit8(0xE9);

                const patch_offset = self.offset;
                self.emit32(0);

                return patch_offset;
            }

            pub inline fn patchJump(self: *Emitter, patch_offset: usize, target: usize) void {
                const rel: i32 = @intCast(@as(i64, @intCast(target)) - @as(i64, @intCast(patch_offset + 4)));

                std.mem.writeInt(i32, self.buffer[patch_offset..][0..4], rel, .little);
            }

            pub inline fn lea64(self: *Emitter, rd: Register, base: Register, offset: i32) void {
                self.rexW(rd, base);
                self.emit8(0x8D);
                self.emitMemOperand(rd, base, offset);
            }

            pub inline fn movsxd(self: *Emitter, rd: Register, rs: Register) void {
                self.rexW(rd, rs);
                self.emit8(0x63);
                self.modRMReg(rd, rs);
            }

            pub inline fn subImm64(self: *Emitter, rd: Register, imm: i32) void {
                if (imm == 0) {
                    return;
                }

                self.rexW(Register.rax, rd);

                if (imm >= -128 and imm <= 127) {
                    self.emit8(0x83);
                    self.modRM(0b11, 5, rd.lowBits());
                    self.emit8(@bitCast(@as(i8, @truncate(imm))));
                } else {
                    self.emit8(0x81);
                    self.modRM(0b11, 5, rd.lowBits());
                    self.emit32(@bitCast(imm));
                }
            }
        };

        const is_windows = builtin.os.tag == .windows;

        const shadow_space: i32 = if (is_windows) 32 else 0;
        const max_reg_args: u32 = if (is_windows) 4 else 6;

        const cpu_ptr = Emitter.Register.rbx;
        const regs_base = Emitter.Register.r12;
        const float_base = Emitter.Register.r13;
        const ram_base = Emitter.Register.r14;

        const scratch1 = Emitter.Register.rax;
        const scratch2 = Emitter.Register.rcx;
        const scratch3 = Emitter.Register.rdx;
        const scratch4 = Emitter.Register.r8;
        const scratch5 = Emitter.Register.r9;
        const scratch6 = Emitter.Register.r10;
        const scratch7 = Emitter.Register.r11;
        const call_scratch = Emitter.Register.r10;

        const arg0: Emitter.Register = if (is_windows) .rcx else .rdi;
        const arg1: Emitter.Register = if (is_windows) .rdx else .rsi;
        const arg2: Emitter.Register = if (is_windows) .r8 else .rdx;
        const arg3: Emitter.Register = if (is_windows) .r9 else .rcx;
        const arg4: Emitter.Register = .r8;
        const arg5: Emitter.Register = .r9;

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
            ram: []const u8,
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
                const ram_offset = pc -% config.vars.ram_start;

                if (ram_offset + 4 > ram.len) {
                    break;
                }

                const raw = std.mem.readInt(u32, ram[ram_offset..][0..4], .little);
                const inst = arch.Instruction.decode(raw) catch {
                    this.emitUpdateCounters();

                    this.emit.movImm32(scratch1, @intFromEnum(arch.Registers.Mcause.Exception.illegal_instruction));
                    this.emitStoreField32(offsets.trap_cause, scratch1);
                    this.emit.movImm32(scratch1, 0);
                    this.emitStoreField32(offsets.trap_tval, scratch1);

                    this.emitEpilogue(pc, .trap);

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

                pc += 4;

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
            this.emit.push64(.rbx);
            this.emit.push64(.r12);
            this.emit.push64(.r13);
            this.emit.push64(.r14);
            this.emit.push64(.r15);
            this.emit.push64(.rbp);

            if (comptime is_windows) {
                this.emit.push64(.rdi);
                this.emit.push64(.rsi);
            }

            this.emit.subImm64(.rsp, 8);

            this.emit.movReg64(cpu_ptr, arg0);
            this.emit.lea64(regs_base, cpu_ptr, @intCast(offsets.regs));
            this.emit.lea64(float_base, cpu_ptr, @intCast(offsets.float));
        }

        inline fn emitEpilogue(this: *Self, new_pc: u32, result: EngineConfig.State) void {
            this.emit.movImm32(scratch1, new_pc);
            this.emit.movRegToMem32(cpu_ptr, @intCast(offsets.pc), scratch1);
            this.emitEpilogueNoPc(result);
        }

        inline fn emitEpilogueNoPc(this: *Self, result: EngineConfig.State) void {
            this.emit.movImm32(.rax, @intFromEnum(result));
            this.emit.addImm64(.rsp, 8);

            if (comptime is_windows) {
                this.emit.pop64(.rsi);
                this.emit.pop64(.rdi);
            }

            this.emit.pop64(.rbp);
            this.emit.pop64(.r15);
            this.emit.pop64(.r14);
            this.emit.pop64(.r13);
            this.emit.pop64(.r12);
            this.emit.pop64(.rbx);
            this.emit.ret();
        }

        inline fn emitUpdateCounters(this: *Self) void {
            const inst_count = this.instruction_count;
            const cycles = this.cycle_count;

            if (inst_count == 0) {
                return;
            }

            this.emitAdd64Field(offsets.cycle, cycles);
            this.emitAdd64Field(offsets.instret, inst_count);

            if (comptime config.vars.timer_ticks_per_cycle > 0) {
                const mtime_increment = cycles * config.vars.timer_ticks_per_cycle;

                this.emitAdd64Field(offsets.mtime, mtime_increment);
            }
        }

        inline fn emitAdd64Field(this: *Self, field_offset: usize, value: u64) void {
            this.emit.movMemToReg64(scratch1, cpu_ptr, @intCast(field_offset));

            if (value <= 0x7FFFFFFF) {
                this.emit.addImm64(scratch1, @intCast(value));
            } else {
                this.emit.movImm64(scratch2, value);
                this.emit.addReg64(scratch1, scratch2);
            }

            this.emit.movRegToMem64(cpu_ptr, @intCast(field_offset), scratch1);
        }

        inline fn loadGuestReg(this: *Self, host_reg: Emitter.Register, guest_reg: u8) void {
            if (guest_reg == 0) {
                this.emit.movImm32(host_reg, 0);
            } else {
                const offset: i32 = @as(i32, guest_reg) * 4;

                this.emit.movMemToReg32(host_reg, regs_base, offset);
            }
        }

        inline fn storeGuestReg(this: *Self, guest_reg: u8, host_reg: Emitter.Register) void {
            if (guest_reg == 0) {
                return;
            }

            const offset: i32 = @as(i32, guest_reg) * 4;

            this.emit.movRegToMem32(regs_base, offset, host_reg);
        }

        inline fn emitLoadField32(this: *Self, dest: Emitter.Register, field_offset: usize) void {
            this.emit.movMemToReg32(dest, cpu_ptr, @intCast(field_offset));
        }

        inline fn emitStoreField32(this: *Self, field_offset: usize, src: Emitter.Register) void {
            this.emit.movRegToMem32(cpu_ptr, @intCast(field_offset), src);
        }

        inline fn emitAddImmediate(this: *Self, rd: Emitter.Register, rn: Emitter.Register, imm: i32) void {
            if (rd != rn) {
                this.emit.movReg32(rd, rn);
            }

            if (imm != 0) {
                this.emit.addImm32(rd, imm);
            }
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
                    this.emitBranch(i, pc, .e);

                    return .epilogue_emitted;
                },
                .bne => |i| {
                    this.emitUpdateCounters();
                    this.emitBranch(i, pc, .ne);

                    return .epilogue_emitted;
                },
                .blt => |i| {
                    this.emitUpdateCounters();
                    this.emitBranch(i, pc, .l);

                    return .epilogue_emitted;
                },
                .bge => |i| {
                    this.emitUpdateCounters();
                    this.emitBranch(i, pc, .ge);

                    return .epilogue_emitted;
                },
                .bltu => |i| {
                    this.emitUpdateCounters();
                    this.emitBranch(i, pc, .b);

                    return .epilogue_emitted;
                },
                .bgeu => |i| {
                    this.emitUpdateCounters();
                    this.emitBranch(i, pc, .ae);

                    return .epilogue_emitted;
                },
                .lb => |i| this.emitLoadCallback(i, pc, .byte_signed, config.memory_callbacks.read_byte),
                .lh => |i| this.emitLoadCallback(i, pc, .half_signed, config.memory_callbacks.read_half),
                .lw => |i| this.emitLoadCallback(i, pc, .word, config.memory_callbacks.read_word),
                .lbu => |i| this.emitLoadCallback(i, pc, .byte_unsigned, config.memory_callbacks.read_byte),
                .lhu => |i| this.emitLoadCallback(i, pc, .half_unsigned, config.memory_callbacks.read_half),
                .sb => |i| this.emitStoreCallback(i, pc, .byte, config.memory_callbacks.write_byte),
                .sh => |i| this.emitStoreCallback(i, pc, .half, config.memory_callbacks.write_half),
                .sw => |i| this.emitStoreCallback(i, pc, .word, config.memory_callbacks.write_word),
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
                .fmadd_s => |i| this.emitFMADD_S(i, pc),
                .fmsub_s => |i| this.emitFMSUB_S(i, pc),
                .fnmadd_s => |i| this.emitFNMADD_S(i, pc),
                .fnmsub_s => |i| this.emitFNMSUB_S(i, pc),
                .fadd_s => |i| this.emitFADD_S(i, pc),
                .fsub_s => |i| this.emitFSUB_S(i, pc),
                .fmul_s => |i| this.emitFMUL_S(i, pc),
                .fdiv_s => |i| this.emitFDIV_S(i, pc),
                .fsqrt_s => |i| this.emitFSQRT_S(i, pc),
                .fsgnj_s => |i| this.emitFSGNJ_S(i, pc),
                .fsgnjn_s => |i| this.emitFSGNJN_S(i, pc),
                .fsgnjx_s => |i| this.emitFSGNJX_S(i, pc),
                .fmin_s => |i| this.emitFMIN_S(i, pc),
                .fmax_s => |i| this.emitFMAX_S(i, pc),
                .fcvt_w_s => |i| this.emitFCVT_W_S(i, pc),
                .fcvt_wu_s => |i| this.emitFCVT_WU_S(i, pc),
                .fmv_x_w => |i| this.emitFMV_X_W(i, pc),
                .feq_s => |i| this.emitFEQ_S(i, pc),
                .flt_s => |i| this.emitFLT_S(i, pc),
                .fle_s => |i| this.emitFLE_S(i, pc),
                .fclass_s => |i| this.emitFCLASS_S(i, pc),
                .fcvt_s_w => |i| this.emitFCVT_S_W(i, pc),
                .fcvt_s_wu => |i| this.emitFCVT_S_WU(i, pc),
                .fmv_w_x => |i| this.emitFMV_W_X(i, pc),
                // Zba
                .sh1add => |i| this.emitSH1ADD(i),
                .sh2add => |i| this.emitSH2ADD(i),
                .sh3add => |i| this.emitSH3ADD(i),
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
                // CSR
                .csrrw => |i| {
                    this.emitCSRRW(i, pc);

                    return .end_block;
                },
                .csrrs => |i| {
                    this.emitCSRRS(i, pc);

                    return .end_block;
                },
                .csrrc => |i| {
                    this.emitCSRRC(i, pc);

                    return .end_block;
                },
                .csrrwi => |i| {
                    this.emitCSRRWI(i, pc);

                    return .end_block;
                },
                .csrrsi => |i| {
                    this.emitCSRRSI(i, pc);

                    return .end_block;
                },
                .csrrci => |i| {
                    this.emitCSRRCI(i, pc);

                    return .end_block;
                },
                .fence_i => {
                    this.emitUpdateCounters();
                    this.emitEpilogue(pc + 4, .ok);

                    return .epilogue_emitted;
                },
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
            const result = pc +% offset;

            this.emit.movImm32(scratch1, result);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitADDI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emitAddImmediate(scratch1, scratch1, i.imm);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLTI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.cmpImm32(scratch1, i.imm);
            this.emit.setcc(.l, scratch1);
            this.emit.movzx8to32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLTIU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.cmpImm32(scratch1, i.imm);
            this.emit.setcc(.b, scratch1);
            this.emit.movzx8to32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitXORI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.imm == -1) {
                this.emit.notReg32(scratch1);
            } else if (i.imm != 0) {
                this.emit.movImm32(scratch2, @bitCast(i.imm));
                this.emit.xorReg32(scratch1, scratch2);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitORI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.imm != 0) {
                this.emit.orImm32(scratch1, i.imm);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitANDI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.andImm32(scratch1, i.imm);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLLI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.shamt != 0) {
                this.emit.shlImm32(scratch1, i.shamt);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSRLI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.shamt != 0) {
                this.emit.shrImm32(scratch1, i.shamt);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSRAI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.shamt != 0) {
                this.emit.sarImm32(scratch1, i.shamt);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitADD(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.addReg32(scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSUB(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.subReg32(scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLL(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(.rcx, i.rs2);
            this.emit.shlCl32(scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLT(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.setcc(.l, scratch1);
            this.emit.movzx8to32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSLTU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.setcc(.b, scratch1);
            this.emit.movzx8to32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitXOR(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.xorReg32(scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSRL(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(.rcx, i.rs2);
            this.emit.shrCl32(scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSRA(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(.rcx, i.rs2);
            this.emit.sarCl32(scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitOR(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.orReg32(scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitAND(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.andReg32(scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitJAL(this: *Self, i: anytype, pc: u32) void {
            const target: u32 = @bitCast(@as(i32, @intCast(pc)) +% i.imm);

            if (i.rd != 0) {
                this.emit.movImm32(scratch1, pc + 4);
                this.storeGuestReg(i.rd, scratch1);
            }

            this.emit.movImm32(scratch1, target);
            this.emit.movRegToMem32(cpu_ptr, @intCast(offsets.pc), scratch1);
            this.emitEpilogueNoPc(.ok);
        }

        inline fn emitJALR(this: *Self, i: anytype, pc: u32) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.rd != 0) {
                this.emit.movImm32(scratch2, pc + 4);
                this.storeGuestReg(i.rd, scratch2);
            }

            this.emitAddImmediate(scratch1, scratch1, i.imm);
            this.emit.andImm32(scratch1, @bitCast(@as(i32, -2)));

            this.emit.movRegToMem32(cpu_ptr, @intCast(offsets.pc), scratch1);
            this.emitEpilogueNoPc(.ok);
        }

        inline fn emitBranch(this: *Self, i: anytype, pc: u32, comptime cond: Emitter.Condition) void {
            const taken_pc: u32 = @bitCast(@as(i32, @intCast(pc)) +% i.imm);
            const not_taken_pc = pc + 4;

            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);

            this.emit.movImm32(scratch4, taken_pc);
            this.emit.movImm32(scratch5, not_taken_pc);

            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.cmovcc32(cond, scratch5, scratch4);

            this.emit.movRegToMem32(cpu_ptr, @intCast(offsets.pc), scratch5);
            this.emitEpilogueNoPc(.ok);
        }

        const LoadSize = enum {
            byte_signed,
            byte_unsigned,
            half_signed,
            half_unsigned,
            word,
        };

        const StoreSize = enum { byte, half, word };

        inline fn emitLoadCallback(
            this: *Self,
            i: anytype,
            pc: u32,
            comptime size: LoadSize,
            comptime callback: anytype,
        ) void {
            this.loadGuestReg(scratch6, i.rs1);
            this.emitAddImmediate(scratch6, scratch6, i.imm);

            _ = this.emitCallPrepare(2);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movReg32(arg1, scratch6);
            this.emitCallFinish(@intFromPtr(callback), 2);

            this.emit.movReg64(scratch2, .rax);
            this.emit.shrImm64(scratch2, 32);
            this.emit.testReg32(scratch2, scratch2);

            const ok_branch = this.emit.jccPlaceholder(.e);
            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);
            this.emit.patchJump(ok_branch, this.emit.offset);

            switch (size) {
                .byte_signed => this.emit.movsx8to32(scratch1, .rax),
                .half_signed => this.emit.movsx16to32(scratch1, .rax),
                .byte_unsigned => this.emit.movzx8to32(scratch1, .rax),
                .half_unsigned => this.emit.movzx16to32(scratch1, .rax),
                .word => this.emit.movReg32(scratch1, .rax),
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitStoreCallback(
            this: *Self,
            i: anytype,
            pc: u32,
            comptime size: StoreSize,
            comptime callback: anytype,
        ) void {
            this.loadGuestReg(scratch6, i.rs1);
            this.emitAddImmediate(scratch6, scratch6, i.imm);
            this.loadGuestReg(scratch7, i.rs2);

            _ = this.emitCallPrepare(3);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movReg32(arg1, scratch6);

            switch (size) {
                .byte => this.emit.movzx8to32(arg2, scratch7),
                .half => this.emit.movzx16to32(arg2, scratch7),
                .word => this.emit.movReg32(arg2, scratch7),
            }

            this.emitCallFinish(@intFromPtr(callback), 3);

            this.emit.testReg32(.rax, .rax);
            const ok_branch = this.emit.jccPlaceholder(.e);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);
            this.emit.patchJump(ok_branch, this.emit.offset);
        }

        inline fn emitMUL(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch4, i.rs2);
            this.emit.imul32(scratch1, scratch4);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMULH(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch4, i.rs2);

            this.emit.movsxd(scratch1, scratch1);
            this.emit.movsxd(scratch4, scratch4);

            this.emit.imul64(scratch1, scratch4);
            this.emit.shrImm64(scratch1, 32);

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMULHSU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch4, i.rs2);

            this.emit.movsxd(scratch1, scratch1);
            this.emit.movReg32(scratch4, scratch4);

            this.emit.imul64(scratch1, scratch4);
            this.emit.shrImm64(scratch1, 32);

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMULHU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch4, i.rs2);

            this.emit.movReg32(scratch1, scratch1);
            this.emit.movReg32(scratch4, scratch4);

            this.emit.imul64(scratch1, scratch4);
            this.emit.shrImm64(scratch1, 32);

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitDIV(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch4, i.rs2);

            this.emit.testReg32(scratch4, scratch4);
            const not_zero = this.emit.jccPlaceholder(.ne);

            this.emit.movImm32(scratch1, 0xFFFFFFFF);
            const done1 = this.emit.jmpPlaceholder();

            this.emit.patchJump(not_zero, this.emit.offset);

            this.emit.cmpImm32(scratch1, std.math.minInt(i32));
            const not_min = this.emit.jccPlaceholder(.ne);

            this.emit.cmpImm32(scratch4, -1);
            const not_neg1 = this.emit.jccPlaceholder(.ne);

            const done2 = this.emit.jmpPlaceholder();

            this.emit.patchJump(not_min, this.emit.offset);
            this.emit.patchJump(not_neg1, this.emit.offset);

            this.emit.cdq();
            this.emit.idiv32(scratch4);

            this.emit.patchJump(done1, this.emit.offset);
            this.emit.patchJump(done2, this.emit.offset);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitDIVU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch4, i.rs2);

            this.emit.testReg32(scratch4, scratch4);
            const not_zero = this.emit.jccPlaceholder(.ne);

            this.emit.movImm32(scratch1, 0xFFFFFFFF);
            const done = this.emit.jmpPlaceholder();

            this.emit.patchJump(not_zero, this.emit.offset);

            this.emit.movImm32(scratch3, 0);
            this.emit.div32(scratch4);

            this.emit.patchJump(done, this.emit.offset);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitREM(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch4, i.rs2);

            this.emit.testReg32(scratch4, scratch4);
            const not_zero = this.emit.jccPlaceholder(.ne);
            const done1 = this.emit.jmpPlaceholder();

            this.emit.patchJump(not_zero, this.emit.offset);

            this.emit.cmpImm32(scratch1, std.math.minInt(i32));
            const not_min = this.emit.jccPlaceholder(.ne);
            this.emit.cmpImm32(scratch4, -1);
            const not_neg1 = this.emit.jccPlaceholder(.ne);

            this.emit.movImm32(scratch1, 0);
            const done2 = this.emit.jmpPlaceholder();

            this.emit.patchJump(not_min, this.emit.offset);
            this.emit.patchJump(not_neg1, this.emit.offset);

            this.emit.cdq();
            this.emit.idiv32(scratch4);
            this.emit.movReg32(scratch1, scratch3);

            this.emit.patchJump(done1, this.emit.offset);
            this.emit.patchJump(done2, this.emit.offset);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitREMU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch4, i.rs2);

            this.emit.testReg32(scratch4, scratch4);
            const not_zero = this.emit.jccPlaceholder(.ne);
            const done1 = this.emit.jmpPlaceholder();

            this.emit.patchJump(not_zero, this.emit.offset);

            this.emit.movImm32(scratch3, 0);
            this.emit.div32(scratch4);
            this.emit.movReg32(scratch1, scratch3);

            this.emit.patchJump(done1, this.emit.offset);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSH1ADD(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.shlImm32(scratch1, 1);
            this.emit.addReg32(scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSH2ADD(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.shlImm32(scratch1, 2);
            this.emit.addReg32(scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSH3ADD(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.shlImm32(scratch1, 3);
            this.emit.addReg32(scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitANDN(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);

            if (comptime has_bmi) {
                this.emit.andnReg32(scratch1, scratch2, scratch1);
            } else {
                this.emit.notReg32(scratch2);
                this.emit.andReg32(scratch1, scratch2);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitORN(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.notReg32(scratch2);
            this.emit.orReg32(scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitXNOR(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.xorReg32(scratch1, scratch2);
            this.emit.notReg32(scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitCLZ(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (comptime has_lzcnt) {
                this.emit.lzcnt32(scratch1, scratch1);
            } else {
                this.emit.testReg32(scratch1, scratch1);
                const not_zero = this.emit.jccPlaceholder(.ne);

                this.emit.movImm32(scratch1, 32);
                const done = this.emit.jmpPlaceholder();

                this.emit.patchJump(not_zero, this.emit.offset);
                this.emit.bsr32(scratch1, scratch1);
                this.emit.movImm32(scratch2, 31);
                this.emit.subReg32(scratch2, scratch1);
                this.emit.movReg32(scratch1, scratch2);

                this.emit.patchJump(done, this.emit.offset);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitCTZ(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (comptime has_bmi) {
                this.emit.tzcnt32(scratch1, scratch1);
            } else {
                this.emit.testReg32(scratch1, scratch1);
                const not_zero = this.emit.jccPlaceholder(.ne);

                this.emit.movImm32(scratch1, 32);
                const done = this.emit.jmpPlaceholder();

                this.emit.patchJump(not_zero, this.emit.offset);
                this.emit.bsf32(scratch1, scratch1);

                this.emit.patchJump(done, this.emit.offset);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitCPOP(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (comptime has_popcnt) {
                this.emit.popcnt32(scratch1, scratch1);
            } else {
                this.emit.movReg32(scratch2, scratch1);
                this.emit.shrImm32(scratch2, 1);
                this.emit.movImm32(scratch3, 0x55555555);
                this.emit.andReg32(scratch2, scratch3);
                this.emit.subReg32(scratch1, scratch2);

                this.emit.movImm32(scratch3, 0x33333333);
                this.emit.movReg32(scratch2, scratch1);
                this.emit.andReg32(scratch2, scratch3);
                this.emit.shrImm32(scratch1, 2);
                this.emit.andReg32(scratch1, scratch3);
                this.emit.addReg32(scratch1, scratch2);

                this.emit.movReg32(scratch2, scratch1);
                this.emit.shrImm32(scratch2, 4);
                this.emit.addReg32(scratch1, scratch2);
                this.emit.movImm32(scratch3, 0x0F0F0F0F);
                this.emit.andReg32(scratch1, scratch3);

                this.emit.movReg32(scratch2, scratch1);
                this.emit.shrImm32(scratch2, 8);
                this.emit.addReg32(scratch1, scratch2);

                this.emit.movReg32(scratch2, scratch1);
                this.emit.shrImm32(scratch2, 16);
                this.emit.addReg32(scratch1, scratch2);
                this.emit.andImm32(scratch1, 0x3F);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMAX(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.cmovcc32(.l, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMAXU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.cmovcc32(.b, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMIN(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.cmovcc32(.g, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitMINU(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(scratch2, i.rs2);
            this.emit.cmpReg32(scratch1, scratch2);
            this.emit.cmovcc32(.a, scratch1, scratch2);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSEXTB(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.movsx8to32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitSEXTH(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.movsx16to32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitZEXTH(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.movzx16to32(scratch1, scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitROL(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(.rcx, i.rs2);
            this.emit.rolCl32(scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitROR(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.loadGuestReg(.rcx, i.rs2);
            this.emit.rorCl32(scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitRORI(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            if (i.shamt != 0) {
                this.emit.rorImm32(scratch1, i.shamt);
            }

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitORCB(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);

            this.emit.movReg32(scratch2, scratch1);
            this.emit.shrImm32(scratch2, 1);
            this.emit.movImm32(scratch3, 0x7F7F7F7F);
            this.emit.andReg32(scratch2, scratch3);
            this.emit.orReg32(scratch1, scratch2);

            this.emit.movReg32(scratch2, scratch1);
            this.emit.shrImm32(scratch2, 2);
            this.emit.movImm32(scratch3, 0x3F3F3F3F);
            this.emit.andReg32(scratch2, scratch3);
            this.emit.orReg32(scratch1, scratch2);

            this.emit.movReg32(scratch2, scratch1);
            this.emit.shrImm32(scratch2, 4);
            this.emit.movImm32(scratch3, 0x0F0F0F0F);
            this.emit.andReg32(scratch2, scratch3);
            this.emit.orReg32(scratch1, scratch2);

            this.emit.movReg32(scratch2, scratch1);
            this.emit.shlImm32(scratch2, 1);
            this.emit.movImm32(scratch3, 0xFEFEFEFE);
            this.emit.andReg32(scratch2, scratch3);
            this.emit.orReg32(scratch1, scratch2);

            this.emit.movReg32(scratch2, scratch1);
            this.emit.shlImm32(scratch2, 2);
            this.emit.movImm32(scratch3, 0xFCFCFCFC);
            this.emit.andReg32(scratch2, scratch3);
            this.emit.orReg32(scratch1, scratch2);

            this.emit.movReg32(scratch2, scratch1);
            this.emit.shlImm32(scratch2, 4);
            this.emit.movImm32(scratch3, 0xF0F0F0F0);
            this.emit.andReg32(scratch2, scratch3);
            this.emit.orReg32(scratch1, scratch2);

            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitREV8(this: *Self, i: anytype) void {
            this.loadGuestReg(scratch1, i.rs1);
            this.emit.bswap32(scratch1);
            this.storeGuestReg(i.rd, scratch1);
        }

        inline fn emitEcall(this: *Self, pc: u32) void {
            const ecall_from_u: u32 = @intFromEnum(arch.Registers.Mcause.Exception.ecall_from_u);
            const ecall_from_m: u32 = @intFromEnum(arch.Registers.Mcause.Exception.ecall_from_m);

            this.emit.movImm32(scratch2, ecall_from_u);
            this.emit.movImm32(scratch3, ecall_from_m);

            this.emitLoadField32(scratch1, offsets.privilege);
            this.emit.testReg32(scratch1, scratch1);
            this.emit.cmovcc32(.ne, scratch2, scratch3);

            this.emitStoreField32(offsets.trap_cause, scratch2);
            this.emit.movImm32(scratch1, 0);
            this.emitStoreField32(offsets.trap_tval, scratch1);

            if (comptime config.hooks.ecall) |hook| {
                _ = this.emitCallPrepare(2);
                this.emit.movReg64(arg0, cpu_ptr);
                this.emitLoadField32(arg1, offsets.trap_cause);
                this.emitCallFinish(@intFromPtr(hook), 2);

                this.emit.cmpImm32(.rax, @intFromEnum(EngineConfig.Hooks.Action.skip));
                const skip_branch = this.emit.jccPlaceholder(.e);

                this.emit.cmpImm32(.rax, @intFromEnum(EngineConfig.Hooks.Action.halt));
                const halt_branch = this.emit.jccPlaceholder(.e);

                this.emitEpilogue(pc, .trap);

                this.emit.patchJump(skip_branch, this.emit.offset);
                this.emitEpilogue(pc + 4, .ok);

                this.emit.patchJump(halt_branch, this.emit.offset);
                this.emitEpilogue(pc, .halt);
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
                _ = this.emitCallPrepare(1);
                this.emit.movReg64(arg0, cpu_ptr);
                this.emitCallFinish(@intFromPtr(hook), 1);

                this.emit.cmpImm32(.rax, @intFromEnum(EngineConfig.Hooks.Action.skip));
                const skip_branch = this.emit.jccPlaceholder(.e);

                this.emit.cmpImm32(.rax, @intFromEnum(EngineConfig.Hooks.Action.halt));
                const halt_branch = this.emit.jccPlaceholder(.e);

                this.emitEpilogue(pc, .trap);

                this.emit.patchJump(skip_branch, this.emit.offset);
                this.emitEpilogue(pc + 4, .ok);

                this.emit.patchJump(halt_branch, this.emit.offset);
                this.emitEpilogue(pc, .halt);
            } else {
                this.emitEpilogue(pc, .trap);
            }
        }

        inline fn emitCSRRW(this: *Self, i: anytype, pc: u32) void {
            this.emitUpdateCounters();
            this.loadGuestReg(scratch6, i.rs1);

            _ = this.emitCallPrepare(5);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movImm32(arg1, i.csr);
            this.emit.movReg32(arg2, scratch6);
            this.emit.movImm32(arg3, @intFromEnum(EngineConfig.Callbacks.CsrOp.rw));

            if (comptime is_windows) {
                this.emitStackArgImm(0, 1);
            } else {
                this.emit.movImm32(arg4, 1);
            }

            this.emitCallFinish(@intFromPtr(config.callbacks.csr_op), 5);

            this.emit.movReg64(scratch2, .rax);
            this.emit.shrImm64(scratch2, 32);
            this.emit.testReg32(scratch2, scratch2);
            const trap_branch = this.emit.jccPlaceholder(.ne);

            if (i.rd != 0) {
                this.emit.movReg32(scratch1, .rax);
                this.storeGuestReg(i.rd, scratch1);
            }

            this.emitEpilogue(pc + 4, .ok);

            this.emit.patchJump(trap_branch, this.emit.offset);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitCSRRS(this: *Self, i: anytype, pc: u32) void {
            this.emitUpdateCounters();
            this.loadGuestReg(scratch6, i.rs1);

            _ = this.emitCallPrepare(5);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movImm32(arg1, i.csr);
            this.emit.movReg32(arg2, scratch6);
            this.emit.movImm32(arg3, @intFromEnum(EngineConfig.Callbacks.CsrOp.rs));

            if (comptime is_windows) {
                this.emitStackArgImm(0, if (i.rs1 != 0) 1 else 0);
            } else {
                this.emit.movImm32(arg4, if (i.rs1 != 0) 1 else 0);
            }

            this.emitCallFinish(@intFromPtr(config.callbacks.csr_op), 5);

            this.emit.movReg64(scratch2, .rax);
            this.emit.shrImm64(scratch2, 32);
            this.emit.testReg32(scratch2, scratch2);

            const trap_branch = this.emit.jccPlaceholder(.ne);

            if (i.rd != 0) {
                this.emit.movReg32(scratch1, .rax);
                this.storeGuestReg(i.rd, scratch1);
            }

            this.emitEpilogue(pc + 4, .ok);

            this.emit.patchJump(trap_branch, this.emit.offset);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitCSRRC(this: *Self, i: anytype, pc: u32) void {
            this.emitUpdateCounters();
            this.loadGuestReg(scratch6, i.rs1);

            _ = this.emitCallPrepare(5);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movImm32(arg1, i.csr);
            this.emit.movReg32(arg2, scratch6);
            this.emit.movImm32(arg3, @intFromEnum(EngineConfig.Callbacks.CsrOp.rc));

            if (comptime is_windows) {
                this.emitStackArgImm(0, if (i.rs1 != 0) 1 else 0);
            } else {
                this.emit.movImm32(arg4, if (i.rs1 != 0) 1 else 0);
            }

            this.emitCallFinish(@intFromPtr(config.callbacks.csr_op), 5);

            this.emit.movReg64(scratch2, .rax);
            this.emit.shrImm64(scratch2, 32);
            this.emit.testReg32(scratch2, scratch2);

            const trap_branch = this.emit.jccPlaceholder(.ne);

            if (i.rd != 0) {
                this.emit.movReg32(scratch1, .rax);
                this.storeGuestReg(i.rd, scratch1);
            }

            this.emitEpilogue(pc + 4, .ok);

            this.emit.patchJump(trap_branch, this.emit.offset);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitCSRRWI(this: *Self, i: anytype, pc: u32) void {
            this.emitUpdateCounters();

            _ = this.emitCallPrepare(5);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movImm32(arg1, i.csr);
            this.emit.movImm32(arg2, @as(u32, i.uimm));
            this.emit.movImm32(arg3, @intFromEnum(EngineConfig.Callbacks.CsrOp.rw));

            if (comptime is_windows) {
                this.emitStackArgImm(0, 1);
            } else {
                this.emit.movImm32(arg4, 1);
            }

            this.emitCallFinish(@intFromPtr(config.callbacks.csr_op), 5);

            this.emit.movReg64(scratch2, .rax);
            this.emit.shrImm64(scratch2, 32);
            this.emit.testReg32(scratch2, scratch2);

            const trap_branch = this.emit.jccPlaceholder(.ne);

            if (i.rd != 0) {
                this.emit.movReg32(scratch1, .rax);
                this.storeGuestReg(i.rd, scratch1);
            }

            this.emitEpilogue(pc + 4, .ok);

            this.emit.patchJump(trap_branch, this.emit.offset);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitCSRRSI(this: *Self, i: anytype, pc: u32) void {
            this.emitUpdateCounters();

            _ = this.emitCallPrepare(5);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movImm32(arg1, i.csr);
            this.emit.movImm32(arg2, @as(u32, i.uimm));
            this.emit.movImm32(arg3, @intFromEnum(EngineConfig.Callbacks.CsrOp.rs));

            if (comptime is_windows) {
                this.emitStackArgImm(0, if (i.uimm != 0) 1 else 0);
            } else {
                this.emit.movImm32(arg4, if (i.uimm != 0) 1 else 0);
            }

            this.emitCallFinish(@intFromPtr(config.callbacks.csr_op), 5);

            this.emit.movReg64(scratch2, .rax);
            this.emit.shrImm64(scratch2, 32);
            this.emit.testReg32(scratch2, scratch2);

            const trap_branch = this.emit.jccPlaceholder(.ne);

            if (i.rd != 0) {
                this.emit.movReg32(scratch1, .rax);
                this.storeGuestReg(i.rd, scratch1);
            }

            this.emitEpilogue(pc + 4, .ok);

            this.emit.patchJump(trap_branch, this.emit.offset);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitCSRRCI(this: *Self, i: anytype, pc: u32) void {
            this.emitUpdateCounters();

            _ = this.emitCallPrepare(5);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movImm32(arg1, i.csr);
            this.emit.movImm32(arg2, @as(u32, i.uimm));
            this.emit.movImm32(arg3, @intFromEnum(EngineConfig.Callbacks.CsrOp.rc));

            if (comptime is_windows) {
                this.emitStackArgImm(0, if (i.uimm != 0) 1 else 0);
            } else {
                this.emit.movImm32(arg4, if (i.uimm != 0) 1 else 0);
            }

            this.emitCallFinish(@intFromPtr(config.callbacks.csr_op), 5);

            this.emit.movReg64(scratch2, .rax);
            this.emit.shrImm64(scratch2, 32);
            this.emit.testReg32(scratch2, scratch2);

            const trap_branch = this.emit.jccPlaceholder(.ne);

            if (i.rd != 0) {
                this.emit.movReg32(scratch1, .rax);
                this.storeGuestReg(i.rd, scratch1);
            }

            this.emitEpilogue(pc + 4, .ok);

            this.emit.patchJump(trap_branch, this.emit.offset);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitFLW(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadGuestReg(scratch6, i.rs1);
            this.emitAddImmediate(scratch6, scratch6, i.imm);

            _ = this.emitCallPrepare(2);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movReg32(arg1, scratch6);
            this.emitCallFinish(@intFromPtr(config.memory_callbacks.read_word), 2);

            this.emit.movReg64(scratch2, .rax);
            this.emit.shrImm64(scratch2, 32);
            this.emit.testReg32(scratch2, scratch2);

            const ok_branch = this.emit.jccPlaceholder(.e);
            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);
            this.emit.patchJump(ok_branch, this.emit.offset);

            this.storeFpReg32Boxed(i.rd, .rax);
            this.emitMarkFpDirty();
        }

        inline fn emitFSW(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadGuestReg(scratch6, i.rs1);
            this.emitAddImmediate(scratch6, scratch6, i.imm);
            this.loadFpRegRaw(scratch7, i.rs2);

            _ = this.emitCallPrepare(3);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movReg32(arg1, scratch6);
            this.emit.movReg32(arg2, scratch7);
            this.emitCallFinish(@intFromPtr(config.memory_callbacks.write_word), 3);

            this.emit.testReg32(.rax, .rax);
            const ok_branch = this.emit.jccPlaceholder(.e);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);
            this.emit.patchJump(ok_branch, this.emit.offset);
        }

        inline fn emitFMV_X_W(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadFpRegRaw(scratch1, i.rs1);

            this.emit.movReg64(scratch2, scratch1);
            this.emit.shrImm64(scratch2, 32);
            this.emit.cmpImm32(scratch2, @bitCast(@as(i32, -1)));

            const boxed = this.emit.jccPlaceholder(.e);

            this.emit.movImm32(scratch1, 0x7FC00000);

            this.emit.patchJump(boxed, this.emit.offset);
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
            this.emit.movReg64(scratch2, scratch1);
            this.emit.shrImm64(scratch2, 32);
            this.emit.cmpImm32(scratch2, @bitCast(@as(i32, -1)));

            const boxed = this.emit.jccPlaceholder(.e);
            this.emit.movImm32(scratch1, 0x7FC00000);
            this.emit.patchJump(boxed, this.emit.offset);

            this.loadFpRegRaw(scratch2, i.rs2);

            this.emit.andImm32(scratch1, 0x7FFFFFFF);
            this.emit.movReg32(scratch3, scratch2);
            this.emit.andImm32(scratch3, @bitCast(@as(i32, -0x80000000)));
            this.emit.orReg32(scratch1, scratch3);

            this.storeFpReg32Boxed(i.rd, scratch1);
            this.emitMarkFpDirty();
        }

        inline fn emitFSGNJN_S(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadFpRegRaw(scratch1, i.rs1);
            this.emit.movReg64(scratch2, scratch1);
            this.emit.shrImm64(scratch2, 32);
            this.emit.cmpImm32(scratch2, @bitCast(@as(i32, -1)));

            const boxed = this.emit.jccPlaceholder(.e);
            this.emit.movImm32(scratch1, 0x7FC00000);
            this.emit.patchJump(boxed, this.emit.offset);

            this.loadFpRegRaw(scratch2, i.rs2);

            this.emit.andImm32(scratch1, 0x7FFFFFFF);
            this.emit.notReg32(scratch2);
            this.emit.andImm32(scratch2, @bitCast(@as(i32, -0x80000000)));
            this.emit.orReg32(scratch1, scratch2);

            this.storeFpReg32Boxed(i.rd, scratch1);
            this.emitMarkFpDirty();
        }

        inline fn emitFSGNJX_S(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadFpRegRaw(scratch1, i.rs1);
            this.emit.movReg64(scratch2, scratch1);
            this.emit.shrImm64(scratch2, 32);
            this.emit.cmpImm32(scratch2, @bitCast(@as(i32, -1)));

            const boxed = this.emit.jccPlaceholder(.e);
            this.emit.movImm32(scratch1, 0x7FC00000);
            this.emit.patchJump(boxed, this.emit.offset);

            this.loadFpRegRaw(scratch2, i.rs2);

            this.emit.andImm32(scratch2, @bitCast(@as(i32, -0x80000000)));
            this.emit.xorReg32(scratch1, scratch2);

            this.storeFpReg32Boxed(i.rd, scratch1);
            this.emitMarkFpDirty();
        }

        inline fn emitFCLASS_S(this: *Self, i: anytype, pc: u32) void {
            this.emitCheckFpAccess(pc);

            this.loadFpRegRaw(scratch6, i.rs1);
            this.emit.movReg64(scratch7, scratch6);
            this.emit.shrImm64(scratch7, 32);
            this.emit.cmpImm32(scratch7, @bitCast(@as(i32, -1)));

            const nan_boxed = this.emit.jccPlaceholder(.e);

            this.emit.movImm32(scratch1, 0x200);
            this.storeGuestReg(i.rd, scratch1);
            const done = this.emit.jmpPlaceholder();

            this.emit.patchJump(nan_boxed, this.emit.offset);

            _ = this.emitCallPrepare(5);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movImm32(arg1, @intFromEnum(EngineConfig.Callbacks.UnaryOpS.fclass));
            this.emit.movImm32(arg2, i.rd);
            this.emit.movImm32(arg3, i.rs1);

            if (comptime is_windows) {
                this.emitStackArgImm(0, 0);
            } else {
                this.emit.movImm32(arg4, 0);
            }

            this.emitCallFinish(@intFromPtr(config.callbacks.unary_s), 5);

            this.emit.testReg32(.rax, .rax);

            const ok_branch = this.emit.jccPlaceholder(.e);
            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);

            this.emit.patchJump(ok_branch, this.emit.offset);
            this.emit.patchJump(done, this.emit.offset);
        }

        inline fn emitFpBinaryOp(this: *Self, i: anytype, pc: u32, rm: u3, comptime op: EngineConfig.Callbacks.BinaryOpS) void {
            this.emitCheckFpAccess(pc);

            _ = this.emitCallPrepare(6);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movImm32(arg1, @intFromEnum(op));
            this.emit.movImm32(arg2, i.rd);
            this.emit.movImm32(arg3, i.rs1);

            if (comptime is_windows) {
                this.emitStackArgImm(0, i.rs2);
                this.emitStackArgImm(1, rm);
            } else {
                this.emit.movImm32(arg4, i.rs2);
                this.emit.movImm32(arg5, rm);
            }

            this.emitCallFinish(@intFromPtr(config.callbacks.binary_s), 6);

            this.emit.testReg32(.rax, .rax);
            const ok_branch = this.emit.jccPlaceholder(.e);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);
            this.emit.patchJump(ok_branch, this.emit.offset);
        }

        inline fn emitFADD_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpBinaryOp(i, pc, i.rm, .add);
        }

        inline fn emitFSUB_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpBinaryOp(i, pc, i.rm, .sub);
        }

        inline fn emitFMUL_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpBinaryOp(i, pc, i.rm, .mul);
        }

        inline fn emitFDIV_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpBinaryOp(i, pc, i.rm, .div);
        }

        inline fn emitFMIN_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpBinaryOp(i, pc, 0, .min);
        }

        inline fn emitFMAX_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpBinaryOp(i, pc, 0, .max);
        }

        inline fn emitFpUnaryOp(this: *Self, i: anytype, pc: u32, comptime op: EngineConfig.Callbacks.UnaryOpS) void {
            this.emitCheckFpAccess(pc);

            _ = this.emitCallPrepare(5);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movImm32(arg1, @intFromEnum(op));
            this.emit.movImm32(arg2, i.rd);
            this.emit.movImm32(arg3, i.rs1);

            if (comptime is_windows) {
                this.emitStackArgImm(0, i.rm);
            } else {
                this.emit.movImm32(arg4, i.rm);
            }

            this.emitCallFinish(@intFromPtr(config.callbacks.unary_s), 5);

            this.emit.testReg32(.rax, .rax);
            const ok_branch = this.emit.jccPlaceholder(.e);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);
            this.emit.patchJump(ok_branch, this.emit.offset);
        }

        inline fn emitFSQRT_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpUnaryOp(i, pc, .sqrt);
        }

        inline fn emitFCVT_W_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpUnaryOp(i, pc, .fcvt_w_s);
        }

        inline fn emitFCVT_WU_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpUnaryOp(i, pc, .fcvt_wu_s);
        }

        inline fn emitFCVT_S_W(this: *Self, i: anytype, pc: u32) void {
            this.emitFpUnaryOp(i, pc, .fcvt_s_w);
        }

        inline fn emitFCVT_S_WU(this: *Self, i: anytype, pc: u32) void {
            this.emitFpUnaryOp(i, pc, .fcvt_s_wu);
        }

        inline fn emitFpFmaOp(this: *Self, i: anytype, pc: u32, comptime op: EngineConfig.Callbacks.FmaOpS) void {
            this.emitCheckFpAccess(pc);

            _ = this.emitCallPrepare(7);

            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movImm32(arg1, @intFromEnum(op));
            this.emit.movImm32(arg2, i.rd);
            this.emit.movImm32(arg3, i.rs1);

            if (comptime is_windows) {
                this.emitStackArgImm(0, i.rs2);
                this.emitStackArgImm(1, i.rs3);
                this.emitStackArgImm(2, i.rm);
            } else {
                this.emit.movImm32(arg4, i.rs2);
                this.emit.movImm32(arg5, i.rs3);
                this.emitStackArgImm(0, i.rm);
            }

            this.emitCallFinish(@intFromPtr(config.callbacks.fma_s), 7);

            this.emit.testReg32(.rax, .rax);

            const ok_branch = this.emit.jccPlaceholder(.e);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);
            this.emit.patchJump(ok_branch, this.emit.offset);
        }

        inline fn emitFMADD_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpFmaOp(i, pc, .fmadd);
        }

        inline fn emitFMSUB_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpFmaOp(i, pc, .fmsub);
        }

        inline fn emitFNMADD_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpFmaOp(i, pc, .fnmadd);
        }

        inline fn emitFNMSUB_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpFmaOp(i, pc, .fnmsub);
        }

        inline fn emitFpCmpOp(this: *Self, i: anytype, pc: u32, comptime op: EngineConfig.Callbacks.CmpOpS) void {
            this.emitCheckFpAccess(pc);

            _ = this.emitCallPrepare(5);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emit.movImm32(arg1, @intFromEnum(op));
            this.emit.movImm32(arg2, i.rd);
            this.emit.movImm32(arg3, i.rs1);

            if (comptime is_windows) {
                this.emitStackArgImm(0, i.rs2);
            } else {
                this.emit.movImm32(arg4, i.rs2);
            }

            this.emitCallFinish(@intFromPtr(config.callbacks.cmp_s), 5);

            this.emit.testReg32(.rax, .rax);
            const ok_branch = this.emit.jccPlaceholder(.e);

            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);
            this.emit.patchJump(ok_branch, this.emit.offset);
        }

        inline fn emitFEQ_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpCmpOp(i, pc, .eq);
        }

        inline fn emitFLT_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpCmpOp(i, pc, .lt);
        }

        inline fn emitFLE_S(this: *Self, i: anytype, pc: u32) void {
            this.emitFpCmpOp(i, pc, .le);
        }

        inline fn loadFpRegRaw(this: *Self, host_reg: Emitter.Register, fp_reg: u8) void {
            const offset: i32 = @as(i32, fp_reg) * 8;

            this.emit.movMemToReg64(host_reg, float_base, offset);
        }

        inline fn storeFpRegRaw(this: *Self, fp_reg: u8, host_reg: Emitter.Register) void {
            const offset: i32 = @as(i32, fp_reg) * 8;

            this.emit.movRegToMem64(float_base, offset, host_reg);
        }

        inline fn storeFpReg32Boxed(this: *Self, fp_reg: u8, host_reg: Emitter.Register) void {
            this.emit.movImm64(scratch4, 0xFFFFFFFF00000000);
            this.emit.movReg32(scratch5, host_reg);
            this.emit.orReg64(scratch4, scratch5);
            this.storeFpRegRaw(fp_reg, scratch4);
        }

        inline fn emitCheckFpAccess(this: *Self, pc: u32) void {
            this.emitLoadField32(scratch1, offsets.mstatus);
            this.emit.movReg32(scratch2, scratch1);
            this.emit.shrImm32(scratch2, 13);
            this.emit.andImm32(scratch2, 0x3);
            this.emit.testReg32(scratch2, scratch2);

            const ok_branch = this.emit.jccPlaceholder(.ne);

            this.emit.movImm32(scratch1, @intFromEnum(arch.Registers.Mcause.Exception.illegal_instruction));
            this.emitStoreField32(offsets.trap_cause, scratch1);
            this.emit.movImm32(scratch1, 0);
            this.emitStoreField32(offsets.trap_tval, scratch1);
            this.emitUpdateCounters();
            this.emitEpilogue(pc, .trap);

            this.emit.patchJump(ok_branch, this.emit.offset);
        }

        inline fn emitMarkFpDirty(this: *Self) void {
            this.emitLoadField32(scratch1, offsets.mstatus);
            this.emit.orImm32(scratch1, 0x6000);
            this.emit.movImm32(scratch2, @bitCast(@as(i32, -0x80000000)));
            this.emit.orReg32(scratch1, scratch2);
            this.emitStoreField32(offsets.mstatus, scratch1);
        }

        inline fn emitMRET(this: *Self, pc: u32) void {
            _ = this.emitCallPrepare(1);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emitCallFinish(@intFromPtr(config.callbacks.mret), 1);

            this.emit.cmpImm32(.rax, @bitCast(@as(i32, -1)));
            const trap_branch = this.emit.jccPlaceholder(.e);

            this.emit.movRegToMem32(cpu_ptr, @intCast(offsets.pc), .rax);
            this.emitEpilogueNoPc(.ok);

            this.emit.patchJump(trap_branch, this.emit.offset);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitWFI(this: *Self, pc: u32) void {
            _ = this.emitCallPrepare(1);
            this.emit.movReg64(arg0, cpu_ptr);
            this.emitCallFinish(@intFromPtr(config.callbacks.wfi), 1);

            this.emit.movReg32(scratch6, .rax);
            this.emit.cmpImm32(scratch6, @intFromEnum(EngineConfig.State.trap));
            const is_trap = this.emit.jccPlaceholder(.e);

            this.emit.movImm32(scratch1, pc + 4);
            this.emit.movRegToMem32(cpu_ptr, @intCast(offsets.pc), scratch1);
            this.emit.movReg32(.rax, scratch6);
            this.emit.addImm64(.rsp, 8);

            if (comptime is_windows) {
                this.emit.pop64(.rsi);
                this.emit.pop64(.rdi);
            }

            this.emit.pop64(.rbp);
            this.emit.pop64(.r15);
            this.emit.pop64(.r14);
            this.emit.pop64(.r13);
            this.emit.pop64(.r12);
            this.emit.pop64(.rbx);
            this.emit.ret();

            this.emit.patchJump(is_trap, this.emit.offset);
            this.emitEpilogue(pc, .trap);
        }

        inline fn emitCallPrepare(this: *Self, comptime total_args: u32) u32 {
            const stack_args = if (total_args > max_reg_args) total_args - max_reg_args else 0;
            const extra: i32 = shadow_space + @as(i32, stack_args * 8);
            const aligned: i32 = if (extra > 0) (extra + 15) & ~@as(i32, 15) else 0;

            if (aligned > 0) {
                this.emit.subImm64(.rsp, aligned);
            }

            return stack_args;
        }

        inline fn emitStackArg(this: *Self, index: u32, reg: Emitter.Register) void {
            const offset: i32 = shadow_space + @as(i32, @intCast(index * 8));

            this.emit.movRegToMem64(.rsp, offset, reg);
        }

        inline fn emitStackArgImm(this: *Self, index: u32, value: u32) void {
            this.emit.movImm32(scratch7, value);
            this.emitStackArg(index, scratch7);
        }

        inline fn emitCallFinish(this: *Self, func_addr: u64, comptime total_args: u32) void {
            this.emit.movImm64(call_scratch, func_addr);
            this.emit.call(call_scratch);

            const stack_args = if (total_args > max_reg_args) total_args - max_reg_args else 0;
            const extra: i32 = shadow_space + @as(i32, stack_args * 8);
            const aligned: i32 = if (extra > 0) (extra + 15) & ~@as(i32, 15) else 0;

            if (aligned > 0) {
                this.emit.addImm64(.rsp, aligned);
            }
        }
    };
}
