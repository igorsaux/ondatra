// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

pub const Identity = struct {
    pub const Class = enum(u8) {
        class32 = 0x01,
        class64 = 0x02,
    };

    pub const Data = enum(u8) {
        lsb = 0x01,
        msb = 0x02,
    };

    pub const Version = enum(u8) {
        current = 0x01,
    };

    pub const OsAbi = enum(u8) {
        sysv = 0x00,
        hpux = 0x01,
        netbsd = 0x02,
        linux = 0x03,
        gnuhurd = 0x04,
        solaris = 0x06,
        aix = 0x07,
        irix = 0x08,
        freebsd = 0x09,
        tru64 = 0x0A,
        novell_modesto = 0x0B,
        openbsd = 0x0C,
        openvms = 0x0D,
        non_stop_kernel = 0x0E,
        aros = 0x0F,
        fenixos = 0x10,
        cloudabi = 0x11,
        openvos = 0x12,
        arm_eabi = 0x40,
        standalone = 0xFF,
    };

    pub const AbiVersion = u8;

    class: Class,
    data: Data,
    version: Version,
    os_abi: OsAbi,
    abi_version: AbiVersion,

    fn parse(reader: *std.Io.Reader) ParseError!Identity {
        const magic = try reader.takeArray(MAGIC.len);

        if (!std.mem.eql(u8, &magic.*, &MAGIC)) {
            return ParseError.InvalidMagic;
        }

        const class = reader.takeEnum(Identity.Class, .little) catch |err| return enumError2Parse(err, ParseError.InvalidClass);
        const data = reader.takeEnum(Identity.Data, .little) catch |err| return enumError2Parse(err, ParseError.InvalidData);
        const version = reader.takeEnum(Identity.Version, .little) catch |err| return enumError2Parse(err, ParseError.InvalidVersion);
        const os_abi = reader.takeEnum(Identity.OsAbi, .little) catch |err| return enumError2Parse(err, ParseError.InvalidOsAbi);
        const abi_version = try reader.takeInt(Identity.AbiVersion, .little);

        try reader.discardAll(7);

        return .{
            .class = class,
            .data = data,
            .version = version,
            .os_abi = os_abi,
            .abi_version = abi_version,
        };
    }
};

pub const Header = struct {
    pub const Type = enum(u16) {
        rel = 0x0001,
        exec = 0x0002,
        dyn = 0x0003,
        core = 0x0004,
    };

    pub const Machine = enum(u16) {
        m32 = 0x0001,
        sparc = 0x0002,
        m386 = 0x0003,
        m68k = 0x0004,
        m88k = 0x0005,
        iamcu = 0x0006,
        m860 = 0x0007,
        mips = 0x0008,
        s370 = 0x0009,
        mips_rs4_be = 0x000a,
        parisc = 0x000f,
        vpp500 = 0x0011,
        sparc32plus = 0x0012,
        m960 = 0x0013,
        ppc = 0x0014,
        ppc64 = 0x0015,
        s390 = 0x0016,
        spu = 0x0017,
        v800 = 0x0024,
        fr20 = 0x0025,
        rh32 = 0x0026,
        rce = 0x0027,
        arm = 0x0028,
        alpha = 0x0029,
        sh = 0x002a,
        sparcv9 = 0x002b,
        tricore = 0x002c,
        arc = 0x002d,
        h8_300 = 0x002e,
        h8_300h = 0x002f,
        h8s = 0x0030,
        h8_500 = 0x0031,
        ia_64 = 0x0032,
        mips_x = 0x0033,
        coldfire = 0x0034,
        m68hc12 = 0x0035,
        mma = 0x0036,
        pcp = 0x0037,
        ncpu = 0x0038,
        ndr1 = 0x0039,
        starcore = 0x003a,
        me16 = 0x003b,
        st100 = 0x003c,
        tinyj = 0x003d,
        x86_64 = 0x003e,
        pdsp = 0x003f,
        pdp10 = 0x0040,
        pdp11 = 0x0041,
        fx66 = 0x0042,
        st9plus = 0x0043,
        st7 = 0x0044,
        m68hc16 = 0x0045,
        m68hc11 = 0x0046,
        m68hc08 = 0x0047,
        m68hc05 = 0x0048,
        svx = 0x0049,
        st19 = 0x004a,
        vax = 0x004b,
        cris = 0x004c,
        javelin = 0x004d,
        firepath = 0x004e,
        zsp = 0x004f,
        mmix = 0x0050,
        huany = 0x0051,
        prism = 0x0052,
        avr = 0x0053,
        fr30 = 0x0054,
        d10v = 0x0055,
        d30v = 0x0056,
        v850 = 0x0057,
        m32r = 0x0058,
        mn10300 = 0x0059,
        mn10200 = 0x005a,
        pj = 0x005b,
        openrisc = 0x005c,
        arc_compact = 0x005d,
        xtensa = 0x005e,
        videocore = 0x005f,
        tmm_gpp = 0x0060,
        ns32k = 0x0061,
        tpc = 0x0062,
        snp1k = 0x0063,
        st200 = 0x0064,
        ip2k = 0x0065,
        max = 0x0066,
        cr = 0x0067,
        f2mc16 = 0x0068,
        msp430 = 0x0069,
        blackfin = 0x006a,
        se_c33 = 0x006b,
        sep = 0x006c,
        arca = 0x006d,
        unicore = 0x006e,
        excess = 0x006f,
        dxp = 0x0070,
        altera_nios2 = 0x0071,
        crx = 0x0072,
        xgate = 0x0073,
        c166 = 0x0074,
        m16c = 0x0075,
        dspic30f = 0x0076,
        ce = 0x0077,
        m32c = 0x0078,
        tsk3000 = 0x0083,
        rs08 = 0x0084,
        sharc = 0x0085,
        ecog2 = 0x0086,
        score7 = 0x0087,
        dsp24 = 0x0088,
        videocore3 = 0x0089,
        latticemico32 = 0x008a,
        se_c17 = 0x008b,
        ti_c6000 = 0x008c,
        ti_c2000 = 0x008d,
        ti_c5500 = 0x008e,
        ti_arp32 = 0x008f,
        ti_pru = 0x0090,
        mmdsp_plus = 0x00a0,
        cypress_m8c = 0x00a1,
        r32c = 0x00a2,
        trimedia = 0x00a3,
        qdsp6 = 0x00a4,
        m8051 = 0x00a5,
        stxp7x = 0x00a6,
        nds32 = 0x00a7,
        ecog1 = 0x00a8,
        maxq30 = 0x00a9,
        ximo16 = 0x00aa,
        manik = 0x00ab,
        craynv2 = 0x00ac,
        rx = 0x00ad,
        metag = 0x00ae,
        mcst_elbrus = 0x00af,
        ecog16 = 0x00b0,
        cr16 = 0x00b1,
        etpu = 0x00b2,
        sle9x = 0x00b3,
        l10m = 0x00b4,
        k10m = 0x00b5,
        aarch64 = 0x00b7,
        avr32 = 0x00b9,
        stm8 = 0x00ba,
        tile64 = 0x00bb,
        tilepro = 0x00bc,
        microblaze = 0x00bd,
        cuda = 0x00be,
        tilegx = 0x00bf,
        cloudshield = 0x00c0,
        corea_1st = 0x00c1,
        corea_2nd = 0x00c2,
        arc_compact2 = 0x00c3,
        open8 = 0x00c4,
        rl78 = 0x00c5,
        videocore5 = 0x00c6,
        m78kor = 0x00c7,
        m56800ex = 0x00c8,
        ba1 = 0x00c9,
        ba2 = 0x00ca,
        xcore = 0x00cb,
        mchp_pic = 0x00cc,
        intel205 = 0x00cd,
        intel206 = 0x00ce,
        intel207 = 0x00cf,
        intel208 = 0x00d0,
        intel209 = 0x00d1,
        km32 = 0x00d2,
        kmx32 = 0x00d3,
        kmx16 = 0x00d4,
        kmx8 = 0x00d5,
        kvarc = 0x00d6,
        cdp = 0x00d7,
        coge = 0x00d8,
        cool = 0x00d9,
        norc = 0x00da,
        csr_kalimba = 0x00db,
        z80 = 0x00dc,
        visium = 0x00dd,
        ft32 = 0x00de,
        moxie = 0x00df,
        amdgpu = 0x00e0,
        riscv = 0x00f3,
    };

    ident: Identity,
    ty: Type,
    machine: Machine,
    version: u32,
    entry: u32,
    phoff: u32,
    shoff: u32,
    flags: u32,
    ehsize: u16,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
    shstrndx: u16,

    fn parse(reader: *std.Io.Reader) ParseError!Header {
        const ident: Identity = try Identity.parse(reader);
        const ty = reader.takeEnum(Header.Type, .little) catch |err| return enumError2Parse(err, ParseError.InvalidType);
        const machine = reader.takeEnum(Header.Machine, .little) catch |err| return enumError2Parse(err, ParseError.InvalidMachine);
        const version = try reader.takeInt(u32, .little);
        const entry = try reader.takeInt(u32, .little);
        const phoff = try reader.takeInt(u32, .little);
        const shoff = try reader.takeInt(u32, .little);
        const flags = try reader.takeInt(u32, .little);
        const ehsize = try reader.takeInt(u16, .little);
        const phentsize = try reader.takeInt(u16, .little);
        const phnum = try reader.takeInt(u16, .little);
        const shentsize = try reader.takeInt(u16, .little);
        const shnum = try reader.takeInt(u16, .little);
        const shstrndx = try reader.takeInt(u16, .little);

        return .{
            .ident = ident,
            .ty = ty,
            .machine = machine,
            .version = version,
            .entry = entry,
            .phoff = phoff,
            .shoff = shoff,
            .flags = flags,
            .ehsize = ehsize,
            .phentsize = phentsize,
            .phnum = phnum,
            .shentsize = shentsize,
            .shnum = shnum,
            .shstrndx = shstrndx,
        };
    }
};

pub const ProgramHeader = struct {
    pub const Type = enum(u32) {
        null = 0x00,
        load = 0x01,
        dynamic = 0x02,
        interp = 0x03,
        note = 0x04,
        shlib = 0x05,
        phdr = 0x06,
        tls = 0x07,
        loos = 0x60000000,
        hios = 0x6fffffff,
        gnu_eh_frame = 0x60000000 + 0x474e550,
        gnu_stack = 0x60000000 + 0x474e551,
        gnu_relro = 0x60000000 + 0x474e552,
        gnu_property = 0x60000000 + 0x474e553,
        sunwbss = 0x6ffffffa,
        sunwstack = 0x6ffffffb,
        arm_archext = 0x70000000,
        arm_unwind = 0x70000001,
        riscv_attributes = 0x70000003,
    };

    ty: Type,
    offset: u32,
    vaddr: u32,
    paddr: u32,
    filesz: u32,
    memsz: u32,
    flags: u32,
    palign: u32,

    fn parse(reader: *std.Io.Reader) ParseError!ProgramHeader {
        const ty = reader.takeEnum(ProgramHeader.Type, .little) catch |err| return enumError2Parse(err, ParseError.InvalidProgramHeaderType);
        const offset = try reader.takeInt(u32, .little);
        const vaddr = try reader.takeInt(u32, .little);
        const paddr = try reader.takeInt(u32, .little);
        const filesz = try reader.takeInt(u32, .little);
        const memsz = try reader.takeInt(u32, .little);
        const flags = try reader.takeInt(u32, .little);
        const palign = try reader.takeInt(u32, .little);

        return .{
            .ty = ty,
            .offset = offset,
            .vaddr = vaddr,
            .paddr = paddr,
            .filesz = filesz,
            .memsz = memsz,
            .flags = flags,
            .palign = palign,
        };
    }
};

pub const File = struct {
    header: Header,
    program_headers: std.ArrayList(ProgramHeader),

    pub fn parse(allocator: std.mem.Allocator, reader: *std.Io.Reader) ParseError!File {
        const header: Header = try Header.parse(reader);
        var program_headers: std.ArrayList(ProgramHeader) = .empty;

        try program_headers.ensureTotalCapacityPrecise(allocator, header.phnum);
        program_headers.expandToCapacity();

        errdefer program_headers.deinit(allocator);

        for (0..header.phnum) |i| {
            program_headers.items[i] = try ProgramHeader.parse(reader);
        }

        return .{
            .header = header,
            .program_headers = program_headers,
        };
    }

    pub fn deinit(this: *File, allocator: std.mem.Allocator) void {
        this.program_headers.deinit(allocator);
    }
};

const MAGIC: [4]u8 = [_]u8{ '\x7F', 'E', 'L', 'F' };

pub const ParseError = error{
    ReadFailed,
    EndOfStream,
    InvalidMagic,
    InvalidClass,
    InvalidData,
    InvalidVersion,
    InvalidOsAbi,
    InvalidType,
    InvalidMachine,
    InvalidProgramHeaderType,
    OutOfMemory,
};

fn enumError2Parse(err: std.Io.Reader.TakeEnumError, by: ParseError) ParseError {
    return switch (err) {
        std.Io.Reader.TakeEnumError.InvalidEnumTag => return by,
        std.Io.Reader.TakeEnumError.EndOfStream => return ParseError.EndOfStream,
        std.Io.Reader.TakeEnumError.ReadFailed => return ParseError.ReadFailed,
    };
}
