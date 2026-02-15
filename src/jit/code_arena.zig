const std = @import("std");
const builtin = @import("builtin");

pub const CodeArena = struct {
    memory: [*]align(page_size) u8,
    capacity: usize,
    write_offset: usize,
    pending_offset: usize,
    state: State,
    use_map_jit: bool,

    const page_size = std.heap.pageSize();
    const State = enum { writable, executable };

    pub const BlockFn = *const fn (*anyopaque) callconv(.c) u32;

    const is_windows = builtin.os.tag == .windows;
    const is_macos = builtin.os.tag == .macos;
    const is_aarch64 = builtin.cpu.arch == .aarch64;

    const HANDLE = *anyopaque;
    const LPVOID = ?*anyopaque;
    const DWORD = u32;
    const SIZE_T = usize;
    const BOOL = c_int;

    // Memory allocation types
    const MEM_COMMIT: DWORD = 0x00001000;
    const MEM_RESERVE: DWORD = 0x00002000;
    const MEM_RELEASE: DWORD = 0x00008000;

    // Memory protection constants
    const PAGE_READWRITE: DWORD = 0x04;
    const PAGE_EXECUTE_READ: DWORD = 0x20;

    extern "kernel32" fn VirtualAlloc(
        lpAddress: LPVOID,
        dwSize: SIZE_T,
        flAllocationType: DWORD,
        flProtect: DWORD,
    ) callconv(.winapi) LPVOID;

    extern "kernel32" fn VirtualFree(
        lpAddress: LPVOID,
        dwSize: SIZE_T,
        dwFreeType: DWORD,
    ) callconv(.winapi) BOOL;

    extern "kernel32" fn VirtualProtect(
        lpAddress: LPVOID,
        dwSize: SIZE_T,
        flNewProtect: DWORD,
        lpflOldProtect: *DWORD,
    ) callconv(.winapi) BOOL;

    extern "kernel32" fn FlushInstructionCache(
        hProcess: HANDLE,
        lpBaseAddress: ?*const anyopaque,
        dwSize: SIZE_T,
    ) callconv(.winapi) BOOL;

    extern "kernel32" fn GetCurrentProcess() callconv(.winapi) HANDLE;

    extern "c" fn mmap(
        addr: ?*anyopaque,
        len: usize,
        prot: c_int,
        flags: c_int,
        fd: c_int,
        offset: isize,
    ) *anyopaque;
    extern "c" fn munmap(addr: *anyopaque, len: usize) c_int;
    extern "c" fn mprotect(addr: *anyopaque, len: usize, prot: c_int) c_int;

    // macOS specific
    extern "c" fn pthread_jit_write_protect_np(enabled: c_int) void;
    extern "c" fn sys_icache_invalidate(start: *anyopaque, len: usize) void;

    // Linux ARM64 (from compiler-rt/libgcc)
    extern "c" fn __clear_cache(start: [*]u8, end: [*]u8) void;

    const PROT_READ: c_int = 0x01;
    const PROT_WRITE: c_int = 0x02;
    const PROT_EXEC: c_int = 0x04;
    const MAP_PRIVATE: c_int = 0x0002;
    const MAP_ANON: c_int = if (is_macos) 0x1000 else 0x0020;
    const MAP_JIT: c_int = 0x0800;
    const MAP_FAILED: *anyopaque = @ptrFromInt(~@as(usize, 0));

    pub inline fn init(size: usize) !CodeArena {
        const aligned_size = std.mem.alignForward(usize, size, page_size);

        if (comptime is_windows) {
            return initWindows(aligned_size);
        } else {
            return initPosix(aligned_size);
        }
    }

    pub inline fn deinit(this: *CodeArena) void {
        if (comptime is_windows) {
            _ = VirtualFree(@ptrCast(this.memory), 0, MEM_RELEASE);
        } else {
            _ = munmap(@ptrCast(this.memory), this.capacity);
        }
        this.* = undefined;
    }

    pub inline fn beginBlock(this: *CodeArena, max_size: usize) ?[]u8 {
        this.makeWritable();

        const aligned_offset = std.mem.alignForward(usize, this.write_offset, 4);

        if (aligned_offset + max_size > this.capacity) {
            return null;
        }

        this.pending_offset = aligned_offset;

        return this.memory[aligned_offset..this.capacity];
    }

    pub inline fn commitBlock(this: *CodeArena, actual_size: usize) BlockFn {
        const block_start = this.pending_offset;
        this.write_offset = block_start + actual_size;

        this.makeExecutable();
        this.invalidateIcache(block_start, actual_size);

        // std.debug.print("\n", .{});
        // std.debug.dumpHex((this.memory + block_start)[0..actual_size]);

        return @ptrCast(@alignCast(this.memory + block_start));
    }

    pub inline fn abortBlock(this: *CodeArena) void {
        this.pending_offset = this.write_offset;
    }

    pub inline fn reset(this: *CodeArena) void {
        this.makeWritable();
        this.write_offset = 0;
        this.pending_offset = 0;
    }

    pub inline fn usedBytes(this: *const CodeArena) usize {
        return this.write_offset;
    }

    pub inline fn freeBytes(this: *const CodeArena) usize {
        return this.capacity - this.write_offset;
    }

    pub inline fn totalBytes(this: *const CodeArena) usize {
        return this.capacity;
    }

    inline fn initWindows(aligned_size: usize) !CodeArena {
        const ptr = VirtualAlloc(
            null,
            aligned_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if (ptr == null) {
            return error.VirtualAllocFailed;
        }

        return .{
            .memory = @ptrCast(@alignCast(ptr.?)),
            .capacity = aligned_size,
            .write_offset = 0,
            .pending_offset = 0,
            .state = .writable,
            .use_map_jit = false,
        };
    }

    inline fn initPosix(aligned_size: usize) !CodeArena {
        if (comptime is_macos and is_aarch64) {
            const ptr = mmap(
                null,
                aligned_size,
                PROT_READ | PROT_WRITE | PROT_EXEC,
                MAP_PRIVATE | MAP_ANON | MAP_JIT,
                -1,
                0,
            );

            if (ptr != MAP_FAILED) {
                pthread_jit_write_protect_np(0);

                return .{
                    .memory = @ptrCast(@alignCast(ptr)),
                    .capacity = aligned_size,
                    .write_offset = 0,
                    .pending_offset = 0,
                    .state = .writable,
                    .use_map_jit = true,
                };
            }
        }

        const ptr = mmap(
            null,
            aligned_size,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANON,
            -1,
            0,
        );

        if (ptr == MAP_FAILED) {
            return error.MmapFailed;
        }

        return .{
            .memory = @ptrCast(@alignCast(ptr)),
            .capacity = aligned_size,
            .write_offset = 0,
            .pending_offset = 0,
            .state = .writable,
            .use_map_jit = false,
        };
    }

    inline fn makeWritable(this: *CodeArena) void {
        if (this.state == .writable) {
            return;
        }

        if (comptime is_windows) {
            var old_protect: DWORD = undefined;

            _ = VirtualProtect(
                @ptrCast(this.memory),
                this.capacity,
                PAGE_READWRITE,
                &old_protect,
            );
        } else if (this.use_map_jit) {
            if (comptime is_macos) {
                pthread_jit_write_protect_np(0);
            }
        } else {
            _ = mprotect(@ptrCast(this.memory), this.capacity, PROT_READ | PROT_WRITE);
        }

        this.state = .writable;
    }

    inline fn makeExecutable(this: *CodeArena) void {
        if (this.state == .executable) {
            return;
        }

        if (comptime is_windows) {
            var old_protect: DWORD = undefined;

            _ = VirtualProtect(
                @ptrCast(this.memory),
                this.capacity,
                PAGE_EXECUTE_READ,
                &old_protect,
            );
        } else if (this.use_map_jit) {
            if (comptime is_macos) {
                pthread_jit_write_protect_np(1);
            }
        } else {
            _ = mprotect(@ptrCast(this.memory), this.capacity, PROT_READ | PROT_EXEC);
        }

        this.state = .executable;
    }

    inline fn invalidateIcache(this: *CodeArena, offset: usize, len: usize) void {
        const start = this.memory + offset;

        if (comptime is_windows) {
            if (comptime is_aarch64) {
                _ = FlushInstructionCache(
                    GetCurrentProcess(),
                    @ptrCast(start),
                    len,
                );
            }

            return;
        }

        if (comptime !is_aarch64) {
            return;
        }

        if (comptime is_macos) {
            sys_icache_invalidate(@ptrCast(start), len);
        } else {
            __clear_cache(start, start + len);
        }
    }
};
