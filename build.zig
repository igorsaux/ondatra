const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.addModule("ondatra", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
    });
    mod.addImport("ondatra", mod);

    const bench = b.addExecutable(.{
        .name = "bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/bench.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{
                .{ .name = "ondatra", .module = mod },
            },
        }),
    });

    addBinary(b, bench, b.path("src/bench/fibbonacci.zig"), "fibbonacci.bin");
    addBinary(b, bench, b.path("src/bench/float_minmax_abs.zig"), "float_minmax_abs.bin");
    addBinary(b, bench, b.path("src/bench/float_arithmetic.zig"), "float_arithmetic.bin");
    addBinary(b, bench, b.path("src/bench/float_sqrt_fma.zig"), "float_sqrt_fma.bin");

    b.installArtifact(bench);

    const bench_step = b.step("bench", "Run the benchmarks");

    const bench_cmd = b.addRunArtifact(bench);
    bench_step.dependOn(&bench_cmd.step);

    if (b.args) |args| {
        bench_cmd.addArgs(args);
    }

    const mod_tests = b.addTest(.{
        .root_module = mod,
    });

    const run_mod_tests = b.addRunArtifact(mod_tests);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&run_mod_tests.step);
}

const riscv32Query: std.Target.Query = .{
    .cpu_arch = .riscv32,
    .cpu_model = .{
        .explicit = std.Target.Cpu.Model.generic(.riscv32),
    },
    .cpu_features_add = std.Target.riscv.featureSet(&[_]std.Target.riscv.Feature{
        std.Target.riscv.Feature.@"32bit",
        std.Target.riscv.Feature.i,
        std.Target.riscv.Feature.m,
        std.Target.riscv.Feature.f,
        std.Target.riscv.Feature.d,
        std.Target.riscv.Feature.zicsr,
        std.Target.riscv.Feature.zicntr,
        std.Target.riscv.Feature.zifencei,
        std.Target.riscv.Feature.zba,
        std.Target.riscv.Feature.zbb,
    }),
    .os_tag = .freestanding,
};

fn addBinary(b: *std.Build, step: *std.Build.Step.Compile, path: std.Build.LazyPath, name: []const u8) void {
    const target = b.resolveTargetQuery(riscv32Query);

    const binary = b.addExecutable(.{
        .name = name,
        .root_module = b.createModule(.{
            .root_source_file = path,
            .target = target,
            .optimize = .ReleaseSmall,
        }),
    });
    binary.linker_script = b.path("src/bench/env/ondatra.ld");

    b.installArtifact(binary);

    step.root_module.addAnonymousImport(name, .{
        .root_source_file = binary.getEmittedBin(),
    });
}
