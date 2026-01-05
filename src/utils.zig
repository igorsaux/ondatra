// Copyright (C) 2026 Igor Spichkin
// SPDX-License-Identifier: Apache-2.0

const std = @import("std");

pub fn dump(v: anytype) void {
    var buffer: [1024]u8 = undefined;
    var writer = std.fs.File.stderr().writer(&buffer);

    std.zon.stringify.serialize(v, .{}, &writer.interface) catch {};

    writer.interface.writeByte('\n') catch {};
    writer.interface.flush() catch {};
}
