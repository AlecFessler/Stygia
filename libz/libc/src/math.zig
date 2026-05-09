// math — libm shim. Forwards to std.math + Zig builtins.
//
// LLVM lowers many of these to inline x87/SSE instructions or
// polynomial expansions; what's left links against compiler-rt (auto-
// pulled in by Zig). Long-double (80-bit / x87) variants alias their
// double counterparts since LLVM's host libstdc++ build typically
// uses `long double = double` on freestanding targets.

const std = @import("std");

// ── Pure Zig builtins ─────────────────────────────────────────────

export fn sin(x: f64) callconv(.c) f64 {
    return @sin(x);
}
export fn sinf(x: f32) callconv(.c) f32 {
    return @sin(x);
}
export fn cos(x: f64) callconv(.c) f64 {
    return @cos(x);
}
export fn cosf(x: f32) callconv(.c) f32 {
    return @cos(x);
}
export fn tan(x: f64) callconv(.c) f64 {
    return @tan(x);
}
export fn tanf(x: f32) callconv(.c) f32 {
    return @tan(x);
}
export fn sqrt(x: f64) callconv(.c) f64 {
    return @sqrt(x);
}
export fn sqrtf(x: f32) callconv(.c) f32 {
    return @sqrt(x);
}
export fn exp(x: f64) callconv(.c) f64 {
    return @exp(x);
}
export fn expf(x: f32) callconv(.c) f32 {
    return @exp(x);
}
export fn exp2(x: f64) callconv(.c) f64 {
    return @exp2(x);
}
export fn exp2f(x: f32) callconv(.c) f32 {
    return @exp2(x);
}
export fn log(x: f64) callconv(.c) f64 {
    return @log(x);
}
export fn logf(x: f32) callconv(.c) f32 {
    return @log(x);
}
export fn log2(x: f64) callconv(.c) f64 {
    return @log2(x);
}
export fn log2f(x: f32) callconv(.c) f32 {
    return @log2(x);
}
export fn log10(x: f64) callconv(.c) f64 {
    return @log10(x);
}
export fn log10f(x: f32) callconv(.c) f32 {
    return @log10(x);
}
export fn floor(x: f64) callconv(.c) f64 {
    return @floor(x);
}
export fn floorf(x: f32) callconv(.c) f32 {
    return @floor(x);
}
export fn ceil(x: f64) callconv(.c) f64 {
    return @ceil(x);
}
export fn ceilf(x: f32) callconv(.c) f32 {
    return @ceil(x);
}
export fn round(x: f64) callconv(.c) f64 {
    return @round(x);
}
export fn roundf(x: f32) callconv(.c) f32 {
    return @round(x);
}
export fn trunc(x: f64) callconv(.c) f64 {
    return @trunc(x);
}
export fn truncf(x: f32) callconv(.c) f32 {
    return @trunc(x);
}
export fn fabs(x: f64) callconv(.c) f64 {
    return @abs(x);
}
export fn fabsf(x: f32) callconv(.c) f32 {
    return @abs(x);
}
export fn copysign(x: f64, y: f64) callconv(.c) f64 {
    return std.math.copysign(x, y);
}
export fn copysignf(x: f32, y: f32) callconv(.c) f32 {
    return std.math.copysign(x, y);
}

// ── std.math forwards ─────────────────────────────────────────────

export fn pow(x: f64, y: f64) callconv(.c) f64 {
    return std.math.pow(f64, x, y);
}
export fn powf(x: f32, y: f32) callconv(.c) f32 {
    return std.math.pow(f32, x, y);
}
export fn fmod(x: f64, y: f64) callconv(.c) f64 {
    return @mod(x, y);
}
export fn fmodf(x: f32, y: f32) callconv(.c) f32 {
    return @mod(x, y);
}
export fn atan(x: f64) callconv(.c) f64 {
    return std.math.atan(x);
}
export fn atanf(x: f32) callconv(.c) f32 {
    return std.math.atan(x);
}
export fn atan2(y: f64, x: f64) callconv(.c) f64 {
    return std.math.atan2(y, x);
}
export fn atan2f(y: f32, x: f32) callconv(.c) f32 {
    return std.math.atan2(y, x);
}
export fn asin(x: f64) callconv(.c) f64 {
    return std.math.asin(x);
}
export fn asinf(x: f32) callconv(.c) f32 {
    return std.math.asin(x);
}
export fn acos(x: f64) callconv(.c) f64 {
    return std.math.acos(x);
}
export fn acosf(x: f32) callconv(.c) f32 {
    return std.math.acos(x);
}
export fn sinh(x: f64) callconv(.c) f64 {
    return std.math.sinh(x);
}
export fn sinhf(x: f32) callconv(.c) f32 {
    return std.math.sinh(x);
}
export fn cosh(x: f64) callconv(.c) f64 {
    return std.math.cosh(x);
}
export fn coshf(x: f32) callconv(.c) f32 {
    return std.math.cosh(x);
}
export fn tanh(x: f64) callconv(.c) f64 {
    return std.math.tanh(x);
}
export fn tanhf(x: f32) callconv(.c) f32 {
    return std.math.tanh(x);
}
export fn cbrt(x: f64) callconv(.c) f64 {
    return std.math.cbrt(x);
}
export fn cbrtf(x: f32) callconv(.c) f32 {
    return std.math.cbrt(x);
}
export fn hypot(x: f64, y: f64) callconv(.c) f64 {
    return std.math.hypot(x, y);
}
export fn hypotf(x: f32, y: f32) callconv(.c) f32 {
    return std.math.hypot(x, y);
}
export fn fma(x: f64, y: f64, z: f64) callconv(.c) f64 {
    return @mulAdd(f64, x, y, z);
}
export fn fmaf(x: f32, y: f32, z: f32) callconv(.c) f32 {
    return @mulAdd(f32, x, y, z);
}
export fn log1p(x: f64) callconv(.c) f64 {
    return std.math.log1p(x);
}
export fn log1pf(x: f32) callconv(.c) f32 {
    return std.math.log1p(x);
}
export fn expm1(x: f64) callconv(.c) f64 {
    return std.math.expm1(x);
}
export fn expm1f(x: f32) callconv(.c) f32 {
    return std.math.expm1(x);
}
export fn logb(x: f64) callconv(.c) f64 {
    return std.math.log10(@abs(x));
}
export fn logbf(x: f32) callconv(.c) f32 {
    return std.math.log10(@abs(x));
}

export fn frexp(x: f64, exp_out: *c_int) callconv(.c) f64 {
    const r = std.math.frexp(x);
    exp_out.* = @intCast(r.exponent);
    return r.significand;
}
export fn frexpf(x: f32, exp_out: *c_int) callconv(.c) f32 {
    const r = std.math.frexp(x);
    exp_out.* = @intCast(r.exponent);
    return r.significand;
}

export fn ldexp(x: f64, n: c_int) callconv(.c) f64 {
    return std.math.ldexp(x, @intCast(n));
}
export fn ldexpf(x: f32, n: c_int) callconv(.c) f32 {
    return std.math.ldexp(x, @intCast(n));
}

export fn modf(x: f64, ipart: *f64) callconv(.c) f64 {
    const i = @trunc(x);
    ipart.* = i;
    return x - i;
}
export fn modff(x: f32, ipart: *f32) callconv(.c) f32 {
    const i = @trunc(x);
    ipart.* = i;
    return x - i;
}

export fn erf(x: f64) callconv(.c) f64 {
    // Abramowitz/Stegun 7.1.26 — five-term polynomial; ~1.5e-7 error.
    const sign: f64 = if (x < 0) -1 else 1;
    const a1: f64 = 0.254829592;
    const a2: f64 = -0.284496736;
    const a3: f64 = 1.421413741;
    const a4: f64 = -1.453152027;
    const a5: f64 = 1.061405429;
    const p: f64 = 0.3275911;
    const ax = @abs(x);
    const t = 1.0 / (1.0 + p * ax);
    const y = 1.0 - (((((a5 * t + a4) * t) + a3) * t + a2) * t + a1) * t * @exp(-ax * ax);
    return sign * y;
}
export fn erff(x: f32) callconv(.c) f32 {
    return @floatCast(erf(@floatCast(x)));
}

// ── Long-double aliases (treat as f64 on Stygia-target since LLVM's
//    host libstdc++ build defaults to `long double = double`) ──────

export fn frexpl(x: f64, exp_out: *c_int) callconv(.c) f64 {
    return frexp(x, exp_out);
}
export fn ldexpl(x: f64, n: c_int) callconv(.c) f64 {
    return ldexp(x, n);
}
export fn fabsl(x: f64) callconv(.c) f64 {
    return @abs(x);
}
export fn copysignl(x: f64, y: f64) callconv(.c) f64 {
    return std.math.copysign(x, y);
}

// ── fenv (rounding mode + exception flags) — stub-ish ─────────────
// Round-to-nearest is the only mode we expose; LLVM mostly uses
// these to *probe* support, then falls back if they error.

export fn fegetround() callconv(.c) c_int {
    return 0; // FE_TONEAREST
}
export fn fesetround(mode: c_int) callconv(.c) c_int {
    return if (mode == 0) 0 else -1;
}
export fn feclearexcept(excepts: c_int) callconv(.c) c_int {
    _ = excepts;
    return 0;
}
export fn fetestexcept(excepts: c_int) callconv(.c) c_int {
    _ = excepts;
    return 0;
}
