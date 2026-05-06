/* Freestanding math shim. Implementations route to Zig's @sin/@cos/
 * etc. via libc_shim.zig. */
#ifndef _DESKTOPOS_DOOM_MATH_H
#define _DESKTOPOS_DOOM_MATH_H

#define M_PI    3.14159265358979323846
#define M_PI_2  1.57079632679489661923
#define HUGE_VAL 1e9999

double sqrt(double);
double floor(double);
double ceil(double);
double round(double);
double trunc(double);
double log(double);
double log10(double);
double log2(double);
double pow(double, double);
double exp(double);
double sin(double);
double cos(double);
double tan(double);
double asin(double);
double acos(double);
double atan(double);
double atan2(double, double);
double fabs(double);
double fmod(double, double);
double sinh(double);
double cosh(double);
double tanh(double);
double ldexp(double, int);
double frexp(double, int *);

float sqrtf(float);
float floorf(float);
float ceilf(float);
float fabsf(float);
float sinf(float);
float cosf(float);

int    isnan(double);
int    isinf(double);
int    isfinite(double);

#endif
