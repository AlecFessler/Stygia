/* Minimal math shim. SQLite calls these only for built-in math
 * functions in expressions; we provide stubs. Most queries don't
 * exercise them. */
#ifndef _DESKTOPOS_MATH_H
#define _DESKTOPOS_MATH_H

double sqrt(double);
double floor(double);
double ceil(double);
double log(double);
double log10(double);
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

int    isnan(double);
int    isinf(double);

#endif
