#ifndef USAGE_H
#define USAGE_H

#include <libconfig.h>

#include "oflops.h"

#define SNMP_DELIMITER ":"

int parse_args(oflops_context * ctx, int argc, char * argv[]);
void usage(const char * s1, const char *s2);

#endif
