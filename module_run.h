#ifndef MODULE_RUN_H
#define MODULE_RUN_H

#include "context.h"

/**
 * A function to load the shared library and run it initialization code
 * \param ctx the context of the test module
 * \param mod_filename the path to the libary
 * \param initstr a space separated string with initiliazation data for the moduel
 */
int load_test_module(oflops_context *ctx, char * mod_filename, char * initstr);

/**
 * A function that run the main loop for tha data and control channel code.
 * \param ctx context of the module
 * \param ix_text the relative sequnce id number of the test
 */
void *run_test_module(oflops_context *ctx, int ix_test); //, test_module * mod);

/**
 * a function to setup the data and snmp channels of the module
 * \param ctx the context of the module
 * \param ix_mod the relative sequnce id number of the test
 */
int setup_test_module(oflops_context *ctx, int ix_mod);

/**
 * a function used to run the traffic generation thread.
 * \param ctx the context of the module
 * \param ix_mod the relative sequnce id number of the test
 */
void *run_traffic_generation(oflops_context *ctx, int ix_mod);

#endif
