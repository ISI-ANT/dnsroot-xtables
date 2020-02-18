/*
 *    "dnsroot" match extension for IPv4/UDP/DNS DNS Root TLD
 *    Copyright © USC/ISI, 2017-2020
 *
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License; either
 *    version 2 of the License, or any later version, as published by the
 *    Free Software Foundation.
 */
#include <getopt.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <xtables.h>
#include "xt_dnsroot.h"
#include "compat_user.h"

static void dnsroot_mt_help(void)
{
    printf("dnsroot match options:\n"
           "  --tld\n");
}

static const struct option dnsroot_mt_opts[] = {
    {.name = "tld", .has_arg = false, .val = '1'},
    {.name = "optimization", .has_arg = false, .val = '2'},
    {.name = "debug", .has_arg = false, .val = '3'},
    {NULL},
};

static int dnsroot_mt_parse(int c, char **argv, int invert,
    unsigned int *flags, const void *entry, struct xt_entry_match **match)
{
    struct xt_dnsroot_mtinfo1 *info = (void *)(*match)->data;

#define IPT_DNSROOT_TLD       0x01
/*#define IPT_DNSROOT_UNUSED 0x02*/
#define IPT_DNSROOT_INVERT 0x04
#define IPT_DNSROOT_DEBUG  0x08

    if (invert)
        *flags |= IPT_DNSROOT_INVERT;

    switch (c) {
    case '1':
        if (*flags & IPT_DNSROOT_TLD)
            xtables_error(PARAMETER_PROBLEM,"Can't specify --tld twice");
        *flags |= IPT_DNSROOT_TLD;
        info->tldmatch = 1 & !invert;
        return true;

    case '2':
        ++info->optimization;
        return true;

    case '3':
        *flags |= IPT_DNSROOT_DEBUG;
        ++info->debug;
        return true;
    }
    return false;
}

/* no checking of *flags - no IPv4 options is also valid */

static void dnsroot_mt_save(const void *ip,
    const struct xt_entry_match *match)
{
    /*const struct xt_dnsroot_mtinfo1 *info = (void *)match->data;*/
    printf(" ");
}

static void dnsroot_mt_print(const void *ip,
    const struct xt_entry_match *match, int numeric)
{
    printf(" -m dnsroot");
    dnsroot_mt_save(ip, match);
}

static struct xtables_match dnsroot_mt_reg = {
    .version       = XTABLES_VERSION,
    .name          = "dnsroot",
    .revision      = 1,
    .family        = NFPROTO_IPV4,
    .size          = XT_ALIGN(sizeof(struct xt_dnsroot_mtinfo1)),
    .userspacesize = XT_ALIGN(sizeof(struct xt_dnsroot_mtinfo1)),
    .help          = dnsroot_mt_help,
    .parse         = dnsroot_mt_parse,
    .print         = dnsroot_mt_print,
    .save          = dnsroot_mt_save,
    .extra_opts    = dnsroot_mt_opts,
};

static __attribute__((constructor)) void dnsroot_mt_ldr(void)
{
    xtables_register_match(&dnsroot_mt_reg);
}
