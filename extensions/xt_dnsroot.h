#ifndef _LINUX_NETFILTER_DNSROOT_H
#define _LINUX_NETFILTER_DNSROOT_H

// not used yet
enum {
    DNSROOT_FLAG = 1,
};

struct xt_dnsroot_mtinfo1 {
   __u8 *lookup_table;
   uint8_t tldmatch;
   uint8_t debug;
   uint8_t optimization;
};

#endif /* _LINUX_NETFILTER_DNSROOT_H */
