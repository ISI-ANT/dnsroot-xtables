/*
 *    xt_dnsroot - Xtables module to match IPv4 UDP DNS root TLDs
 *    Copyright © USC/ISI, 2017-2020
 *
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License; either
 *    version 2 of the License, or any later version, as published by the
 *    Free Software Foundation.
 */
#include <linux/ctype.h>
#include <linux/ip.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/netfilter/x_tables.h>
#include <net/ip.h>
#include <linux/proc_fs.h>
#include "xt_dnsroot.h"
#include "compat_xtables.h"

#define MATCH_PACKET_ERROR 0 /* later make it an option to match -> drop? */

#include "whitelist-root.c"

#define LOGNOTICE(x) do { if (info->debug >= 1) printk x ; } while(0)
#define LOGINFO(x) do { if (info->debug >= 2) printk x ; } while(0)
#define LOGDEBUG(x) do { if (info->debug >= 3) printk x ; } while(0)

/* procfs */

#define BUFSIZE  100
 
 
static struct proc_dir_entry *ent;
 
static ssize_t mywrite(struct file *file, const char __user *ubuf,size_t count, loff_t *ppos) 
{
    printk( KERN_DEBUG "write handler\n");
    return -1;
}
 
static ssize_t myread(struct file *file, char __user *ubuf,size_t count, loff_t *ppos) 
{
    printk( KERN_DEBUG "read handler\n");
    return 0;
}
 
static struct file_operations myops = 
{
    .owner = THIS_MODULE,
    .read = myread,
    .write = mywrite,
};

static bool dnsroot_mt(const struct sk_buff *skb,
                           struct xt_action_param *par)
{
    const struct xt_dnsroot_mtinfo1 *info = par->matchinfo;
    const struct iphdr *iph = ip_hdr(skb);
    /** hlen = packet-data length */
    unsigned int rem, hlen = ntohs(iph->tot_len) - ip_hdrlen(skb);

    unsigned char *dnsmsg, *dnspkt, *tldptr = NULL;
    uint32_t count = 0;

    LOGDEBUG(("top of dnsroot\n"));

    /* must not be a fragment */
    if (par->fragoff != 0) {
        printk("dnsroot:  fragment\n");
        par->hotdrop = true;
        return MATCH_PACKET_ERROR;
    }

    /* make sure that skb is linear */
    if (skb_is_nonlinear(skb)) {
        printk("dnsroot:  nonlinear\n");
        par->hotdrop = true;
        return MATCH_PACKET_ERROR;
    }

    switch (iph->protocol) {
            case IPPROTO_TCP:    /* what to do with a TCP packet */
            {
#ifdef USE_TCP_WJH
                const struct tcphdr *tcph = (const void *)iph + ip_hdrlen(skb);
                /* XXX: pull from similar xt_ipp2p .. ipp2p_mt() */
#endif
                /** don't process tcp packets */
                return MATCH_PACKET_ERROR;
            }
            break;

            case IPPROTO_UDP:    /* what to do with an UDP packet */
            case IPPROTO_UDPLITE:
            {
                const struct udphdr *udph = (const void *)iph + ip_hdrlen(skb);
                dnspkt = dnsmsg = skb_network_header(skb) + ip_hdrlen(skb) + sizeof(*udph);
                if (sizeof(*udph) > hlen) {
                    /* header length is less than udp header size */
                    printk("dnsroot: packet header smaller than udp header from %pI4\n", &iph->saddr);
                    print_hex_dump(KERN_WARNING, "dnsroot: ", DUMP_PREFIX_NONE, 16, 2, dnspkt, hlen, 1);
                    par->hotdrop = true;
                    return MATCH_PACKET_ERROR;
                }
            }
            break;

            default:
                printk("unknown protocol sent to dnsroot from %pI4\n", &iph->saddr);
                par->hotdrop = true;
                return MATCH_PACKET_ERROR;
    }

    /** we need at least 14 bytes to continue.
     * 2 tid + 2 flags + 2*4 section counters + 1 (minimum tld '.') + 1 NUL */
    rem = hlen;
    if (rem < 14 ) {
        printk("dnsroot: packet too short from %pI4\n", &iph->saddr);
        print_hex_dump(KERN_WARNING, "dnsroot: ", DUMP_PREFIX_NONE, 16, 2, dnspkt, hlen, 1);
        par->hotdrop = true;
        return MATCH_PACKET_ERROR;
    }

    /* navigate to QNAME */
    dnsmsg += 2 + 2; /* skip transaction id and flags */
    rem -= 4;

    if (*dnsmsg != 0x00 && *(dnsmsg+1) != 0x01) {
        printk("dnsroot: number of questions != 1: %x%x from %pI4\n", *dnsmsg, *(dnsmsg+1), &iph->saddr);
        print_hex_dump(KERN_WARNING, "dnsroot: ", DUMP_PREFIX_NONE, 16, 2, dnspkt, hlen, 1);
        par->hotdrop = true;
        return MATCH_PACKET_ERROR;
    }

    dnsmsg += 8; /* skip past all the 4 section counters */
    rem -= 8;

    /* start of qname */
    /* BYTECOUNT, LABEL, BYTECOUNT, LABEL, ..., 00 */
    /* We need the very last label in the sequence */
    /* Notes: */
    /*    BYTECOUNT is a single byte, but always? */
    /*    <label> ::= <letter> [ [ <ldh-str> ] <let-dig> ] */
    while (rem > 0) {
        LOGDEBUG(("dnsroot: loop at %x, %d bytes left\n", *dnsmsg, rem));
        if ( *dnsmsg == 0x00 ) /* end of labels */
            break;
        count = *dnsmsg + 1; /* label length + 1 for bytecount */
        if ( count > rem ) {
            printk("dnsroot: packet too short (%d < %d) from %pI4\n", rem, count, &iph->saddr);
            print_hex_dump(KERN_WARNING, "dnsroot: ", DUMP_PREFIX_NONE, 16, 2, dnspkt, hlen, 1);
            par->hotdrop = true;
            return MATCH_PACKET_ERROR;
        }
        tldptr = dnsmsg + 1; /* position of the last label */
        dnsmsg += count;
        rem -= count;
    }

    if (tldptr == NULL) {
        LOGINFO(("dnsroot: query for root itself\n"));
        return info->tldmatch;
    }

    /* check for illegal characters in tld */
    dnsmsg = tldptr;
    while (*dnsmsg != 0x00) {
        if ((*dnsmsg & 0x80) ||
            (!islower(*dnsmsg) && (*dnsmsg!='-') &&
             !isdigit(*dnsmsg) && !isupper(*dnsmsg))) {
            if (info->debug >= 1) { /* NOTICE */
               printk("dnsroot: illegal char in tld %x from %pI4\n", *dnsmsg, &iph->saddr);
               print_hex_dump(KERN_WARNING, "dnsroot: ", DUMP_PREFIX_NONE, 16, 2, dnspkt, hlen, 1);
            }
            return  ! info->tldmatch;
        }
        ++dnsmsg;
    }

    LOGINFO(("dnsroot: found tld: %s (len %d, hex %x)\n", tldptr, count, *tldptr));

    if (root_tld_is_valid(count, tldptr, info->optimization)) {
        if (info->tldmatch) {
            LOGNOTICE(("dnsroot: tld %s is VALID\n", tldptr));
        }
        return info->tldmatch;
    }

    if (! info->tldmatch) {
        LOGNOTICE(("dnsroot: tld %s is INVALID\n", tldptr));
    }
    return  ! info->tldmatch;
}

static struct xt_match dnsroot_mt_reg __read_mostly = {
    .name      = "dnsroot",
    .revision  = 1,
    .family    = NFPROTO_IPV4, /* need to do ipv6 too */
    .proto     = IPPROTO_UDP, /* need to do TCP too */
    .match     = dnsroot_mt,
    .matchsize = sizeof(struct xt_dnsroot_mtinfo1),
    .me        = THIS_MODULE,
};

static int __init dnsroot_mt_init(void)
{
    /* XXX: build search tree */
    ent=proc_create("dnsroot",0660,NULL,&myops);
    return xt_register_match(&dnsroot_mt_reg);
}

static void __exit dnsroot_mt_exit(void)
{
    /* XXX: free search tree */
    proc_remove(ent);
    xt_unregister_match(&dnsroot_mt_reg);
}


MODULE_DESCRIPTION("XTables: IPv4/UDP/DNS DNS Root TLD Match");
MODULE_AUTHOR("Wes Hardaker");
MODULE_LICENSE("GPL");
MODULE_ALIAS("ipt_dnsroot");
module_init(dnsroot_mt_init);
module_exit(dnsroot_mt_exit);
