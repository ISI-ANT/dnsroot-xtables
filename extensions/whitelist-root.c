#ifdef NON_KERNEL
#include <stdio.h>
#include <string.h>
#else
#include <linux/string.h>
#endif

#include "whitelist-root.h"
#include "whitelist-init.h"

int find_index_spot(const char *name) {
    int index_spot = (name[0] - 'a') * 26 + (name[1] - 'a');
    return(index_spot);
}

int find_index_offset(const char *name) {
    int index_spot = find_index_spot(name);
    return(whitelist.index[index_spot]);
}

/* returns 1 if in the root name list, or 0 otherwise */
int root_tld_is_valid(int len, const char *name, u_int flags) {
    int start_offset, cmp, i;

    if (flags == 1) {
        /* optimization: check top N for length */
        static const char *topN[3] = { "com", "net", "org" };

        if (len == 3) {
            for(i = 0; i < (sizeof(topN)/sizeof(char *)); ++i) {
                if (strcasecmp(topN[i], name) == 0) {
                    return 1;
                }
            }
        } else if (len ==4) {
            if (strcasecmp("arpa", name) == 0) {
                return 1;
            }
        }
    }

    start_offset = find_index_offset(name);
    for(i = start_offset ; i >= 0 && i <= TLD_MAXNUM; i++) {
        cmp = strcasecmp(whitelist.names[i], name);
        if (cmp == 0) {
            return 1;
        } else if (cmp > 0) {
            /* search name is beyond a list name; we're done */
            return 0;
        }
    }
    return 0; /* we fell off the end of the list */
}

