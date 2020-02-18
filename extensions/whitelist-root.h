#define TLD_MAXLEN 28
#define TLD_MAXNUM 1544

typedef struct all_whitelist_data_s {
    int     num_tlds;
    short   index[36*56];
    char    names[TLD_MAXNUM][TLD_MAXLEN+1];
} all_whitelist_data;

int find_index_spot(const char *name);
int find_index_offset(const char *name);
int root_tld_is_valid(int len, const char *name, u_int flags);

extern all_whitelist_data whitelist;

