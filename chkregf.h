#ifndef _CHKREGF_H_
#define _CHKREGF_H_

struct regf_block *get_regf_struct(void);

int parse_sk (uint8_t *data, int size, long int offset);
int parse_vk (uint8_t *data, int size, uint32_t offset);
int parse_ri (uint8_t *_ri_ptr, int size, long int offset);
int parse_li (uint8_t *_li_ptr, int size, long int offset);
int parse_lh (uint8_t *_lh_ptr, int size, long int offset);
int parse_lf (uint8_t *_lf_ptr, int size, long int offset);
int parse_nk (TALLOC_CTX *mem_ctx, uint8_t *data, int size, long int offset);
int read_blocks (TALLOC_CTX *parent_ctx, FILE *fd, int32_t offset);
uint32_t get_hbin_header(FILE *fd, signed long int offset);
struct hbin_data_block *get_hbin_data_block(TALLOC_CTX *mem_ctx, FILE *fd, long int offset, long int parent_off);
int read_regf_header(FILE *fd);
int main (int argc, char **argv);

int parse_tree(TALLOC_CTX *parent_ctx,
               FILE *fd,
               long int offset,
               long int parent_off,
               const char *expect_type,
               long int expect_count);

#endif /* _CHKREGF_H_ */
