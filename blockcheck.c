/* 
 * blockcheck.c  --  Check regf registry files
 *
 * This program is not meant for end-users, but for developers and skillful
 * system administrators. It is meant to point out regf file inconsistencies
 * in a manner that it's easy to fix them, so that Windows will parse them 
 * correctly.
 * 
 * Licensed under the GNU GPL v2 or any later version
 *
 * Copyright (C) 2005-2010 Wilco Baan Hofman <wilco@baanhofman.nl>
 * 
 * This file contains the sequential block check (first pass).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <talloc.h>
#include "regf.h"
#include "chkregf.h"
#include "config.h"

int parse_sk (uint8_t *data, int size, long int offset)
{
	struct sk_record *sk;

	sk = (struct sk_record *) data;
	
	/* [SYN] If one of sk prev/next offset points to self, it means there
	 * is only one sk record, however.. if one points to self, the other
	 * should point to self as well. */
	if ((sk->prev_sk_offset == offset || sk->next_sk_offset == offset) &&
			sk->prev_sk_offset != sk->next_sk_offset) {
		printf("Error: One sk offset points to self, the other doesn't. (0x%lx)\n",
				offset+0x1000);
		return 0;
	}
	
	/* [SYN] The offsets point to the next and previous sk record, thus the
	 * last points to the first and the first to the last, therefore it 
	 * should never be 0 or -1 */
	if (sk->prev_sk_offset == -1 || sk->next_sk_offset == -1 ||
			sk->prev_sk_offset == 0 || sk->next_sk_offset == 0) {
		printf("Error: illegal prev/next sk offset. (0x%lx)\n",
				offset+0x1000);
		return 0;
	}
	
	/* [SYN] Size check, can't stretch beyond end of data block */
	if (sk->size > size - 0x10) {
		printf("Error: sk size value stretches beyond end of hbin data block (0x%lx)\n",
				offset+0x1000);
		return 0;
	}
	return 1;
}

int parse_vk (uint8_t *data, int size, uint32_t offset)
{
	struct vk_record *vk;
	uint32_t data_length;
	
	vk = (struct vk_record *) data;

	/* [SYN] Name length shouldn't be larger than the block->size minus 
	 * header size. */ 
	if (vk->name_length > size - 0x14) {
		printf("Error: Value name length too high (0x%lx)\n",
				(long)offset+0x1000);
		return 0;
	}
	
	/* [SYN] If bit 31 of the data length is set, the data is in the offset
	 * field itself. Locate it and strip it, if necessary. */
	if (vk->data_length & 0x80000000) {
		/* [SYN] Strip bit 31 */
		data_length = vk->data_length ^ 0x80000000;
		
		/* [SYN] No point in checking the offset, because it's data. */
		
	} else if (vk->data_offset == 0 || vk->data_offset == -1) {
		printf("Error: Invalid data offset at vk record (0x%lx)\n",
				(long)offset+0x1000);
		return 0;
	}
#if DODEBUG > 0
	if (vk->type == REG_NONE) {
		printf("Warning: You have a REG_NONE key (0x%lx)\n",
				(long)offset+0x1000);
	}
#endif
	/* [SYN] I know of only 12 data types (0x0 to 0xB) */
	if (vk->type > 0xB) {
		printf("Warning: You have an unknown value type (0x%lx) 0x%lx\n",
				(long)vk->type, (long)offset+0x1000);
	}
#if DODEBUG > 0
	if (vk->flag != 0x0 && vk->flag != 0x1) {
		printf("DEBUG: You have a vk flag (0x%x) set (0x%lx)\n",
				vk->flag, (long)offset+0x1000);
	}
#endif
	return 1;
}

int parse_ri (uint8_t *_ri_ptr, int size, long int offset)
{
	struct li_record *ri;
	uint16_t i;
	ri = (struct li_record *) _ri_ptr;

	if (ri->key_count > (size - 8) / 4) {
		printf("Size doesn't match offset count (0x%lx)!\n",
				(long)offset+0x1000);
		return 0;
	}
	if (ri->key_count == 0 || ri->key_count == 0xFFFF) {
		printf("No offset count (0x%lx)!\n",
				offset+0x1000);
		return 0;
	}
	for (i = 0;i < ri->key_count; i++) {
		struct ri_record_data *data;
		
		data = (struct ri_record_data *) &ri->data;

		if (data->offset <= 0) {
			printf("No valid offset (0x%lx) in this ri record (0x%lx)\n",
					(long)data->offset, (long)offset+0x1000);
			return 0;
		}
	}
	return 1;
}

int parse_li (uint8_t *_li_ptr, int size, long int offset)
{
	struct li_record *li;
	uint16_t i;
	li = (struct li_record *) _li_ptr;
	
	if (li->key_count > (size - 8) / 8) {
		printf("Size doesn't match key count (0x%lx)!\n",
				offset+0x1000);
		return 0;
	}
	if (li->key_count == 0 || li->key_count == 0xFFFF) {
		printf("No key count (0x%lx)!\n",
				offset+0x1000);
		return 0;
	}
	for (i = 0;i < li->key_count; i++) {
		struct li_record_data *data;
		
		data = (struct li_record_data *) &li->data;

		if (data->offset <= 0) {
			printf("No valid offset (0x%lx) in this li record (0x%lx)\n",
					(long)data->offset, (long)offset+0x1000);
			return 0;
		}
	}
	return 1;
}


int parse_lh (uint8_t *_lh_ptr, int size, long int offset)
{
	struct lh_record *lh;
	struct regf_block *regf;
	uint16_t i;
	lh = (struct lh_record *) _lh_ptr;

	regf = get_regf_struct();
	
	/* [SYN] 1.3.0.1 registries should not contain lh records. Those were
	 * introduced in 1.5.0.1 (Windows XP) */
	if (regf->version[1] == '3') {
		printf("lh records should not exist in windows NT4/2k registries (0x%lx)",
				offset+0x1000);
	}
	if (lh->key_count > (size - 8) / 8) {
		printf("Size doesn't match key count (0x%lx)!\n",
				offset+0x1000);
		return 0;
	}
	if (lh->key_count == 0 || lh->key_count == 0xFFFF) {
		printf("No key count (0x%lx)!\n",
				offset+0x1000);
		return 0;
	}
	for (i = 0;i < lh->key_count; i++) {
		struct lh_record_data *data;
		
		data = (struct lh_record_data *) &lh->data;

		if (data->offset <= 0) {
			printf("No valid offset (0x%lx) in this lh record (0x%lx)\n",
					(long)data->offset, (long)offset+0x1000);
			return 0;
		}
	}
	return 1;
}


int parse_lf (uint8_t *_lf_ptr, int size, long int offset)
{
	struct lf_record *lf;
	uint16_t i;
	lf = (struct lf_record *) _lf_ptr;

	if (lf->key_count > (size - 8) / 8) {
		printf("Size doesn't match key count (0x%lx)!\n",
				offset+0x1000);
		return 0;
	}
	if (lf->key_count == 0 || lf->key_count == 0xFFFF) {
		printf("No key count (0x%lx)!\n",
				offset+0x1000);
		return 0;
	}
	for (i = 0;i < lf->key_count; i++) {
		struct lf_record_data *data;
		
		data = (struct lf_record_data *) &lf->data;

		if (data->offset <= 0) {
			printf("No valid offset (0x%lx) in this lf record (0x%lx)\n",
					(long)data->offset, (long)offset+0x1000);
			return 0;
		}
	}
	return 1;
}

int parse_nk (TALLOC_CTX *mem_ctx, uint8_t *data, int size, long int offset)
{
	struct nk_record *nk;
	struct regf_block *regf;
#if DODEBUG > 2
	char *keyname;
#endif
	
	regf = get_regf_struct();

	nk = (struct nk_record *) data;

	if (nk->keyname_length > size - 0x4C) {
		printf("Error: Too long keyname length value (0x%lx).\n", 
				offset+0x1000);
		return 0;
	}
#if DODEBUG > 2
	keyname = talloc_strndup(mem_ctx, (char *) &nk->keyname, nk->keyname_length);
	if (!keyname) {
		printf("Allocating %ld bytes of memory failed.\n",
				(long)nk->keyname_length);
		return 0;
	}
	printf("Parsing nk of %s\n", keyname);
	talloc_free(keyname);
#endif
	/* [SYN] 0x20 = normal nk, 0x2C = root nk, 0x10 is sym-linked nk */
	if (nk->type != 0x20 && nk->type != 0x2C && nk->type != 0x10) {
		printf("Warning: this key is of unknown (%x) type (0x%lx)\n", 
				nk->type, offset+0x1000);
	}
	/* [SYN] There can be only one! */
	if (nk->type == 0x2C && offset != regf->key_offset) {
		printf("Error: Encountered unexpected root key. (0x%lx)\n",
				offset+0x1000);
	} 
	/* [SYN] If it has no parent and isn't a root key, something is wrong. */
	if (nk->parent_offset == 0x00 && nk->type != 0x2C) {
		printf("Error: this key has no parent and is no root key (0x%lx)\n",
				offset+0x1000);
		return 0;
	}
	/* [SYN] Check if there are subkeys without a subkey listing specified. */
	if (nk->subkey_count > 0 && nk->subkey_offset == -1) {
		printf("Error: this key has subkeys, but no listing (0x%lx)\n",
				offset+0x1000);
		return 0;
	}
	/* [SYN] Check for illegal NULL offsets */
	if (nk->subkey_offset == 0x00 || nk->value_offset == 0x00 || nk->classname_offset == 0x00) {
		printf("Error: this key has a 0x00 offset, this is illegal (0x%lx)\n",
				offset+0x1000);
		return 0;
	}
	/* [SYN] Check for a classname */
	if (nk->classname_length > 0 && nk->classname_offset == -1) {
		printf("Error: this key has a class name length, but no offset (0x%lx)\n",
				offset+0x1000);
		return 0;
	}
#if DODEBUG > 0
	if (nk->uk3 != 0 && nk->uk3 != -1) {
		printf("DEBUG: strange value at unknown 3 (0x%lx)\n",
				offset+0x1000);
	}
#endif
#if DODEBUG > 2
	if (nk->classname_offset != -1 || nk->classname_length > 0) {
		printf("DEBUG: Class name offset found at (0x%lx)\n",
				offset+0x1000);
	}
#endif
	/* [SYN] Check for values without listing */
	if (nk->value_count > 0 && nk->value_offset == -1) {
		printf("Error: this key has values, but no listing (0x%lx)\n",
				offset+0x1000);
		return 0;
	}
	/* [SYN] sk record is mandatory */
	if (nk->sk_offset == -1 || nk->sk_offset == 0) {
		printf("Error: this key has no sk record (0x%lx)!\n",
				offset+0x1000);
		return 0;
	}
#if DODEBUG > 2
	if (nk->uk4[0] != 0x00) {
		printf("DEBUG: 0x0034: Abnormal value (0x%08lx) at unknown 4 [0] (0x%lx)\n",
				(long)nk->uk4[0], offset+0x1000);
	}
	if (nk->uk4[1] != 0x00) {
		printf("DEBUG: 0x0038: Abnormal value (0x%08lx) at unknown 4 [1] (0x%lx)\n",
				(long)nk->uk4[1], offset+0x1000);
	}
	if (nk->uk4[2] != 0x00) {
		printf("DEBUG: 0x003C: Abnormal value (0x%08lx) at unknown 4 [2] (0x%lx)\n",
				(long)nk->uk4[2], offset+0x1000);
	}
	if (nk->uk4[3] != 0x00) {
		printf("DEBUG: 0x0040: Abnormal value (0x%08lx) at unknown 4 [3] (0x%lx)\n",
				(long)nk->uk4[3], offset+0x1000);
	}
	if (nk->uk4[4] != 0x00) {
		printf("DEBUG: 0x0044: Abnormal value (0x%08lx) at unknown 4 [4] (0x%lx)\n",
				(long)nk->uk4[4], offset+0x1000);
	}
#endif
	return 1;
}


int read_blocks (TALLOC_CTX *parent_ctx, FILE *fd, int32_t offset)
{
	int32_t cur_offset;
	struct regf_block *regf;
	int succes = 1;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_new(parent_ctx);
	if (!mem_ctx) {
		printf("Memory allocation error\n");
		return 0;
	}
	
	regf = get_regf_struct();

	/* [SYN] Set index to data block */
	cur_offset = offset + regf->key_offset;

	/* [SYN] Seek to data block */
	fseek(fd, cur_offset+0x1000, SEEK_SET);

	
	while (cur_offset < offset+0x1000) {
		struct hbin_data_block *block;
		uint16_t *record_type;
		
		block = get_hbin_data_block(mem_ctx, fd, cur_offset, 0);
		if (!block) {
			talloc_free(mem_ctx);
			return 0;
		}
		if (block->size < 0) {
			/* Unused block */
			cur_offset += -block->size;
			talloc_free(block);
			continue;
		} 
		
		/* [SYN] Get the record type and parse/check it accordingly. */
		record_type = (uint16_t *) block->data;
	
		switch (*record_type) {
			case 0x6B6E: /* [SYN] nk */
				succes &= parse_nk(mem_ctx, block->data, block->size, cur_offset);
				
				break;
			case 0x684C: /* [SYN] lh */
				succes &= parse_lh(block->data, block->size, cur_offset);
				break;
			case 0x666C: /* [SYN] lf */
				succes &= parse_lf(block->data, block->size, cur_offset);
				break;
			case 0x696C: /* [SYN] li */
				succes &= parse_li(block->data, block->size, cur_offset);
				break;
			case 0x6972: /* [SYN] ri */
				succes &= parse_ri(block->data, block->size, cur_offset);
				break;
			case 0x6B76: /* [SYN] vk */
				succes &= parse_vk(block->data, block->size, cur_offset);
				break;
			case 0x6B73: /* [SYN] sk */
				succes &= parse_sk(block->data, block->size, cur_offset);
				break;
			default:
				break;
		}
		talloc_free(block);
		cur_offset+=block->size;
		fseek(fd, cur_offset+0x1000, SEEK_SET);
	}

	talloc_free(mem_ctx);
	if (!succes) {
		return 0;
	}
	return (1);
}

