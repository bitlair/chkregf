/* 
 * treecheck.c  --  Check regf registry files
 *
 * This program is not meant for end-users, but for developers and skillful
 * system administrators. It is meant to point out regf file inconsistencies
 * in a manner that it's easy to fix them, so that Windows will parse them 
 * correctly.
 * 
 * Licensed under the GNU GPL v2 or any later version
 *
 * Copyright (C) 2010 Wilco Baan Hofman <wilco@baanhofman.nl>
 * 
 * This file contains the tree/offset/integrity check.
 */
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <talloc.h>
#include <ctype.h>
#include "regf.h"
#include "chkregf.h"
#include "config.h"

char * get_nk_keyname(TALLOC_CTX *mem_ctx, FILE *fd, long int offset, long int parent_off)
{
	char *keyname;
	struct hbin_data_block *block;
	struct nk_record *nk;
	
	block = get_hbin_data_block(mem_ctx, fd, offset, parent_off);
	if (!block) {
		return NULL;
	}
	if (strncmp((char *)block->data, "nk", 2) != 0) {
		printf("Error: Expected nk block at 0x%lx, parent 0x%lx\n", offset, parent_off);
		talloc_free(block);
		return NULL;
	}
	nk = (struct nk_record *) block->data;

	keyname = talloc_strndup(mem_ctx, (char *)&nk->keyname, nk->keyname_length);
	talloc_free(block);
	return keyname;
}

int parse_tree(TALLOC_CTX *parent_ctx,
               FILE *fd,
               long int offset,
               long int parent_off,
               const char *expect_type,
               long int expect_count)
{
	struct hbin_data_block *block;
	int rv;
	int error = 0;
	TALLOC_CTX *mem_ctx;

	mem_ctx = talloc_new(parent_ctx);
	if (!mem_ctx) {
		printf("Memory allocation error\n");
		return 0;
	}

	block = get_hbin_data_block(mem_ctx, fd, offset, parent_off);
	if (!block) {
		return 0;
	}

	/* [SYN] For display purposes, increase offset by 0x1000 */
	offset += 0x1000;

	/* [SYN] 
	 * Based on the type of block we expect and actually get, parse the block
	 */

	/* [SYN] Value expected, this has no header so best we can do is check block length */
	if (strcmp(expect_type, "value") == 0) {
		if (block->size - 4 < expect_count) {
			printf("Error: Block too small (0x%lxb) for value length (%ld) at 0x%lx\n",
					(long)block->size, (long)expect_count, (long)offset);
			talloc_free(mem_ctx);
			return 0;
		}	
	/* [SYN] Value list expected, no header, so check block->size and traverse the values */
	} else if (strcmp(expect_type, "valuelist") == 0) {
		uint16_t i;
		if (block->size < (expect_count+1)*sizeof(uint32_t)) {
			printf("Error: Block too small (0x%lxb) for value count (%ld) at 0x%lx\n",
					(long)block->size, (long)expect_count, (long)offset);
			talloc_free(mem_ctx);
			return 0;
		}
		for (i = 0; i < expect_count; i++) {
			uint32_t vl_offset = ((uint32_t *)block->data)[i];
			rv = parse_tree(mem_ctx, fd, vl_offset, parent_off, "vk", 0);
			if (!rv) {
				error = 1;
			}
		}

	/* [SYN] We got an 'nk' block. */
	} else if (strncmp((char *)block->data, "nk", 2) == 0) {
		struct nk_record *nk = (struct nk_record *) block->data;
#if DODEBUG > 2
		char *keyname;
#endif
		/* [SYN] If we didn't expect an nk block, the registry is corrupt. */
		if (strncmp(expect_type, "nk", 2) != 0) {
			printf("Error: Unexpected 'nk' record at 0x%lx, expected %s\n",
					(long)offset, expect_type);
			talloc_free(mem_ctx);
			return 0;
		}
	
		/* [SYN] Check if the parent is consistent with our data about the parent. */
		if (nk->parent_offset != parent_off && nk->type != 0x2C) {
			printf("Error: Incorrect parent offset for nk record at 0x%lx\n",
					(long)offset);
			error = 1;
		}

		/* [SYN] If we have a parent, this should not be a root key */
		if (nk->type == 0x2C && parent_off != 0) {
			printf("Error: Unexpected root key at 0x%lx, parent 0x%lx\n",
				(long)offset, (long)parent_off);
			error = 1;
		}
#if DODEBUG > 2
		printf("==== KEY ====\n");

		keyname = talloc_strndup(mem_ctx, (char *)&nk->keyname, nk->keyname_length);
		if (!keyname) {
			printf("Allocating %ld bytes of memory failed.\n",
					(long)nk->keyname_length);
			talloc_free(mem_ctx);
			return 0;
		}
		printf("Key name:            %s\n", keyname);
		printf("Type:                %X\n", nk->type);
		printf("Parent offset:       0x%lx\n", (long) nk->parent_offset);
		printf("Number of subkeys:   %ld\n", (long) nk->subkey_count);
		printf("Subkey dir offset:   0x%lx\n", (long) nk->subkey_offset);
		printf("Number of values:    %ld\n", (long) nk->value_count);
		printf("Value list offset:   0x%lx\n", (long) nk->value_offset);
		printf("Security key offset: 0x%lx\n", (long) nk->sk_offset);
		printf("Class name offset:   0x%lx\n", (long) nk->classname_offset);
		printf("Key name length:     %ld\n", (long) nk->keyname_length);

#endif
		/* [SYN] If we have a class name, parse it */
		if (nk->classname_length > 0) {
			rv = parse_tree(mem_ctx, fd, nk->classname_offset, offset-0x1000, "value", nk->classname_length);
			if (!rv) {
				error = 1;
			}
		}
		/* [SYN] Parse the security key */
		rv = parse_tree(mem_ctx, fd, nk->sk_offset, offset-0x1000, "sk", 0);
		if (!rv) {
			error = 1;
		}

		/* [SYN] If we have subkeys, parse the subkeys */
		if (nk->subkey_count > 0) {
			rv = parse_tree(mem_ctx, fd, nk->subkey_offset, offset-0x1000, "subkeylist", nk->subkey_count);
			if (!rv) {
				error = 1;
			}
		}
		/* [SYN] If we have values, parse the values */
		if (nk->value_count > 0) {
			rv = parse_tree(mem_ctx, fd, nk->value_offset, offset-0x1000, "valuelist", nk->value_count);
			if (!rv) {
				error = 1;
			}
		}
	
		
	} else if (strncmp((char *)block->data, "sk", 2) == 0) {
		if (strcmp(expect_type, "sk") != 0) {
			printf("Error: Did not expect sk block here\n");
			error = 1;
		}
		/* TODO: Count sk references */
		/* TODO: Check security descriptor */
	} else if (strncmp((char *)block->data, "ri", 2) == 0) {
		printf("This is an ri block, cannot check this.\n");
		if (strcmp(expect_type, "subkeylist") != 0) {
			printf("Error: Did not expect subkey list, expected %s at 0x%lx, parent 0x%lx\n",
					expect_type, (long)offset, (long)parent_off);
			error = 1;
		}
		error = 1;
	} else if (strncmp((char *)block->data, "li", 2) == 0) {
		struct li_record *li = (struct li_record *)block->data;
		char *keyname;
		char *prev_keyname = NULL;
		uint16_t i;

		printf("This is an li block\n");
		if (strcmp(expect_type, "subkeylist") != 0) {
			printf("Error: Did not expect subkey list, expected %s at 0x%lx, parent 0x%lx\n",
					expect_type, (long)offset, (long)parent_off);
			error = 1;
		}
		/* [SYN] Check if the key count matches that of the parent */
		if (li->key_count != expect_count) {
			printf("Error: Expected %ld subkeys, got %ld subkeys at 0x%lx\n",
					(long)expect_count, (long)li->key_count, (long)offset);
			error = 1;
		}
		
		for (i = 0; i < li->key_count; i++) {
			struct li_record_data *data = &(((struct li_record_data *)&li->data)[i]);

			keyname = get_nk_keyname(mem_ctx, fd, data->offset, offset);
			
			/* [SYN] Check if the keys are sorted alphabetically */
			if (prev_keyname != NULL && strcasecmp(prev_keyname, keyname) > 0) {
				printf("Error: lf block is not sorted by name at 0x%lx, parent 0x%lx\n",
						(long)offset, (long)parent_off);
				error = 1;
			}

			rv = parse_tree(mem_ctx, fd, data->offset, parent_off, "nk", 0);
			if (!rv) {
				error = 1;
			}
			/* [SYN] Set the previous key name (free previous if exists) */
			if (prev_keyname) {
				talloc_free(prev_keyname);
			}
			prev_keyname = keyname;
		}
		talloc_free(keyname);
	} else if (strncmp((char *)block->data, "lf", 2) == 0) {
		struct lf_record *lf = (struct lf_record *)block->data;
		char *keyname;
		char *prev_keyname = NULL;
		uint16_t i;

		if (strcmp(expect_type, "subkeylist") != 0) {
			printf("Error: Did not expect subkey list, expected %s at 0x%lx, parent 0x%lx\n",
					expect_type, (long)offset, (long)parent_off);
			error = 1;
		}
		/* [SYN] Check if the key count matches that of the parent */
		if (lf->key_count != expect_count) {
			printf("Error: Expected %ld subkeys, got %ld subkeys at 0x%lx\n",
					(long)expect_count, (long)lf->key_count, (long)offset);
			error = 1;
		}
		for (i = 0; i < lf->key_count; i++) {
			struct lf_record_data *data = &(((struct lf_record_data *)&lf->data)[i]);

			keyname = get_nk_keyname(mem_ctx, fd, data->offset, offset);
			
			/* [SYN] Check if the keys are sorted alphabetically */
			if (prev_keyname != NULL && strcasecmp(prev_keyname, keyname) > 0) {
				printf("Error: lf block is not sorted by name at 0x%lx, parent 0x%lx\n",
						(long)offset, (long)parent_off);
				error = 1;
			}

			/* [SYN] Verify first 4 bytes name in lf data record with the key name */
			if (strncmp(data->name, keyname, 4) != 0) {
				printf("Error: Incorrect first 4 bytes of key name (0x%lx) in lf block at 0x%lx\n",
						(long)data->offset, (long)offset);
				error = 1;
			}

			rv = parse_tree(mem_ctx, fd, data->offset, parent_off, "nk", 0);
			if (!rv) {
				error = 1;
			}

			/* [SYN] Set the previous key name (free previous if exists) */
			if (prev_keyname) {
				talloc_free(prev_keyname);
			}
			prev_keyname = keyname;
		}
		talloc_free(keyname);

	} else if (strncmp((char *)block->data, "lh", 2) == 0) {
		struct lh_record *lh = (struct lh_record *)block->data;
		char *keyname;
		char *prev_keyname = NULL;
		uint16_t i;

		if (strcmp(expect_type, "subkeylist") != 0) {
			printf("Error: Did not expect subkey list, expected %s at 0x%lx, parent 0x%lx\n",
					expect_type, (long)offset, (long)parent_off);
			error = 1;
		}
		if (lh->key_count != expect_count) {
			printf("Error: Expected %ld subkeys, got %ld subkeys at 0x%lx\n",
					(long)expect_count, (long)lh->key_count, (long)offset);
			error = 1;
		}
		
		for (i = 0; i < lh->key_count; i++) {
			struct lh_record_data *data = &(((struct lh_record_data *)&lh->data)[i]);
			uint32_t hash;
			uint16_t j;
			keyname = get_nk_keyname(mem_ctx, fd, data->offset, offset);
			
			/* [SYN] Check if the keys are sorted alphabetically */
			if (prev_keyname != NULL && strcasecmp(prev_keyname, keyname) > 0) {
				printf("Error: lf block is not sorted by name at 0x%lx, parent 0x%lx\n",
						(long)offset, (long)parent_off);
				error = 1;
			}

			/* [SYN] Compute hash */
			/* FIXME: toupper is inconsistent with Windows for special characters */
			for (j = 0; j < strlen(keyname); j++) {
				hash *= 37;
				hash += toupper(keyname[i]);
			}

			/* [SYN] Verify if the computed hash is identical to the stored hash */
			if (hash != data->hash) {
				printf("Error: lh block has incorrect hash for offset 0x%lx at 0x%lx\n",
						(long)data->offset, (long)offset);
				error = 1;
			}

			rv = parse_tree(mem_ctx, fd, data->offset, parent_off, "nk", 0);
			if (!rv) {
				error = 1;
			}
		}
	} else if (strncmp((char *)block->data, "vk", 2) == 0) {
		struct vk_record *vk = (struct vk_record *) block->data;
#if DODEBUG > 2
		char *valuename;
#endif
		/* [SYN] If we didn't expect a vk record specifically, this registry is corrupt */
		if (strcmp(expect_type, "vk") != 0) {
			printf("Error: did not expect vk block, expected %s at 0x%lx, parent 0x%lx\n",
					expect_type, (long)offset, (long)parent_off);
			error = 1;
		}
#if DODEBUG > 2
		printf("==== VALUE ====\n"); 
		valuename = talloc_strndup(mem_ctx, (char *)&vk->name, vk->name_length);
		if (!keyname) {
			printf("Allocating %ld bytes of memory failed.\n",
					(long)nk->keyname_length);
			talloc_free(mem_ctx);
			return 0;
		}
		printf("name:     %s\n", valuename);
		printf("name len: %ld\n", (long)vk->name_length);
		printf("data len: 0x%08lx\n", (long)vk->data_length);
		printf("data off: 0x%lx\n", (long)vk->data_offset);
		printf("type:     0x%lx\n\n", (long)vk->type);
#endif
		if (!(vk->data_length & 0x80000000)) {
			rv = parse_tree(mem_ctx, fd, vk->data_offset, offset, "value", vk->data_length);
			if (!rv) {
				error = 1;
			}
		}
	} else {
		printf("Unknown data at 0x%lx!\n", (long)offset);
		error = 1;
	}

	talloc_free(mem_ctx);

	if (error) {
		return 0;

	}
	return 1;	
}
