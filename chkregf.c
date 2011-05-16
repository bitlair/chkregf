/* 
 * chkregf.c  --  Check regf registry files
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
 * This file contains the main registry checking code.
 *
 * TODO:
 * - Add pass 4, checking for orphans
 * - Maybe add a pass 5, for specific registry value data, like incorrect
 *   policy values.
 * - Big endian support and platforms with different alignment than x86
 * - Check sk reference counts
 * - Check sk pointer consistency
 * - Check security descriptors
 * 
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




/* [SYN] regf data should be available globally */
struct regf_block regf;

struct regf_block *get_regf_struct(void)
{
	return &regf;
}

uint32_t get_hbin_header(FILE *fd, signed long int offset)
{
	struct hbin_block hbin;

	
	fseek(fd, offset + 0x1000, SEEK_SET);

	if (!fread(&hbin, sizeof(hbin), 1, fd)) {
		printf("Error: short read while reading hbin block at 0x%lx\n",
			offset + 0x1000);
		return 0;
	}

	/* [SYN] this should be a hbin block */
	if (hbin.id != 0x6E696268) {
		puts("Error: this is no hbin block!");
		return 0;
	}
	
	/* [SYN] The offset from first data block should be offset - 0x1000 */
	if (hbin.offset_from_first != offset 
			|| hbin.offset_from_first % 0x1000 != 0) {
		printf("Error: hbin offset to first incorrect at 0x%lx\n", 
				offset+0x1000);
		return 0;
	}
	
	/* [SYN] The offset to the next record should be a multiple of 0x1000 */
	if (hbin.offset_to_next % 0x1000 != 0) {
		printf("Error: hbin offset to next isn't a multiple of 0x1000 at 0x%lx\n",
				offset+0x1000);
		return 0;
	}
	
	/* [SYN] The size of the hbin should be identical to the relative 
	 * offset of the next hbin. Windows XP doesn't use it. */
	return (hbin.offset_to_next);
}

int read_regf_header(FILE *fd)
{
	short int i;
	uint32_t hash = 0;
	
	fseek(fd, 0, SEEK_SET);
	
	if (!fread(&regf, sizeof(regf), 1, fd)) {
		puts("Error: short read while reading regf block");
		return 0;
	}
	
	/* [SYN] this should be a regf file */
	if (regf.id != 0x66676572) { /* [SYN] 'regf' */
		puts("No 'regf' found at 0x0 (is this an NT registry file?)");
		return 0;
	}
	/* [SYN] uk1[0] should be the same as uk1[1] */
	if (regf.uk1[0] != regf.uk1[1]) {
		puts("Values at 0x0004 and 0x0008 should be identical.");
		return 0;
	}
	/* [SYN] 0x1, 0x3(or 0x5), 0x0, 0x1 for D-words from 0x0014 (version)*/
	if (regf.version[0] != 0x1 || 
			(regf.version[1] != 0x3 && regf.version[1] != 0x5) ||
			regf.version[2] != 0x0 || regf.version[3] != 0x1) {
		puts("D-words from 0x0014 to 0x0020 should be 0x1, 0x3 or 0x5, 0x0, 0x1");
		return 0;
	}
	/* [SYN] Check first record key offset, usually 0x20 */
	if (regf.key_offset < 0x20) {
		puts("Error: 1st record key offset smaller than hbin header.");
		return 0;
	}
	if (regf.key_offset > 0x100) {
		puts("Warning: 1st record offset seems large.");
	}
	
	/* [SYN] hbin data source should be a multiple of 0x1000 */
	if ((regf.data_size % 0x1000) != 0) {
		puts("Error: data size should be a multiple of 0x1000");
		return 0;
	}
	
	/* [SYN] Check if unicode regf description is really unicode */
	for (i = 0; i < sizeof(regf.description); i++) {
		if ((i % 2) == 1) {
			if (regf.description[i] > 0x2 &&
					regf.description[i] != 0xFF) {
				puts("Warning: regf description does not appear to be unicode");
				break;
			}
		} 
	}
	
	/* [SYN] Check the checksum */
	for (i = 0; i <  (0x1FC/4); i+=1) {
		uint32_t *dword;
		dword = (uint32_t *) &regf + i;
		hash = hash ^ *dword;
	}
	if (hash != regf.checksum) {
		printf("Error: checksum incorrect; got 0x%lx, must be 0x%lx\n",
				(long)regf.checksum, (long)hash);
		printf("Note: This could be caused by other malicious data in the header!\n");
		return 0;
	}
	return 1;
}

struct hbin_data_block *get_hbin_data_block(TALLOC_CTX *mem_ctx, FILE *fd, long int offset, long int parent_off)
{
	struct hbin_data_block *block;
	long int cur_offset;

	block = talloc_zero(mem_ctx, struct hbin_data_block);

	/* [SYN] Set index to data block */
	cur_offset = offset+0x1000;

	/* [SYN] Seek to data block */
	fseek(fd, cur_offset, SEEK_SET);

#if DODEBUG > 2
	printf("Debug: Parsing block at cur_offset 0x%lx, parent 0x%lx\n", (long)cur_offset, (long) parent_off+0x1000);
#endif
	if (!fread(block, 4, 1, fd)) {
		printf("Error: short read while reading hbin data record size at 0x%lx\n",
				(long)cur_offset);
		return NULL;
	}
	if (block->size > 0) {
		if (parent_off > 0) {
			/* [SYN] Positive block->size means unused. Time to barf. */
			printf("Error: Referencing unused block (0x%lx) with size 0x%lx from 0x%lx\n",
					(long)cur_offset, (long)block->size, (long)parent_off);
			return NULL;
		} else {
			block->size = -block->size;
			return block;
		}
	}
	if (block->size == 0) {
		printf("Error: hbin data record size is NULL at 0x%lx\n",
				(long)cur_offset);
		return NULL;
	}
		
	block->size = -block->size;
	
	/* [SYN] Check block->size, do not allocate it if bigger */
	if (block->size > 32768) {
		printf("Warning: hbin data record size (0x%lx) is quite large at 0x%lx\n",
				(long)block->size, (long)cur_offset);
		printf("Warning: NOT ALLOCATING THIS BLOCK.");
		return NULL;
	}
		
	/* [SYN] Allocate memory and read the record into memory */
	if ((block->data = talloc_array(block, uint8_t, block->size)) == NULL) {
		printf("Failed to allocate %ld bytes at record 0x%lx\n",
				(long)block->size, (long)cur_offset);
		return NULL;
	}
	if (!fread(block->data, block->size, 1, fd)) {
		printf("Error: Failed to read hbin data record at 0x%lx\n",
				(long)cur_offset);
		return NULL;
	}
	return block;

}

int main (int argc, char **argv)
{
	FILE *fd;
	uint16_t i;
	int rv;
	int error = 0;
	TALLOC_CTX *mem_ctx;
	
	if (argc == 1) {
		puts("Usage: chkregf REGFILE");
		return 1;
	}
	if (!(fd = fopen(argv[1], "r"))) {
		puts("Error: file not found");
		return 2;
	}

	mem_ctx = talloc_init("chkregf registry checker");
	if (!mem_ctx) {
		printf("Memory allocation error\n");
		return 3;
	}
	
	printf("\nPass 1: Checking registry regf header\n\n");
	
	if (!read_regf_header(fd)) {
		printf("Regf header contains errors\n");
		return 1;
	} 
	

	printf("\nPass 2: Checking keys for incorrect values\n\n");
	
	for(i = 0; i < regf.data_size / 0x1000; i++) {
		uint32_t size;
		
		if (!(size = get_hbin_header(fd, 0x1000 * i))) {
			printf("Errors in hbin header at 0x%lx.",
					(long int) (0x1000 * i) + 0x1000);
			return 1;
		}
		rv = read_blocks(mem_ctx, fd, 0x1000 * i);
		if (!rv) {
			error = 1;
		}
		if (size / 0x1000 > 1) {
			i += (size/0x1000) - 1;
		}
	}

	printf("\nPass 3: Checking offsets and tree\n");

	rv = parse_tree(mem_ctx, fd, regf.key_offset, 0, "nk", 0);
	if (!rv) {
		error = 1;
	}

	if (error) {
		printf("Errors encountered\n");
		return 1;
	}
	printf("\nDone checking, no errors...\n\n");

	fclose(fd);
	return 0;
}

