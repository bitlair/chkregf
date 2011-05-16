#ifndef _REGF_H_
#define _REGF_H_

struct regf_block {
	uint32_t id;			/* [SYN] 'regf' 0x66676572*/
	uint32_t uk1[2];		/* [SYN] Same value twice */
	uint32_t timestamp[2];		/* [SYN] NT timestamp */
	uint32_t version[4];		/* [SYN] 0x1,0x3 or 0x5,0x0,0x1 */
	int32_t key_offset;		/* [SYN] offset of 1st key */
	uint32_t data_size;		/* [SYN] size of data blocks */
	uint32_t uk2;			/* [SYN] 0x1 */
	uint8_t description[0x40]; 	/* [SYN] Unicode description */
	uint8_t uk3[0x18C];		/* [SYN] irrelevant bytes */
	uint32_t checksum;		/* [SYN] XOR checksum */
};

struct hbin_block {
	uint32_t id;			/* [SYN] 'hbin' 0x6E696368 */
	int32_t offset_from_first;	/* [SYN] offset from 0x1000 */
	int32_t offset_to_next;		/* [SYN] offset to next hbin */
	uint32_t uk1[2];		/* [SYN] ?? */
	uint32_t timestamp[2];		/* [SYN] NT timestamp */
	uint32_t size;			/* [SYN] size of hbin block */
};
struct hbin_data_block {
	int32_t size;			/* [SYN] Size of key record */
	uint8_t *data;			/* [SYN] the record data */
};

struct nk_record {
	uint16_t id;			/* [SYN] 'nk' 0x6B6E */
	uint16_t type;			/* [SYN] root,link,normal */
	uint32_t timestamp[2];		/* [SYN] NT timestamp */
	uint32_t uk1;			/* [SYN] ?? 0 */
	int32_t parent_offset;		/* [SYN] Parent nk key */
	uint32_t subkey_count;		/* [SYN] number of subkeys */
	uint32_t uk2;			/* [SYN] ?? 0 */
	uint32_t subkey_offset;		/* [SYN] offset of lh/lf/li/ri */
	int32_t uk3;			/* [SYN] ?? 0 or -1 */
	uint32_t value_count;		/* [SYN] number of values */
	int32_t value_offset;		/* [SYN] value list offset */
	int32_t sk_offset;		/* [SYN] Security key offset */
	int32_t classname_offset;	/* [SYN] offset of class name? */
	uint32_t uk4[5];		/* [SYN] ?? */
	uint16_t keyname_length;	/* [SYN] Key name length */
	uint16_t classname_length;	/* [SYN] Class name length */
	uint8_t keyname;
};

struct lh_record {
	uint16_t id;			/* [SYN] 'lh' 0x686C */
	uint16_t key_count;		/* [SYN] number of keys */
	uint8_t data;
};
struct lh_record_data {
	int32_t offset;			/* [SYN] offset of the key */
	uint32_t hash;			/* [SYN] base37 hash 4 bytes */
};
struct lf_record {
	uint16_t id;			/* [SYN] 'lf' 0x666C */
	uint16_t key_count;		/* [SYN] number of keys */
	uint8_t data;
};
struct lf_record_data {
	int32_t offset;			/* [SYN] offset of the key */
	char name[4];			/* [SYN] 4 bytes of key name */
};
struct li_record {
	uint16_t id;			/* [SYN] 'li' 0x696C */
	uint16_t key_count;		/* [SYN] number of keys */
	uint8_t data;
};
struct li_record_data {
	int32_t offset;			/* [SYN] offset of the key */
};
struct ri_record {
	uint16_t id;			/* [SYN] 'ri' 0x6972 */
	uint16_t count;			/* [SYN] number of li/lh's */
	uint8_t data;
};
struct ri_record_data {
	int32_t offset;			/* [SYN] offsets of li/lh */
};
struct vk_record {
	uint16_t id;			/* [SYN] 'vk' 0x6B76 */
	uint16_t name_length;		/* [SYN] value name length */
	uint32_t data_length;		/* [SYN] length of data */
	int32_t data_offset;		/* [SYN] data offset or data */
	uint32_t type;			/* [SYN] data type */
	uint16_t flag;			/* [SYN] flags */
	uint16_t unused1;		/* [SYN] unused, data trash */
	uint8_t name;
};

#define REG_NONE		0x0000
#define REG_SZ			0x0001
#define REG_EXPAND_SZ		0x0002
#define REG_BINARY		0x0003
#define REG_DWORD		0x0004
#define REG_DWORD_BIG_ENDIAN	0x0005
#define REG_LINK		0x0006
#define REG_MULTI_SZ		0x0007
#define REG_RESOURCE_LIST	0x0008
#define REG_FULL_RES_DESC	0x0009
#define REG_RES_REQ		0x000A
#define REG_QWORD		0x000B

struct sk_record {
	uint16_t id;			/* [SYN] 'sk' 0x6B73 */
	uint16_t unused1;		/* [SYN] unused, 0x00? */
	int32_t prev_sk_offset;	/* [SYN] previous sk record */
	int32_t next_sk_offset;	/* [SYN] next sk record */
	uint32_t usage_counter;	/* [SYN] Usage counter */
	uint32_t size;		/* [SYN] sk data size */
	uint8_t data;
};
/* [SYN] FIXME I have no sk record data information. Nigel suggested this is a
 * standard self-relative security descriptor, but that doesn't mean much to
 * me. */
struct sk_record_data {
	char data;				/* [SYN] Insufficient info */
};
#endif /* _REGF_H_ */
