
#ifndef P9_MESSAGES_H_
#define P9_MESSAGES_H_

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

struct p9_message_t {
	uint8_t msg_head[7];
	uint8_t *msg_data;
};

static inline uint8_t p9_msg_type(struct p9_message_t *msg)
{
	return msg->msg_head[4];
}
static inline uint32_t p9_msg_size(struct p9_message_t *msg)
{
	return *(uint32_t*)msg->msg_head;
}
static inline uint16_t p9_msg_tag(struct p9_message_t *msg)
{
	return *(uint16_t*)&msg->msg_head[5];
}


typedef struct {
	uint16_t len;
	char*	str;
}nstr;

typedef struct {
	uint64_t	path; /* similar with inode number */
	uint32_t	version; /* a hash of the file's modification time */
	uint8_t		type; /* file type */
}qid_t;



struct p9_msg_common {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint8_t others[0];
};

struct p9_msg_Tversion {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t msize;
	nstr version;
};
struct p9_msg_Rversion {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t msize;
	nstr version;
};

struct p9_msg_Tauth {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t afid;
	nstr	uname;
	nstr	aname;
};
struct p9_msg_Rauth {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	qid_t aqid;
};

struct p9_msg_Tattach {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t fid;
	uint32_t afid;
	nstr	uname;
	nstr	aname;
};
struct p9_msg_Rattach {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	qid_t qid;
};

struct p9_msg_Rerror {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	nstr ename;
};

struct p9_msg_Tflush {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint16_t oldtag;
};
struct p9_msg_Rflush {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;
};

#define MAXWELEM	16

struct p9_msg_Twalk {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t fid;
	uint32_t newfid;
	uint16_t nwname;
	nstr	wnames[MAXWELEM];
};
struct p9_msg_Rwalk {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint16_t nwqid;
	qid_t	wqids[MAXWELEM];
};

struct p9_msg_Topen {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t fid;
	uint8_t mode;
};
struct p9_msg_Ropen {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	qid_t qid;
	uint32_t iounit;
};

struct p9_msg_Tcreate {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t fid;
	nstr name;
	uint32_t perm;
	uint8_t mode;
};
struct p9_msg_Rcreate {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	qid_t qid;
	uint32_t iounit;
};

struct p9_msg_Tread {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t fid;
	uint64_t offset;
	uint32_t count;
};
struct p9_msg_Rread {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t count;
	uint8_t *data;
};

struct p9_msg_Twrite {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t fid;
	uint64_t offset;
	uint32_t count;
	uint8_t *data;
};
struct p9_msg_Rwrite {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t count;
};

struct p9_msg_Tclunk {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t fid;
};
struct p9_msg_Rclunk {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;
};

struct p9_msg_Tremove {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t fid;
};
struct p9_msg_Rremove {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;
};

typedef struct {
	uint16_t size;
	uint16_t type;
	uint32_t dev;

	qid_t qid;
	uint32_t mode;
	uint32_t atime;
	uint32_t mtime;
	uint64_t length;

	nstr	name;
	nstr	uid;
	nstr	gid;
	nstr	muid;
}stat_t;

struct p9_msg_Tstat {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t fid;
};
struct p9_msg_Rstat {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	stat_t	stat;
};

struct p9_msg_Twstat {
	struct p9_message_t *msg;
	uint32_t size;
	uint8_t type;
	uint16_t tag;

	uint32_t fid;
	stat_t	stat;
};
struct p9_msg_Rwstat {
	uint32_t size;
	uint8_t type;
	uint16_t tag;
};


typedef int (*create_init_spec_f)(struct p9_message_t *msg, void **spec_msg);
typedef int (*display_spec_f)(void *spec_msg);

struct spec_info_t {
	char *name;
	create_init_spec_f create_init_spec;
	display_spec_f display_spec;
};

#define type2idx(mtype) ((mtype) - Tfirst)

int p9_msg_display(struct p9_message_t *msg);



#endif /* P9_MESSAGES_H_ */
