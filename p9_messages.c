
#include <stdlib.h>
#include <string.h>
#include "p9_protocol.h"
#include "p9_messages.h"
#include "p9_cbuf.h"

/* on-off switch to show details */
int display_stat = 0;
int display_qid = 0;
int display_data = 0;

struct spec_info_t *spec_infos[Rlast - Tfirst - 1] = {NULL};

#define SPEC_INFO_INIT(_spec_name_) \
	static struct spec_info_t spec_info_ ## _spec_name_ = { \
		.name = #_spec_name_, \
		.create_init_spec = create_init_ ## _spec_name_, \
		.display_spec = display_ ## _spec_name_, \
	}; \
	__attribute__((constructor)) static void spec_info_init_ ## _spec_name_ (void) \
	{ \
		spec_infos[type2idx(_spec_name_)] = &spec_info_ ## _spec_name_; \
	}

#define SPEC_INFO_INIT_FULL(_spec_name_, create_func, display_func) \
	static struct spec_info_t spec_info_ ## _spec_name_ = { \
		.name = #_spec_name_, \
		.create_init_spec = create_func, \
		.display_spec = display_func, \
	}; \
	__attribute__((constructor)) static void spec_info_init_ ## _spec_name_ (void) \
	{ \
		spec_infos[type2idx(_spec_name_)] = &spec_info_ ## _spec_name_; \
	}


#define P9_HEADER_SET(sm, msg) \
		{ \
			sm->msg = msg; \
			sm->size = p9_msg_size(msg); \
			sm->type = p9_msg_type(msg); \
			sm->tag = p9_msg_tag(msg); \
		}while(0)

#define P9_HEADER_DISPLAY(sm) \
		{ \
			printf("%8s", spec_infos[type2idx(sm->type)]->name); \
			printf("\tsize:%d", sm->size); \
			printf("\ttag:%d", sm->tag); \
		}while(0)


static inline void printfn(nstr *str)
{
	printf("%d-%.*s", str->len, str->len, str->str);
}
static inline void printdata(int len, char* data)
{
	if (display_data) {
		int i;
		printf("\tdata:");
		for (i = 0; i < len; i++)
			printf(" %c", data[i]);
	}
}
static inline void printqid(qid_t *qid)
{
	if (display_qid) {
		printf("\t(qpath:%ld", qid->path);
		printf(" qver:%d", qid->version);
		printf(" qtype:%d)", qid->type);
	}
}
static inline void printstat(stat_t *stat)
{
	if (display_stat) {
		printf("\n\tSTAT{");

		printf(" size:%d", stat->size);
		printf(" type:%d", stat->type);
		printf(" dev:%d", stat->dev);

		printqid(&stat->qid);

		printf("\tmode:%d", stat->mode);
		printf(" atime:%d", stat->atime);
		printf(" mtime:%d", stat->mtime);
		printf(" length:%ld", stat->length);

		printf("\tname:"); printfn(&stat->name);
		printf(" uid:"); printfn(&stat->uid);
		printf(" gid:"); printfn(&stat->gid);
		printf(" muid:"); printfn(&stat->muid);

		printf(" }");
	}
}


static int create_init_Tversion(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Tversion *sm;

	sm = (struct p9_msg_Tversion *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->msize = buf_get_int32(bufp);
	buf_get_str(bufp, &sm->version);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Tversion(void *spec_msg)
{
	struct p9_msg_Tversion *sm = (struct p9_msg_Tversion *)spec_msg;

	P9_HEADER_DISPLAY(sm);
	printf("\tmsize:%d", sm->msize);
	printf("\tVersion:"); printfn(&sm->version);
	printf("\n");

	return 0;
}

/* 102 */
static int create_init_Tauth(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Tauth *sm;

	sm = (struct p9_msg_Tauth *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->afid = buf_get_int32(bufp);
	buf_get_str(bufp, &sm->uname);
	buf_get_str(bufp, &sm->aname);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Tauth(void *spec_msg)
{
	struct p9_msg_Tauth *sm = (struct p9_msg_Tauth *)spec_msg;

	P9_HEADER_DISPLAY(sm);
	printf("\tafid:%d", sm->afid);
	printf("\tuname:"); printfn(&sm->uname);
	printf("\taname:"); printfn(&sm->aname);

	printf("\n");

	return 0;
}

static int create_init_Tattach(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Tattach *sm;

	sm = (struct p9_msg_Tattach *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->fid = buf_get_int32(bufp);
	sm->afid = buf_get_int32(bufp);
	buf_get_str(bufp, &sm->uname);
	buf_get_str(bufp, &sm->aname);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Tattach(void *spec_msg)
{
	struct p9_msg_Tattach *sm = (struct p9_msg_Tattach *)spec_msg;

	P9_HEADER_DISPLAY(sm);
	printf("\tfid:%d", sm->fid);
	printf("\tafid:%d", sm->afid);
	printf("\tuname:"); printfn(&sm->uname);
	printf("\taname:"); printfn(&sm->aname);

	printf("\n");

	return 0;
}

static int create_init_Rattach(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Rattach *sm;

	sm = (struct p9_msg_Rattach *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	buf_get_qid(bufp, &sm->qid);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Rattach(void *spec_msg)
{
	struct p9_msg_Rattach *sm = (struct p9_msg_Rattach *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printqid(&sm->qid);
	printf("\n");

	return 0;
}

/* 107 */
static int create_init_Rerror(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Rerror *sm;

	sm = (struct p9_msg_Rerror *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	buf_get_str(bufp, &sm->ename);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Rerror(void *spec_msg)
{
	struct p9_msg_Rerror *sm = (struct p9_msg_Rerror *)spec_msg;

	P9_HEADER_DISPLAY(sm);
	printf("\tename:"); printfn(&sm->ename);
	printf("\n");

	return 0;
}

/* 108 */
static int create_init_Tflush(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Tflush *sm;

	sm = (struct p9_msg_Tflush *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->oldtag = buf_get_int16(bufp);

	*spec_msg = (void*)sm;

	return 0;
}
static int display_Tflush(void *spec_msg)
{
	struct p9_msg_Tflush *sm = (struct p9_msg_Tflush *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\toldtag:%d", sm->oldtag);
	printf("\n");

	return 0;
}
static int create_init_Rflush(struct p9_message_t *msg, void **spec_msg)
{
	struct p9_msg_Rflush *sm;

	sm = (struct p9_msg_Rflush *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	*spec_msg = (void*)sm;

	return 0;
}
static int display_Rflush(void *spec_msg)
{
	struct p9_msg_Rflush *sm = (struct p9_msg_Rflush *)spec_msg;

	P9_HEADER_DISPLAY(sm);
	printf("\n");

	return 0;
}
/* 110 */
static int create_init_Twalk(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Twalk *sm;

	sm = (struct p9_msg_Twalk *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->fid = buf_get_int32(bufp);
	sm->newfid = buf_get_int32(bufp);
	sm->nwname = buf_get_int16(bufp);
	int i;
	for (i = 0; i < sm->nwname; i++)
		buf_get_str(bufp, &sm->wnames[i]);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Twalk(void *spec_msg)
{
	struct p9_msg_Twalk *sm = (struct p9_msg_Twalk *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tfid:%d", sm->fid);
	printf("\tnewfid:%d", sm->newfid);
	printf("\tnwnames:%d", sm->nwname);

	int i;
	for (i = 0; i < sm->nwname; i++) {
		printf(" ");
		printfn(&sm->wnames[i]);
	}

	printf("\n");

	return 0;
}
/* 111 */
static int create_init_Rwalk(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Rwalk *sm;

	sm = (struct p9_msg_Rwalk *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->nwqid = buf_get_int16(bufp);
	int i;
	for (i = 0; i < sm->nwqid; i++) {
		buf_get_qid(bufp, &sm->wqids[i]);
	}

	*spec_msg = (void*)sm;

	return 0;
}
static int display_Rwalk(void *spec_msg)
{
	struct p9_msg_Rwalk *sm = (struct p9_msg_Rwalk *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tnwqid:%d", sm->nwqid);
	int i;
	for (i = 0; i < sm->nwqid; i++) {
		printf(" ");
		printqid(&sm->wqids[i]);
	}
	printf("\n");

	return 0;
}

static int create_init_Topen(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Topen *sm;

	sm = (struct p9_msg_Topen *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->fid = buf_get_int32(bufp);
	sm->mode = buf_get_int8(bufp);

	*spec_msg = (void*)sm;

	return 0;
}
static int display_Topen(void *spec_msg)
{
	struct p9_msg_Topen *sm = (struct p9_msg_Topen *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tfid:%d", sm->fid);
	printf("\tmode:%d", sm->mode);
	printf("\n");

	return 0;
}
static int create_init_Ropen(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Ropen *sm;

	sm = (struct p9_msg_Ropen *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	buf_get_qid(bufp, &sm->qid);
	sm->iounit = buf_get_int32(bufp);

	*spec_msg = (void*)sm;

	return 0;
}
static int display_Ropen(void *spec_msg)
{
	struct p9_msg_Ropen *sm = (struct p9_msg_Ropen *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printqid(&sm->qid);
	printf("\tiounit:%d", sm->iounit);

	printf("\n");

	return 0;
}

/* 114 */
static int create_init_Tcreate(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Tcreate *sm;

	sm = (struct p9_msg_Tcreate *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->fid = buf_get_int32(bufp);
	buf_get_str(bufp, &sm->name);
	sm->perm = buf_get_int32(bufp);
	sm->mode = buf_get_int8(bufp);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Tcreate(void *spec_msg)
{
	struct p9_msg_Tcreate *sm = (struct p9_msg_Tcreate *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tfid:%d", sm->fid);
	printf("\tname:"); printfn(&sm->name);
	printf("\tperm:%d", sm->perm);
	printf("\tmode:%d", sm->mode);


	printf("\n");

	return 0;
}
/* 116 */
static int create_init_Tread(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Tread *sm;

	sm = (struct p9_msg_Tread *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->fid = buf_get_int32(bufp);
	sm->offset = buf_get_int64(bufp);
	sm->count = buf_get_int32(bufp);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Tread(void *spec_msg)
{
	struct p9_msg_Tread *sm = (struct p9_msg_Tread *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tfid:%d", sm->fid);
	printf("\toffset:%ld", sm->offset);
	printf("\tcount:%d", sm->count);

	printf("\n");

	return 0;
}

static int create_init_Rread(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Rread *sm;

	sm = (struct p9_msg_Rread *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->count = buf_get_int32(bufp);
	sm->data = buf_alloc(bufp, sm->count);

	*spec_msg = (void*)sm;

	return 0;
}
static int display_Rread(void *spec_msg)
{
	struct p9_msg_Rread *sm = (struct p9_msg_Rread *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tcount:%d", sm->count);
	printdata(sm->count, (char *)sm->data);

	printf("\n");

	return 0;
}

/* 118 */
static int create_init_Twrite(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Twrite *sm;

	sm = (struct p9_msg_Twrite *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->fid = buf_get_int32(bufp);
	sm->offset = buf_get_int64(bufp);
	sm->count = buf_get_int32(bufp);
	sm->data = buf_alloc(bufp, sm->count);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Twrite(void *spec_msg)
{
	struct p9_msg_Twrite *sm = (struct p9_msg_Twrite *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tfid:%d", sm->fid);
	printf("\toffset:%ld", sm->offset);
	printf("\tcount:%d", sm->count);
	printdata(sm->count, (char *)sm->data);

	printf("\n");

	return 0;
}


static int create_init_Rwrite(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Rwrite *sm;

	sm = (struct p9_msg_Rwrite *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->count = buf_get_int32(bufp);

	*spec_msg = (void*)sm;

	return 0;
}
static int display_Rwrite(void *spec_msg)
{
	struct p9_msg_Rwrite *sm = (struct p9_msg_Rwrite *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tcount:%d", sm->count);

	printf("\n");

	return 0;
}
/* 120 */
static int create_init_Tclunk(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Tclunk *sm;

	sm = (struct p9_msg_Tclunk *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->fid = buf_get_int32(bufp);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Tclunk(void *spec_msg)
{
	struct p9_msg_Tclunk *sm = (struct p9_msg_Tclunk *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tfid:%d", sm->fid);
	printf("\n");

	return 0;
}

/* 122 */

static int create_init_Tremove(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Tremove *sm;

	sm = (struct p9_msg_Tremove *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->fid = buf_get_int32(bufp);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Tremove(void *spec_msg)
{
	struct p9_msg_Tremove *sm = (struct p9_msg_Tremove *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tfid:%d", sm->fid);
	printf("\n");

	return 0;
}


/* 124 */
static int create_init_Tstat(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Tstat *sm;

	sm = (struct p9_msg_Tstat *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->fid = buf_get_int32(bufp);

	*spec_msg = (void*)sm;

	return 0;
}
static int display_Tstat(void *spec_msg)
{
	struct p9_msg_Tstat *sm = (struct p9_msg_Tstat *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tfid:%d", sm->fid);

	printf("\n");

	return 0;
}
/* 125 */
static int create_init_Rstat(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Rstat *sm;

	sm = (struct p9_msg_Rstat *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	buf_get_stat(bufp, &sm->stat);

	*spec_msg = (void*)sm;

	return 0;
}
static int display_Rstat(void *spec_msg)
{
	struct p9_msg_Rstat *sm = (struct p9_msg_Rstat *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printstat(&sm->stat);

	printf("\n");

	return 0;
}

/* 126 */
static int create_init_Twstat(struct p9_message_t *msg, void **spec_msg)
{
	struct cbuf buffer;
	struct cbuf *bufp;
	struct p9_msg_Twstat *sm;

	sm = (struct p9_msg_Twstat *)malloc(sizeof(*sm));
	if(!sm) {
		*spec_msg = NULL;
		return -1;
	}

	P9_HEADER_SET(sm, msg);

	bufp = &buffer;
	buf_init(bufp, msg->msg_data, sm->size - 7);
	sm->fid = buf_get_int32(bufp);
	buf_get_stat(bufp, &sm->stat);

	*spec_msg = (void*)sm;

	return 0;
}

static int display_Twstat(void *spec_msg)
{
	struct p9_msg_Twstat *sm = (struct p9_msg_Twstat *)spec_msg;

	P9_HEADER_DISPLAY(sm);

	printf("\tfid:%d", sm->fid);
	printstat(&sm->stat);


	printf("\n");

	return 0;
}


SPEC_INFO_INIT(Tversion);
#define create_init_Rversion create_init_Tversion
#define display_Rversion display_Tversion
SPEC_INFO_INIT(Rversion);

SPEC_INFO_INIT(Tauth);
/* Rauth is same with Rattach */
#define create_init_Rauth create_init_Rattach
#define display_Rauth display_Rattach
SPEC_INFO_INIT(Rauth);

SPEC_INFO_INIT(Tattach);
SPEC_INFO_INIT(Rattach);

SPEC_INFO_INIT(Rerror);

SPEC_INFO_INIT(Tflush);
/* Rflush is same with Rclunk, Rremove and Rwstat */
SPEC_INFO_INIT(Rflush);

SPEC_INFO_INIT(Twalk);
SPEC_INFO_INIT(Rwalk);

SPEC_INFO_INIT(Topen);
/* Ropen is same with Rcreate */
SPEC_INFO_INIT(Ropen);
SPEC_INFO_INIT(Tcreate);
#define create_init_Rcreate create_init_Ropen
#define display_Rcreate display_Ropen
SPEC_INFO_INIT(Rcreate);

SPEC_INFO_INIT(Tread);
SPEC_INFO_INIT(Rread);
SPEC_INFO_INIT(Twrite);
SPEC_INFO_INIT(Rwrite);

SPEC_INFO_INIT(Tclunk);
#define create_init_Rclunk create_init_Rflush
#define display_Rclunk display_Rflush
SPEC_INFO_INIT(Rclunk);

SPEC_INFO_INIT(Tremove);
#define create_init_Rremove create_init_Rflush
#define display_Rremove display_Rflush
SPEC_INFO_INIT(Rremove);

SPEC_INFO_INIT(Tstat);
SPEC_INFO_INIT(Rstat);

SPEC_INFO_INIT(Twstat);
#define create_init_Rwstat create_init_Rflush
#define display_Rwstat display_Rflush
SPEC_INFO_INIT(Rwstat);


int p9_msg_display(struct p9_message_t *msg)
{
	uint8_t mtype;
	struct spec_info_t *spec_info;
	void *spec_msg;

	mtype = p9_msg_type(msg);
	spec_info = spec_infos[type2idx(mtype)];

	if(spec_info) {
		spec_info->create_init_spec(msg, &spec_msg);
		if(!spec_msg) {
			printf("spec_msg failed on create\n");
			return -1;
		}
		spec_info->display_spec(spec_msg);
		free(spec_msg);
	} else
		printf("unsupported type: %d\n", mtype);

	return 0;
}
