
#ifndef P9_CBUF_H_
#define P9_CBUF_H_

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <pthread.h>
#include <errno.h>
#include <assert.h>

struct cbuf {
	unsigned char *sp;
	unsigned char *p;
	unsigned char *ep;
};

static inline void
buf_init(struct cbuf *buf, void *data, int datalen)
{
	buf->sp = buf->p = data;
	buf->ep = data + datalen;
}


static inline int
buf_check_overflow(struct cbuf *buf)
{
	return buf->p > buf->ep;
}

static inline int
buf_check_end(struct cbuf *buf)
{
	return buf->p == buf->ep;
}

static inline int
buf_check_size(struct cbuf *buf, int len)
{
	if (buf->p+len > buf->ep) {
		if (buf->p < buf->ep)
			buf->p = buf->ep + 1;

		return 0;
	}

	return 1;
}

static inline void *
buf_alloc(struct cbuf *buf, int len)
{
	void *ret = NULL;

	if (buf_check_size(buf, len)) {
		ret = buf->p;
		buf->p += len;
	}

	return ret;
}

static inline void
buf_put_int8(struct cbuf *buf, uint8_t val, uint8_t* pval)
{
	if (buf_check_size(buf, 1)) {
		buf->p[0] = val;
		buf->p++;

		if (pval)
			*pval = val;
	}
}

static inline void
buf_put_int16(struct cbuf *buf, uint16_t val, uint16_t *pval)
{
	if (buf_check_size(buf, 2)) {
		buf->p[0] = val;
		buf->p[1] = val >> 8;
		buf->p += 2;

		if (pval)
			*pval = val;

	}
}

static inline void
buf_put_int32(struct cbuf *buf, uint32_t val, uint32_t *pval)
{
	if (buf_check_size(buf, 4)) {
		buf->p[0] = val;
		buf->p[1] = val >> 8;
		buf->p[2] = val >> 16;
		buf->p[3] = val >> 24;
		buf->p += 4;

		if (pval)
			*pval = val;
	}
}

static inline void
buf_put_int64(struct cbuf *buf, uint64_t val, uint64_t *pval)
{
	if (buf_check_size(buf, 8)) {
		buf->p[0] = val;
		buf->p[1] = val >> 8;
		buf->p[2] = val >> 16;
		buf->p[3] = val >> 24;
		buf->p[4] = val >> 32;
		buf->p[5] = val >> 40;
		buf->p[6] = val >> 48;
		buf->p[7] = val >> 56;
		buf->p += 8;

		if (pval)
			*pval = val;
	}
}

static inline void
buf_put_str(struct cbuf *buf, char *s, nstr *ps)
{
	int slen = 0;

	if (s)
		slen = strlen(s);

	if (buf_check_size(buf, 2+slen)) {
		ps->len = slen;
		buf_put_int16(buf, slen, NULL);
		ps->str = buf_alloc(buf, slen);
		memmove(ps->str, s, slen);
	}
}

static inline void
buf_put_qid(struct cbuf *buf, qid_t *qid, qid_t *pqid)
{
	buf_put_int8(buf, qid->type, &pqid->type);
	buf_put_int32(buf, qid->version, &pqid->version);
	buf_put_int64(buf, qid->path, &pqid->path);
}

static inline uint8_t
buf_get_int8(struct cbuf *buf)
{
	uint8_t ret = 0;

	if (buf_check_size(buf, 1)) {
		ret = buf->p[0];
		buf->p++;
	}

	return ret;
}

static inline uint16_t
buf_get_int16(struct cbuf *buf)
{
	uint16_t ret = 0;

	if (buf_check_size(buf, 2)) {
		ret = buf->p[0] | (buf->p[1] << 8);
		buf->p += 2;
	}

	return ret;
}

static inline uint32_t
buf_get_int32(struct cbuf *buf)
{
	uint32_t ret = 0;

	if (buf_check_size(buf, 4)) {
		ret = buf->p[0] | (buf->p[1] << 8) | (buf->p[2] << 16) |
			(buf->p[3] << 24);
		buf->p += 4;
	}

	return ret;
}

static inline uint64_t
buf_get_int64(struct cbuf *buf)
{
	uint64_t ret = 0;

	if (buf_check_size(buf, 8)) {
		ret = (uint64_t) buf->p[0] |
			((uint64_t) buf->p[1] << 8) |
			((uint64_t) buf->p[2] << 16) |
			((uint64_t) buf->p[3] << 24) |
			((uint64_t) buf->p[4] << 32) |
			((uint64_t) buf->p[5] << 40) |
			((uint64_t) buf->p[6] << 48) |
			((uint64_t) buf->p[7] << 56);
		buf->p += 8;
	}

	return ret;
}

static inline void
buf_get_str(struct cbuf *buf, nstr *str)
{
	str->len = buf_get_int16(buf);
	str->str = buf_alloc(buf, str->len);
}

static inline void
buf_get_qid(struct cbuf *buf, qid_t *qid)
{
	qid->type = buf_get_int8(buf);
	qid->version = buf_get_int32(buf);
	qid->path = buf_get_int64(buf);
}

static inline void
buf_get_stat(struct cbuf *buf, stat_t *stat)
{
	/* there are useless 2 byte ahead of Stat*/
	buf_get_int16(buf);

	stat->size = buf_get_int16(buf);
	stat->type = buf_get_int16(buf);
	stat->dev = buf_get_int32(buf);
	buf_get_qid(buf, &stat->qid);
	stat->mode = buf_get_int32(buf);
	stat->atime = buf_get_int32(buf);
	stat->mtime = buf_get_int32(buf);
	stat->length = buf_get_int64(buf);
	buf_get_str(buf, &stat->name);
	buf_get_str(buf, &stat->uid);
	buf_get_str(buf, &stat->gid);
	buf_get_str(buf, &stat->muid);
}

#if 0

static inline void
buf_put_wstat(struct cbuf *bufp, stat_t *wstat, stat_t* stat, int statsz, int dotu)
{
	buf_put_int16(bufp, statsz, &stat->size);
	buf_put_int16(bufp, wstat->type, &stat->type);
	buf_put_int32(bufp, wstat->dev, &stat->dev);
	buf_put_qid(bufp, &wstat->qid, &stat->qid);
	buf_put_int32(bufp, wstat->mode, &stat->mode);
	buf_put_int32(bufp, wstat->atime, &stat->atime);
	buf_put_int32(bufp, wstat->mtime, &stat->mtime);
	buf_put_int64(bufp, wstat->length, &stat->length);

	buf_put_str(bufp, wstat->name, &stat->name);
	buf_put_str(bufp, wstat->uid, &stat->uid);
	buf_put_str(bufp, wstat->gid, &stat->gid);
	buf_put_str(bufp, wstat->muid, &stat->muid);

	if (dotu) {
		buf_put_str(bufp, wstat->extension, &stat->extension);
		buf_put_int32(bufp, wstat->n_uid, &stat->n_uid);
		buf_put_int32(bufp, wstat->n_gid, &stat->n_gid);
		buf_put_int32(bufp, wstat->n_muid, &stat->n_muid);
	}
}


static int
size_wstat(stat_t *wstat, int dotu)
{
	int size = 0;

	if (wstat == NULL)
		return 0;

	size = 2 + 4 + 13 + 4 +  /* type[2] dev[4] qid[13] mode[4] */
		4 + 4 + 8 + 	 /* atime[4] mtime[4] length[8] */
		8;		 /* name[s] uid[s] gid[s] muid[s] */

	if (wstat->name)
		size += strlen(wstat->name);
	if (wstat->uid)
		size += strlen(wstat->uid);
	if (wstat->gid)
		size += strlen(wstat->gid);
	if (wstat->muid)
		size += strlen(wstat->muid);

	if (dotu) {
		size += 4 + 4 + 4 + 2; /* n_uid[4] n_gid[4] n_muid[4] extension[s] */
		if (wstat->extension)
			size += strlen(wstat->extension);
	}

	return size;
}

#endif // 0

#endif /* P9_CBUF_H_ */
