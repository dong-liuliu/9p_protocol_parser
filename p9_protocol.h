
#ifndef P9_PROTOCAL_H_
#define P9_PROTOCAL_H_


/* message types */
enum {
	Tfirst		= 100,
	Tversion	= 100,
	Rversion,
	Tauth		= 102,
	Rauth,
	Tattach		= 104,
	Rattach,
	Terror		= 106,
	Rerror,
	Tflush		= 108,
	Rflush,
	Twalk		= 110,
	Rwalk,
	Topen		= 112,
	Ropen,
	Tcreate		= 114,
	Rcreate,
	Tread		= 116,
	Rread,
	Twrite		= 118,
	Rwrite,
	Tclunk		= 120,
	Rclunk,
	Tremove		= 122,
	Rremove,
	Tstat		= 124,
	Rstat,
	Twstat		= 126,
	Rwstat,
	Rlast
};

#endif /* P9_PROTOCAL_H_ */
