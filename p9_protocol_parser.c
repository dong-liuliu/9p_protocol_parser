
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "p9_messages.h"


int msg_file_parse(int fd)
{
	struct p9_message_t p9_msg;
	uint32_t msg_size;

	char * buf;
	int max_size;
	int rsize;
	int ret;


	msg_size = 0;
	rsize = 0;
	while(1) {
		/* msg header read */
		if (rsize < sizeof(p9_msg.msg_head)) {
			buf = (char *)p9_msg.msg_head + rsize;
			max_size = sizeof(p9_msg.msg_head) - rsize;
			ret = read(fd, buf, max_size);
			if (ret <= 0) {
				goto out;
			}

			rsize += ret;
		} else if (rsize == sizeof(p9_msg.msg_head) && msg_size == 0) {
		/* msg body alloc */
			msg_size = p9_msg_size(&p9_msg);
			p9_msg.msg_data = malloc(msg_size - sizeof(p9_msg.msg_head));
		} else {
			/* read out one msg */
			if (rsize == msg_size) {
				p9_msg_display(&p9_msg);
				rsize = 0;
				msg_size = 0;
			} else {
			/* body data read */
				buf = (char *)p9_msg.msg_data + rsize - sizeof(p9_msg.msg_head);
				max_size = msg_size - rsize;
				ret = read(fd, buf, max_size);
				if (ret <= 0) {
					goto out;
				}

				rsize += ret;
			}
		}

	}

out:
	if (ret == 0) {
		printf("Msg data are read out\n");
	} else {
		printf("Ret error = %d\n", ret);
	}

	return ret;
}

int main(int argc, char **argv)
{
	char* file_name = argv[1];
	int fd;

	fd = open(file_name, O_RDONLY);

	msg_file_parse(fd);

	close(fd);

	return 0;
}


