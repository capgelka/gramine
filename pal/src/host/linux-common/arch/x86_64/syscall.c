// #include <stdio.h>
#include <stdarg.h>
#include "syscall.h"
#include "log.h"
// #include <unistd.h>

#define socket socket_orig
#include <sys/socket.h>
#undef socket

#include "api.h"
#include <sys/un.h>
#include <sys/types.h>
#include <sys/syscall.h>

#define CLIENT_SOCK "/tmp/fuzz_client_sock"
#define SERVER_SOCK "/tmp/fuzz_server_sock"
#define BUFF_SIZE 100
 
// typedef struct Driver FuzzDriver;

int g_start_interception = 0;

#define SYSCALL_TO_SWITCH SYS_open
#define ARG_TO_SWITCH "/tmp//message1234"

void on_enable()
{
	log_always("Set break on me");
}


long do_syscall_wrapped(long nr, int num_args, ...)
{
	static int sock_fd = 0;
    static struct sockaddr_un cl_addr;
    static struct sockaddr_un sv_addr;
    static int on_syscall = 0;
    static int not_handle = 0;
    static int enable_hooks = 0;
    char buff[BUFF_SIZE] = {0};


	va_list ap;
  	va_start(ap, num_args);
  	int ret = 0;
  	int fuzz = 0;
  	int fuzz_ret = 0;

	if (g_start_interception && !on_syscall) {

		if (on_syscall || not_handle) {
			goto passthrough_syscall;
		}

		// handle logs. We assume our programs doesn't
		// do anythong importnt with stdout
		if (enable_hooks && nr == SYS_write) {
			va_list ap_copy;
	    	va_copy(ap_copy, ap);
	    	int fd = va_arg(ap_copy, int);
	    	if (fd == 2) {
	    		va_end(ap_copy);
	    		goto passthrough_syscall;
	    	}
	    	va_end(ap_copy);
		}

		not_handle = 1;

	    if (!enable_hooks && (nr == SYSCALL_TO_SWITCH)) {
	    	log_always("HHOOK SPECIAL");
	    	va_list ap_copy;
	    	va_copy(ap_copy, ap);
	    	char* first = va_arg(ap_copy, char*);
	    	if (!strcmp(first, ARG_TO_SWITCH)) {
	    		log_always("ENABLED!!!!! %ld \n", nr);
		    	enable_hooks = 1;
		    	on_enable();
		    	not_handle = 0;
		    	on_syscall = 0;
		    	va_end(ap_copy);
//		    	goto passthrough_syscall;
		    	return 0;
	    	} else {
	    		log_always("GOOD ARG: %ld |CMP: %d",
	    			nr, strcmp(first, ARG_TO_SWITCH)
	    		);
	    		log_always("EXPECTED: %s | REAL: %s", ARG_TO_SWITCH, first);
	    	}
	    	va_end(ap_copy);
	    }

	    if (!enable_hooks) {
	    	long x = SYSCALL_TO_SWITCH;
	    	log_always("CALL: %ld, args: %d | %ld (to switch)", nr, num_args, x);

	    	not_handle = 0;
	    	goto passthrough_syscall;
	    }
	    not_handle = 0;
	    on_syscall = 1;

		
		if (!sock_fd) {
			DO_SYSCALL_ORIG(unlink, CLIENT_SOCK);
			sock_fd = DO_SYSCALL_ORIG(socket, AF_UNIX, SOCK_DGRAM, 0);
			if (sock_fd < 0) {
				DO_SYSCALL_ORIG(exit);
			}

			for (int i = 0; i < sizeof(struct sockaddr_un); i++) {
		    	((char*)&cl_addr)[i] = 0;
		    }

		    cl_addr.sun_family = AF_UNIX;
		    for (int i = 0; i <= sizeof(cl_addr.sun_path); i++) {
		    	cl_addr.sun_path[i] = CLIENT_SOCK[i];
		    }

    	    ret = DO_SYSCALL_ORIG(
		    	bind,
		    	sock_fd,
		    	(const struct sockaddr *) &cl_addr,
	            sizeof(struct sockaddr_un)
	        );

		    if (ret < 0) {
		        log_error("Server is down: %d", ret);
		        log_error("Path: |%s|", cl_addr.sun_path);
				DO_SYSCALL_ORIG(exit);
			}

	        sv_addr.sun_family = AF_UNIX;
		    for (int i = 0; i < sizeof(cl_addr.sun_path); i++) {
		    	sv_addr.sun_path[i] = SERVER_SOCK[i];
		    }

		}


		// memset(&claddr, 0, sizeof(struct sockaddr_un));


	    //strncpy(addr.sun_path, CLIENT_SOCK, sizeof(addr.sun_path) - 1);




		// ret = DO_SYSCALL_ORIG(send, sock_fd, argv[i], strlen(argv[i]) + 1);
        // if (ret == -1) {
        //     perror("write");
        //     break;
        // }
//        raw_syscall(long nr, size_t args_count, unsigned long* values)


        size_t msg_len = 0;

        // long* msg = (long*)buff;
  	

  		// int i = 0;
		
        // int index = 0;
        // msg[index++] = nr;
        // msg[index++] = num_args;
        // for (int i = 0; i < num_args; i++) {
        // 	msg[index++] = va_arg(ap, long);
        // }
	    // size_t msg_len = (num_args + 2) * sizeof(long);
	    // log_always("MSG: %ld, %ld, %ld %ld %ld", msg[0], msg[1], msg[2], msg[3], msg[4]);

        //log_always("SYS: %ld, ARGS: %d, arg1: %ld", nr, num_args, va_arg(ap, char*));
    	va_list ap_fuzz;
    	va_copy(ap_fuzz, ap);
        switch (nr)
		{
		    case SYS_read:
		    {
		        long fd = va_arg(ap_fuzz, long);
		        char* buf = va_arg(ap_fuzz, char*);
		        size_t count = va_arg(ap_fuzz, size_t);
		        snprintf(buff, BUFF_SIZE, "read,%ld,buff,%ld",
		                 fd, count);
		        msg_len = strlen(buff);
		        break;
		    }
		    case SYS_write:
		    {
		        long fd = va_arg(ap_fuzz, long);
		        const char* buf = va_arg(ap_fuzz, const char*);
		        size_t count = va_arg(ap_fuzz, size_t);
		        snprintf(buff, BUFF_SIZE, "write,%ld,buff,%ld",
		                 fd, count);
		        msg_len = strlen(buff);
		        break;
    	    }
		    case SYS_open:
		    {
		        const char* filename = va_arg(ap_fuzz, const char*);
		        int flags = va_arg(ap_fuzz, int);
		        mode_t mode = va_arg(ap_fuzz, mode_t);
		        snprintf(buff, BUFF_SIZE, "open,%s,%d,%d",
		                 filename, flags, mode);
		        msg_len = strlen(buff);
		        break;
		    }
		    case SYS_close:
		    {
		        long fd = va_arg(ap_fuzz, long);
		        snprintf(buff, BUFF_SIZE, "close,%ld", fd);
		        msg_len = strlen(buff);
		        break;
		    }    
		    case SYS_lseek:
		    {
		        long fd = va_arg(ap_fuzz, long);
		        off_t offset = va_arg(ap_fuzz, off_t);
		        int whence = va_arg(ap_fuzz, int);
		        snprintf(buff, BUFF_SIZE, "lseek,%ld,%lld,%d",
		                 fd, (long long)offset, whence);
		        msg_len = strlen(buff);
		        break;
		    }
		    case SYS_pread64:
		    {
		        long fd = va_arg(ap_fuzz, long);
		        char* buf = va_arg(ap_fuzz, char*);
		        size_t count = va_arg(ap_fuzz, size_t);
		        off_t offset = va_arg(ap_fuzz, off_t);
		        snprintf(buff, BUFF_SIZE, "pread,%ld,buff,%ld,%lld",
		                 fd, count, (long long)offset);
		        msg_len = strlen(buff);
		        break;
		    }
		    case SYS_pwrite64:
		    {
		        long fd = va_arg(ap_fuzz, long);
		        const char* buf = va_arg(ap_fuzz, const char*);
		        size_t count = va_arg(ap_fuzz, size_t);
		        off_t offset = va_arg(ap_fuzz, off_t);
		        snprintf(buff, BUFF_SIZE, "pwrite,%ld,buff,%ld,%lld",
		                 fd, count, (long long)offset);
		        msg_len = strlen(buff);
		        break;
		    }
		    default:
		        // handle unrecognized syscall
		        va_end(ap_fuzz);
		        goto passthrough_syscall;
		        break;
		}
		log_always("Interception for %ld, args: %d", nr);
		va_end(ap_fuzz);
		log_always("MSG TO SEND %s", buff);
        ret = DO_SYSCALL_ORIG(
        	sendto, sock_fd,
        	buff, msg_len,
        	0, (struct sockaddr *) &sv_addr,
        	sizeof(struct sockaddr_un)
        );
        
        if (ret != msg_len) {
        	log_error("send failed: %d != %d", msg_len, ret);
			DO_SYSCALL_ORIG(exit);
        }

        for (int i = 0; i < BUFF_SIZE; i++) {
	    	buff[i] = 0;
	    }


        ret = DO_SYSCALL_ORIG(
        	recvfrom, sock_fd, buff, BUFF_SIZE, 0, NULL, NULL
        );
        /* Or equivalently: numBytes = recv(sfd, resp, BUF_SIZE, 0);
                        or: numBytes = read(sfd, resp, BUF_SIZE); */
        if (ret == -1) {
            log_error("recvfrom error");
            DO_SYSCALL_ORIG(exit);
        }

		log_always("DONE: %ld", ((long*)buff)[0]);
		on_syscall = 0;
		return ((long*)buff)[0];


		// static FuzzDriver* driver = NULL;
		// if (!driver) {
		// 	driver = create_fuzz_driver();
		// }
	}

passthrough_syscall:
	
	on_syscall = 0;

	switch (num_args)
	{
		case 0:
			ret = DO_SYSCALL_ORIG_BY_NUM(nr);
			break;
		case 1:
			ret = DO_SYSCALL_ORIG_BY_NUM(nr, va_arg(ap, long));
			break;
		case 2:
			ret = DO_SYSCALL_ORIG_BY_NUM(
				nr,
				va_arg(ap, long),
				va_arg(ap, long)
			);
			break;
		case 3:
			ret = DO_SYSCALL_ORIG_BY_NUM(
				nr,
				va_arg(ap, long),
				va_arg(ap, long),
				va_arg(ap, long)
			);
			break;
		case 4:
			ret = DO_SYSCALL_ORIG_BY_NUM(
				nr,
				va_arg(ap, long),
				va_arg(ap, long),
				va_arg(ap, long),
				va_arg(ap, long)
			);
			break;
		case 5:
			ret = DO_SYSCALL_ORIG_BY_NUM(
				nr,
				va_arg(ap, long),
				va_arg(ap, long),
				va_arg(ap, long),
				va_arg(ap, long),
				va_arg(ap, long)
			);
			break;
		case 6:
			ret = DO_SYSCALL_ORIG_BY_NUM(
				nr,
				va_arg(ap, long),
				va_arg(ap, long),
				va_arg(ap, long),
				va_arg(ap, long),
				va_arg(ap, long),
				va_arg(ap, long)
			);
			break;
	}
    va_end(ap);
	return ret;
}
