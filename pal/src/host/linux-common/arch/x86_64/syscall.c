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
#include <unistd.h>
#include <fcntl.h>

#define CLIENT_SOCK "/tmp/fuzz_client_sock"
#define SERVER_SOCK "/tmp/fuzz_server_sock"
#define AGENT_INPUT "/tmp/fuzz_transport_input_"
#define AGENT_OUTPUT "/tmp/fuzz_transport_output_"
#define BUFF_SIZE 100
#define REGISTER_SIZE 8
#define DESCRIPTORS_TO_RESERVE 500
 
// typedef struct Driver FuzzDriver;

int g_start_interception = 0;

#define SYSCALL_TO_SWITCH SYS_write
#define ARG_TO_SWITCH "message1234"

static void on_enable()
{
	log_always("Set break on me");
}

static int init_socket(struct sockaddr_un* cl_addr, struct sockaddr_un* sv_addr)
{
	DO_SYSCALL_ORIG(unlink, CLIENT_SOCK);
	int sock_fd = DO_SYSCALL_ORIG(socket, AF_UNIX, SOCK_DGRAM, 0);
	if (sock_fd < 0) {
		log_error("FAILED TO OPEN FILE TO WRITE DATA FOR AGENT");
		abort();
	}

	for (int i = 0; i < sizeof(struct sockaddr_un); i++) {
    	((char*)cl_addr)[i] = 0;
    	((char*)sv_addr)[i] = 0;
    }

    cl_addr->sun_family = AF_UNIX;
    for (int i = 0; i <= sizeof(cl_addr->sun_path); i++) {
    	cl_addr->sun_path[i] = CLIENT_SOCK[i];
    }

    int ret = DO_SYSCALL_ORIG(
    	bind,
    	sock_fd,
    	(const struct sockaddr *) cl_addr,
        sizeof(struct sockaddr_un)
    );

    if (ret < 0) {
        log_error("Server is down: %d", ret);
        log_error("Path: |%s|", cl_addr->sun_path);
		abort();
	}

    sv_addr->sun_family = AF_UNIX;
    for (int i = 0; i < sizeof(sv_addr->sun_path); i++) {
    	sv_addr->sun_path[i] = SERVER_SOCK[i];
    }
	//log_always("New socket: %d", sock_fd);
    return sock_fd;
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

		if (nr == SYS_exit) {
			g_start_interception = 0;
			goto internal_syscall;
		}


		if (!enable_hooks && (nr == SYSCALL_TO_SWITCH)) {
	    	// log_always("HHOOK SPECIAL");
	    	va_list ap_copy;
	    	va_copy(ap_copy, ap);
	    	int fd = va_arg(ap_copy, int);
	    	char* msg = va_arg(ap_copy, char*);
	    	// log_always("!!!! fd: %d, msg: |%s|", fd, msg);
	    	if (fd == 1 && strstr(msg, ARG_TO_SWITCH)) {
		    	enable_hooks = 1;
		    	on_enable();
		    	not_handle = 0;
		    	on_syscall = 0;
		    	log_always("ENABLED!!!!! %ld \n", nr);
		//    	log_always("|%s|", msg);
		    	va_end(ap_copy);
//		    	goto passthrough_syscall;
		    	return 0;
	    	// } else {
	    	// 	log_always("GOOD ARG: %ld |CMP: %d",
	    	// 		nr, strcmp(msg, ARG_TO_SWITCH)
	    	// 	);
	    	// 	log_always("EXPECTED: %s | REAL: %s", ARG_TO_SWITCH, msg);
	    	}
	    	va_end(ap_copy);
	    }

		if (nr == SYS_write) {
			va_list ap_copy;
	    	va_copy(ap_copy, ap);

	    	long fd = va_arg(ap_copy, long);
	    	va_end(ap_copy);

	    	if (fd == 1 || fd == 2) {
	    		goto internal_syscall;
	    	}
		}

		if (nr == SYS_fstat || 
			nr == SYS_lstat || 
			nr == SYS_ftruncate ||
			nr == SYS_close) {
			va_list ap_copy;
	    	va_copy(ap_copy, ap);

	    	long fd = va_arg(ap_copy, long);
	    	va_end(ap_copy);

	    	if (fd == 0 || fd == 1 || fd == 2) {
	    		goto internal_syscall;
	    	}
		}

		// if (nr == SYS_close) {
		// 	va_list ap_copy;
	    // 	va_copy(ap_copy, ap);

	    // 	long fd = va_arg(ap_copy, long);
	    // 	va_end(ap_copy);

	    // 	if (fd == 0) {
	    // 		goto internal_syscall;
	    // 	}
		// }

		if (on_syscall || not_handle) {
			goto internal_syscall;
		}

		// handle logs. We assume our programs doesn't
		// do anythong importnt with stdout
		// if (enable_hooks && nr == SYS_write) {
		// 	va_list ap_copy;
	    // 	va_copy(ap_copy, ap);
	    // 	int fd = va_arg(ap_copy, int);
	    // 	if (fd == 2) {
	    // 		va_end(ap_copy);
	    // 		goto internal_syscall;
	    // 	}
	    // 	va_end(ap_copy);
		// }

		not_handle = 1;

	    if (!enable_hooks) {
	    	// long x = SYSCALL_TO_SWITCH;
	    	// log_always("CALL: %ld, args: %d | %ld (to switch)", nr, num_args, x);

	    	not_handle = 0;
			log_always("No Interception for %lu", nr);
	    	goto passthrough_syscall;
	    }

		if (!sock_fd) {
		    int count = DESCRIPTORS_TO_RESERVE;
		    int dst[DESCRIPTORS_TO_RESERVE] = {0};
		    while (count-->0) {
		        dst[count - 1] = DO_SYSCALL_ORIG(
		        	open, "/tmp/tmpp",
		        	O_RDWR | O_CREAT,
		        	0777
		        );
        	    on_syscall = 1;
		        // log_always("Opening dsc N %d: %d", count, dst[count]);
		    }

		    on_syscall = 1;
		    sock_fd = init_socket(&cl_addr, &sv_addr);
		    log_always("Received sock_fd value: %d", sock_fd);
		    on_syscall = 0;
		    

		    for (int i = 0; i < DESCRIPTORS_TO_RESERVE; i++) {
		    	// log_always("Closing dsc N %d: %d", i, dst[i]);
		        DO_SYSCALL_ORIG(close, dst[i]);
		    }
	    }

	    not_handle = 0;
	    on_syscall = 1;


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
    	char* buf = NULL;
        switch (nr)
		{
		    case SYS_read:
		    {
		        long fd = va_arg(ap_fuzz, long);
		        buf = va_arg(ap_fuzz, char*);
		        size_t count = va_arg(ap_fuzz, size_t);
		        snprintf(buff, BUFF_SIZE, "read,%ld,buff,%ld",
		                 fd, count);
		        msg_len = strlen(buff);
		        break;
		    }
		    case SYS_write:
		    {
		        long fd = va_arg(ap_fuzz, long);
		        buf = (char*) va_arg(ap_fuzz, const char*);
		        size_t count = va_arg(ap_fuzz, size_t);
		        snprintf(buff, BUFF_SIZE, "write,%ld,buff,%ld,%s",
		                 fd, count, buf);
		        msg_len = strlen(buff);
		        break;
    	    }
		    case SYS_open:
		    {
		        const char* filename = va_arg(ap_fuzz, const char*);
		        int flags = va_arg(ap_fuzz, long);
		        mode_t mode = va_arg(ap_fuzz, long);
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
		    case SYS_rmdir:
		    {
		        const char* filename = va_arg(ap_fuzz, const char*);
		        snprintf(buff, BUFF_SIZE, "rmdir,%s", filename);
		        msg_len = strlen(buff);
		        break;
		    }
		    case SYS_unlink:
		    {
		        const char* filename = va_arg(ap_fuzz, const char*);
		        snprintf(buff, BUFF_SIZE, "unlink,%s", filename);
		        msg_len = strlen(buff);
		        break;
		    }
		    case SYS_chdir:
		    {
		        const char* filename = va_arg(ap_fuzz, const char*);
		        snprintf(buff, BUFF_SIZE, "chdir,%s", filename);
		        msg_len = strlen(buff);
		        break;
		    }
		    case SYS_mkdir:
		    {
		        const char* filename = va_arg(ap_fuzz, const char*);
		        mode_t mode = va_arg(ap_fuzz, mode_t);
		        snprintf(buff, BUFF_SIZE, "mkdir,%s,%d", filename, mode);
		        msg_len = strlen(buff);
		        break;
		    }
			case SYS_rename:
		    {
		        const char* filename = va_arg(ap_fuzz, const char*);
		        const char* filename_new = va_arg(ap_fuzz, const char*);
		        snprintf(buff, BUFF_SIZE, "mkdir,%s,%s", filename, filename_new);
		        msg_len = strlen(buff);
		        break;
		    }	   
		    case SYS_access:
		    {
		        const char* filename = va_arg(ap_fuzz, const char*);
		        mode_t mode = va_arg(ap_fuzz, mode_t);
		        snprintf(buff, BUFF_SIZE, "access,%s,%d", filename, mode);
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
		        buf = va_arg(ap_fuzz, char*);
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
		        buf = (char*) va_arg(ap_fuzz, const char*);
		        size_t count = va_arg(ap_fuzz, size_t);
		        off_t offset = va_arg(ap_fuzz, off_t);
		        snprintf(buff, BUFF_SIZE, "pwrite,%ld,buff,%ld,%lld,%s",
		                 fd, count, (long long)offset, buf);
		        msg_len = strlen(buff);
		        break;
		    }
		    case SYS_fstat:
		    {
		        long fd = va_arg(ap_fuzz, long);
		        buf = (char*) va_arg(ap_fuzz, const struct stat*);
	            snprintf(buff, BUFF_SIZE, "fstat,%ld,buff", fd);
	            msg_len = strlen(buff);
	            break;
		    }
		    // we use lstat here just because have it implemented
		    // and probably no difference in our examples
		    case SYS_stat:
		    case SYS_lstat:
		    {
                const char* filename = va_arg(ap_fuzz, const char*);
		        buf = (char*) va_arg(ap_fuzz, const struct stat*);
	            snprintf(buff, BUFF_SIZE, "lstat,%s,buff", filename);
	            msg_len = strlen(buff);
	            break;
		    }
		    // case SYS_mmap:
		    // {
		    //     void* addr = va_arg(ap, void*);
		    //     size_t length = va_arg(ap, size_t);
		    //     int prot = va_arg(ap, int);
		    //     int flags = va_arg(ap, int);
		    //     int fd = va_arg(ap, int);
		    //     off_t offset = va_arg(ap, off_t);
	        //     snprintf(buff, BUFF_SIZE, "mmap,%p,%zu,%d,%d,%d,%lld",
	        //              ret, length, prot, flags, fd, (long long)offset);
	        //     msg_len = strlen(buff);
		    //     break;
		    // }
		    // case SYS_munmap:
		    // {
		    //     void* addr = va_arg(ap, void*);
		    //     size_t length = va_arg(ap, size_t);
	        //     snprintf(buff, BUFF_SIZE, "munmap,%p,%zu",
	        //              addr, length);
	        //     msg_len = strlen(buff);
		    //     break;
		    // }
		    case SYS_ftruncate:
		    {
		        long fd = va_arg(ap_fuzz, long);
		        off_t size = va_arg(ap_fuzz, off_t);
	            snprintf(buff, BUFF_SIZE, "ftruncate,%ld,%ld", fd, size);
	            msg_len = strlen(buff);
	            break;
		    }
		    default:
		        // handle unrecognized syscall
		        va_end(ap_fuzz);
		        log_always("Syscall %ld is unsupported by GK", nr);
		        goto internal_syscall;
		        break;
		}
		log_always("!!!!!!!! Interception for %ld", nr);
		va_end(ap_fuzz);
		log_always("MSG TO SEND %s", buff);

		// if (!sock_fd) {
			// sock_fd = DO_SYSCALL_ORIG(
			//   open,
			//   AGENT_INPUT,
		   	//   O_RDWR|O_CREAT|O_TRUNC,
		    //   0777
		    // );
			// // DO_SYSCALL_ORIG(unlink, CLIENT_SOCK);
			// // sock_fd = DO_SYSCALL_ORIG(socket, AF_UNIX, SOCK_DGRAM, 0);
			// // log_always("New socket: %d", sock_fd);
			// if (sock_fd < 0) {
			// 	log_error("FAILED TO OPEN FILE TO WRITE DATA FOR AGENT");
			// 	abort();
			// }

			// for (int i = 0; i < sizeof(struct sockaddr_un); i++) {
		    // 	((char*)&cl_addr)[i] = 0;
		    // }

		    // cl_addr.sun_family = AF_UNIX;
		    // for (int i = 0; i <= sizeof(cl_addr.sun_path); i++) {
		    // 	cl_addr.sun_path[i] = CLIENT_SOCK[i];
		    // }

    	    // ret = DO_SYSCALL_ORIG(
		    // 	bind,
		    // 	sock_fd,
		    // 	(const struct sockaddr *) &cl_addr,
	        //     sizeof(struct sockaddr_un)
	        // );

		    // if (ret < 0) {
		    //     log_error("Server is down: %d", ret);
		    //     log_error("Path: |%s|", cl_addr.sun_path);
			// 	abort();
			// }

	        // sv_addr.sun_family = AF_UNIX;
		    // for (int i = 0; i < sizeof(cl_addr.sun_path); i++) {
		    // 	sv_addr.sun_path[i] = SERVER_SOCK[i];
		    // }

		// } else {
		// 	log_error("File descriptor %d shouldn't be opened!", sock_fd);
		// 	abort();
		// }

		// ret = DO_SYSCALL_ORIG(write, sock_fd, buff, msg_len);
        ret = DO_SYSCALL_ORIG(
        	sendto, sock_fd,
        	buff, msg_len,
        	0, (struct sockaddr *) &sv_addr,
        	sizeof(struct sockaddr_un)
        );
        
        if (ret != msg_len) {
        	log_error("send failed: %zu != %d", msg_len, ret);
			abort();
        }

        for (int i = 0; i < BUFF_SIZE; i++) {
	    	buff[i] = 0;
	    }

	    // for (int i = 0; i < REGISTER_SIZE; i++) {
        // 	log_always("-> %d ",
        // 		((unsigned char*)buff)[i]
        // 	);
        // }
	    log_always("Waiting for result for nr: %ld", nr);
	    // int result_fd = DO_SYSCALL_ORIG(
		//     open,
		//     AGENT_OUTPUT,
	   	//     O_RDONLY,
	    //     0666
		// );

		// if (ret < 0) {
		// 	log_error("Failed to open for read");
		// 	abort();
		// }

		// ret = DO_SYSCALL_ORIG(read, result_fd, buf, BUFF_SIZE);
		// DO_SYSCALL_ORIG(ftruncate, result_fd);
		// DO_SYSCALL_ORIG(close, result_fd);

        ret = DO_SYSCALL_ORIG(
        	recvfrom, sock_fd, buff, BUFF_SIZE, 0, NULL, NULL
        );
        /* Or equivalently: numBytes = recv(sfd, resp, BUF_SIZE, 0);
                        or: numBytes = read(sfd, resp, BUF_SIZE); */
        if (ret <= 0) {
            log_error("recvfrom error");
            // abort();
            abort();
            log_error("SHOULD EXIT");
        }

        // if (DO_SYSCALL_ORIG(close, sock_fd) < 0) {
        // 	log_error("failed to close socket");
        // 	abort();
        // } else {
	    //     log_always("closed socket: %d", sock_fd);
        // }



	    // for (int i = 0; i < REGISTER_SIZE; i++) {
        // 	log_always("-> %d ",
        // 		((unsigned char*)buff)[i]
        // 	);
        // }

        log_always("RET SIZE: %d", ret);
        size_t offset = ret - REGISTER_SIZE;
        if (offset > 0) {
        	for (int i = 0; i < ret - REGISTER_SIZE; i++) {
        		buf[i] = buff[i];
        	}
        } else {
        	offset = 0;
        }
        char* buff2 = buff + offset;
        long val = *(long*)buff2;
        // log_always("buf: %p, new: %p, diff: %ld", buff, buff2,
        // 	(long)buff2 - (long)buff
        // );
        // for (int i = 0; i < REGISTER_SIZE; i++) {
        // 	log_always("-> %d | %d ",
        // 		((unsigned char*)buff2)[i], ((unsigned char*)buff)[i]
        // 	);
        // }
		log_always("===DONE===: %ld", val);
		on_syscall = 0;
		return val;


		// static FuzzDriver* driver = NULL;
		// if (!driver) {
		// 	driver = create_fuzz_driver();
		// }
	}

passthrough_syscall:
	on_syscall = 0;

internal_syscall:
	// 	if (g_start_interception) {
	// 	log_always("PASS111111111!!!");
	// }

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
