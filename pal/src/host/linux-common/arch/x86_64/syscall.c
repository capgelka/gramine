#include <stdarg.h>
#include "syscall.h"
#include "log.h"

#define socket socket_orig
#include <sys/socket.h>
#undef socket

#include "api.h"
#include "base64.h"
#include <sys/un.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#define CLIENT_SOCK "/tmp/fuzz_client_sock"
#define SERVER_SOCK "/tmp/fuzz_server_sock"
#define BUFF_SIZE 8192
#define REGISTER_SIZE 8
#define DESCRIPTORS_TO_RESERVE 50
#define SYSCALL_TO_SWITCH SYS_mkdir
#define ARG_TO_SWITCH "/message1234"

#ifdef FUZZER
int g_start_interception = 1;
#else
int g_start_interception = 0;
#endif


static int init_socket(struct sockaddr_un* cl_addr, struct sockaddr_un* sv_addr)
{
    DO_SYSCALL_ORIG(unlink, CLIENT_SOCK);
    int sock_fd = DO_SYSCALL_ORIG(socket, AF_UNIX, SOCK_DGRAM, 0);
    if (sock_fd < 0) {
        log_error("FAILED TO OPEN FILE TO WRITE DATA FOR AGENT");
        abort();
    }

    for (size_t i = 0; i < sizeof(struct sockaddr_un); i++) {
        ((char*)cl_addr)[i] = 0;
        ((char*)sv_addr)[i] = 0;
    }

    cl_addr->sun_family = AF_UNIX;
    memcpy(cl_addr->sun_path, CLIENT_SOCK, sizeof(CLIENT_SOCK));

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
    memcpy(sv_addr->sun_path, SERVER_SOCK, sizeof(SERVER_SOCK));
    return sock_fd;
}

static void show_stats(const struct stat* stats)
{
    // Print the file information
    log_always("Size: %ld bytes\n", stats->st_size);
    log_always("Permissions: %o\n", stats->st_mode);
    log_always("Owner UID: %d\n", stats->st_uid);
    log_always("Group GID: %d\n", stats->st_gid);
    log_always("Last access: %ld\n", stats->st_atime);
    log_always("Last modification: %ld\n", stats->st_mtime);
    log_always("Last status change: %ld\n", stats->st_ctime);
}

__attribute_no_stack_protector
inline long do_syscall_wrapped(long nr, int num_args, ...)
{
    static int sock_fd = 0;
    static struct sockaddr_un cl_addr = { .sun_family = AF_UNIX };
    static struct sockaddr_un sv_addr = { .sun_family = AF_UNIX };
    static int on_syscall = 0;
    static int not_handle = 0;
    static int enable_hooks = 0;
    static int use_urandom = 0;
    static char buff[BUFF_SIZE] = {0};
    static int dst[DESCRIPTORS_TO_RESERVE] = {0};

    va_list ap;
    va_start(ap, num_args);

    int need_encode = 0;
    int ret = 0;

    if (nr == SYS_open) {
       va_list ap_copy;
       va_copy(ap_copy, ap);

       char* path = va_arg(ap_copy, char*);
       va_end(ap_copy);

       if (!strcmp(path, "/dev/urandom")) {
          use_urandom = 1;
          goto internal_syscall;
       }
   }
    if (g_start_interception && !on_syscall) {

        if (nr == SYS_exit) {
            goto internal_syscall;
        }

        if (nr == SYS_open) {
            va_list ap_copy;
            va_copy(ap_copy, ap);

            char* path = va_arg(ap_copy, char*);
            va_end(ap_copy);

            if (!strcmp(path, "/dev/urandom")) {
               log_always("Use Urandom!");
               use_urandom = 1;
               goto internal_syscall;
            }
            else {
                log_always("NOT RANDOM: %s", path);
            }
        }

        if (!enable_hooks && (nr == SYSCALL_TO_SWITCH)) {
            va_list ap_copy;
            va_copy(ap_copy, ap);
            // int fd = va_arg(ap_copy, int);
            char* msg = va_arg(ap_copy, char*);
            if (strstr(msg, ARG_TO_SWITCH)) {
                enable_hooks = 1;
                not_handle = 0;
                on_syscall = 0;
                log_always("Hooking enabled on syscall %ld\n\n\n", nr);
                va_end(ap_copy);
                return 0;
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

        if (on_syscall || not_handle) {
            goto internal_syscall;
        }

        not_handle = 1;

        if (!enable_hooks) {
    
            not_handle = 0;
            log_debug("No Interception for %lu", nr);
            goto passthrough_syscall;
        }

        if (!sock_fd) {
            int count = DESCRIPTORS_TO_RESERVE;
            while (count-->0) {
                dst[count] = DO_SYSCALL_ORIG(
                    open, "/tmp/tmpp",
                    O_RDWR | O_CREAT,
                    0777
                );
                on_syscall = 1;
            }

            on_syscall = 1;
            sock_fd = init_socket(&cl_addr, &sv_addr);
            log_debug("Received sock_fd value: %d", sock_fd);
            on_syscall = 0;
            

            for (int i = 0; i < DESCRIPTORS_TO_RESERVE; i++) {
                DO_SYSCALL_ORIG(close, dst[i]);
            }
        }

        not_handle = 0;
        on_syscall = 1;

        size_t msg_len = 0;

        va_list ap_fuzz;
        va_copy(ap_fuzz, ap);
        char* buf = NULL;
        for (size_t i = 0; i < BUFF_SIZE; i++) {
            buff[i] = 0;
        }
        switch (nr)
        {
            case SYS_read:
            {
                long fd = va_arg(ap_fuzz, long);
                if (fd == 3 && use_urandom) {
                    log_always("skipping hook for urandom read");
                    goto passthrough_syscall;
                }
                buf = va_arg(ap_fuzz, char*);
                size_t count = va_arg(ap_fuzz, size_t);
                snprintf(buff, BUFF_SIZE, "read,%ld,buff,%ld",
                         fd, count);
                break;
            }
            case SYS_write:
            {
                long fd = va_arg(ap_fuzz, long);
                buf = (char*) va_arg(ap_fuzz, const char*);
                size_t count = va_arg(ap_fuzz, size_t);
                snprintf(buff, BUFF_SIZE, "write,%ld,buff,%ld,",
                         fd, count);
                need_encode = count;
                break;
            }
            case SYS_open:
            {
                const char* filename = va_arg(ap_fuzz, const char*);
                int flags = va_arg(ap_fuzz, long);
                mode_t mode = va_arg(ap_fuzz, long);
                snprintf(buff, BUFF_SIZE, "open,%s,%d,%d",
                         filename, flags, mode);
                break;
            }
            case SYS_openat:
            case SYS_openat2:
            {
                abort();
               // const char* filename = va_arg(ap_fuzz, const char*);
               // int flags = va_arg(ap_fuzz, long);
               // mode_t mode = va_arg(ap_fuzz, long);
               // snprintf(buff, BUFF_SIZE, "open,%s,%d,%d",
               //          filename, flags, mode);
               // break;
            }
            case SYS_close:
            {
                long fd = va_arg(ap_fuzz, long);
                snprintf(buff, BUFF_SIZE, "close,%ld", fd);
                break;
            }    
            case SYS_rmdir:
            {
                const char* filename = va_arg(ap_fuzz, const char*);
                snprintf(buff, BUFF_SIZE, "rmdir,%s", filename);
                break;
            }
            case SYS_unlink:
            {
                const char* filename = va_arg(ap_fuzz, const char*);
                snprintf(buff, BUFF_SIZE, "unlink,%s", filename);
                break;
            }
            case SYS_chdir:
            {
                const char* filename = va_arg(ap_fuzz, const char*);
                snprintf(buff, BUFF_SIZE, "chdir,%s", filename);
                break;
            }
            case SYS_mkdir:
            {
                const char* filename = va_arg(ap_fuzz, const char*);
                mode_t mode = va_arg(ap_fuzz, mode_t);
                snprintf(buff, BUFF_SIZE, "mkdir,%s,%d", filename, mode);
                break;
            }
            case SYS_rename:
            {
                const char* filename = va_arg(ap_fuzz, const char*);
                const char* filename_new = va_arg(ap_fuzz, const char*);
                snprintf(buff, BUFF_SIZE, "rename,%s,%s", filename, filename_new);
                break;
            }      
            case SYS_access:
            {
                const char* filename = va_arg(ap_fuzz, const char*);
                mode_t mode = va_arg(ap_fuzz, mode_t);
                snprintf(buff, BUFF_SIZE, "access,%s,%d", filename, mode);
                break;
            }
            case SYS_lseek:
            {
                long fd = va_arg(ap_fuzz, long);
                off_t offset = va_arg(ap_fuzz, off_t);
                int whence = va_arg(ap_fuzz, int);
                snprintf(buff, BUFF_SIZE, "lseek,%ld,%lld,%d",
                         fd, (long long)offset, whence);
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
                break;
            }
            case SYS_pwrite64:
            {
                long fd = va_arg(ap_fuzz, long);
                buf = (char*) va_arg(ap_fuzz, const char*);
                size_t count = va_arg(ap_fuzz, size_t);
                off_t offset = va_arg(ap_fuzz, off_t);
                snprintf(buff, BUFF_SIZE, "pwrite,%ld,buff,%ld,%lld,",
                         fd, count, (long long)offset);
                need_encode = count;
                break;
            }
            case SYS_fstat:
            {
                long fd = va_arg(ap_fuzz, long);
                buf = (char*) va_arg(ap_fuzz, const struct stat*);
                snprintf(buff, BUFF_SIZE, "fstat,%ld,buff", fd);
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
                break;
            }
            case SYS_ftruncate:
            {
                long fd = va_arg(ap_fuzz, long);
                off_t size = va_arg(ap_fuzz, off_t);
                snprintf(buff, BUFF_SIZE, "ftruncate,%ld,%ld", fd, size);
                break;
            }
            case SYS_fchmod:
            {
                long fd = va_arg(ap_fuzz, long);
                mode_t mode = va_arg(ap_fuzz, mode_t);
                snprintf(buff, BUFF_SIZE, "fchmod,%ld,%u", fd, mode);
                break;
            }
            case SYS_chmod:
            {
                const char* filename = va_arg(ap_fuzz, const char*);
                mode_t mode = va_arg(ap_fuzz, mode_t);
                snprintf(buff, BUFF_SIZE, "chmod,%s,%u", filename, mode);
                break;
            }
            default:
                // handle unrecognized syscall
                va_end(ap_fuzz);
                log_always("Syscall %ld is unsupported by GK", nr);
                goto internal_syscall;
                break;
        }
        log_always("Interception for %ld", nr);
        va_end(ap_fuzz);

        msg_len = strlen(buff);

        if (need_encode) {
            Base64encode(buff + msg_len, buf, need_encode);
        }

        msg_len = strlen(buff);

        log_always("Message to send: %s | len: %zu", buff, msg_len);

        ret = DO_SYSCALL_ORIG(
            sendto, sock_fd,
            buff, msg_len,
            0, (struct sockaddr *) &sv_addr,
            sizeof(struct sockaddr_un)
        );
        
        if (ret != (int) msg_len) {
            log_error("send failed: %zu != %d", msg_len, ret);
            abort();
        }

        for (int i = 0; i < BUFF_SIZE; i++) {
            buff[i] = 0;
        }

        log_debug("Waiting for result for nr: %ld", nr);

        ret = DO_SYSCALL_ORIG(
            recvfrom, sock_fd, buff, BUFF_SIZE, 0, NULL, NULL
        );

        if (ret <= 0) {
            log_error("recvfrom error");
            abort();
        }

        log_debug("RET SIZE: %d", ret);
        size_t offset = ret - REGISTER_SIZE;
        if (offset > 0) {
            if (!buf) {
                log_error("No buf available!");
            }
            for (int i = 0; i < ret - REGISTER_SIZE; i++) {
                buf[i] = buff[i];
            }
        } else {
            offset = 0;
        }
        char* buff2 = buff + offset;
        long val = *(long*)buff2;

        log_always("Syscall result: %ld", val);
        if (nr == SYS_fstat || nr == SYS_lstat || nr == SYS_stat) {
            show_stats((struct stat*) buf);
        }
        on_syscall = 0;
        return val;

    }

passthrough_syscall:
    on_syscall = 0;

internal_syscall:
    on_syscall = 0;
    long arg1 = 0;
    long arg2 = 0;
    long arg3 = 0;
    long arg4 = 0;
    long arg5 = 0;
    long arg6 = 0;
    switch (num_args)
    {
        case 0:
            va_end(ap);
            return DO_SYSCALL_0(nr);
        case 1:
            va_end(ap);
            arg1 = va_arg(ap, long);
            return DO_SYSCALL_1(nr, arg1);
        case 2:
            arg1 = va_arg(ap, long);
            arg2 = va_arg(ap, long);
            va_end(ap);
            return DO_SYSCALL_2(
                nr,
                arg1,
                arg2
            );
        case 3:
            arg1 = va_arg(ap, long);
            arg2 = va_arg(ap, long);
            arg3 = va_arg(ap, long);
            va_end(ap);
            return DO_SYSCALL_3(
                nr,
                arg1,
                arg2,
                arg3
            );
        case 4:
            arg1 = va_arg(ap, long);
            arg2 = va_arg(ap, long);
            arg3 = va_arg(ap, long);
            arg4 = va_arg(ap, long);
            va_end(ap);
            return DO_SYSCALL_4(
                nr,
                arg1,
                arg2,
                arg3,
                arg4
            );
        case 5:
            arg1 = va_arg(ap, long);
            arg2 = va_arg(ap, long);
            arg3 = va_arg(ap, long);
            arg4 = va_arg(ap, long);
            arg5 = va_arg(ap, long);
            va_end(ap);
            return DO_SYSCALL_5(nr, arg1, arg2, arg3, arg4, arg5);
        case 6:
            arg1 = va_arg(ap, long);
            arg2 = va_arg(ap, long);
            arg3 = va_arg(ap, long);
            arg4 = va_arg(ap, long);
            arg5 = va_arg(ap, long);
            arg6 = va_arg(ap, long);
            va_end(ap);
            return DO_SYSCALL_6(
                nr,
                arg1,
                arg2,
                arg3,
                arg4,
                arg5,
                arg6
            );
    }
    return ret;
}
