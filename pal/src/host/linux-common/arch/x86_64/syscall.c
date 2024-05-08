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
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>

#define CLIENT_SOCK "/tmp/fuzz_client_sock"
#define SERVER_SOCK "/tmp/fuzz_server_sock"
#define BUFF_SIZE 8192
#define REGISTER_SIZE 8
#define DESCRIPTORS_TO_RESERVE 50
#define SYSCALL_TO_SWITCH SYS_write
#define ARG_TO_SWITCH "message1234"


#define SHARED_MEM_SIZE 8192

int g_shm_fd1;
// extern char volatile g_shared_memory;
char volatile * g_shared_memory1 = NULL;

#ifdef FUZZER
int g_start_interception = 0;
#else
int g_start_interception = 0;
#endif


static void init_shm() {
    // g_shm_fd = DO_SYSCALL(memfd_create, SHARED_MEM_NAME, 0);
    g_shm_fd1 = DO_SYSCALL(open, "/dev/shm/shm_interface", O_RDWR);
    // g_shm_fd1_out = DO_SYSCALL(open, "/dev/shm/to_agent", O_RDWR);
    // g_shm_fd1_in = DO_SYSCALL(open, "/dev/shm/from_agent", O_RDWR);
    // g_shared_memory_out = (char*) DO_SYSCALL(
    //     mmap, NULL, SHARED_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd1_out, 0
    // );
    //  g_shared_memory_in = (char*) DO_SYSCALL(
    //     mmap, NULL, SHARED_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd1_in, 0
    // );
    g_shared_memory1 = (char*) DO_SYSCALL(
        mmap, NULL, SHARED_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd1, 0
    );
}

static void send_msg(char* msg, size_t size) {
    char volatile *spinlock = g_shared_memory1;
    char volatile *gramine_interested = g_shared_memory1 + 1;
    char volatile *start_interception = g_shared_memory1 + 2;
    char volatile *gramine_done = g_shared_memory1 + 3;
    char volatile *agent_done = g_shared_memory1 + 4;

    char volatile *shared_memory = agent_done + 1;

    *gramine_interested = 1;
    while (__sync_lock_test_and_set(spinlock, 1) != 0) {
        log_debug("Send waiting lock, lock: %d, start_interception: %d, size: %d",
               *spinlock, *start_interception, (shared_memory + sizeof(size_t))[0]
           );
    }

    ((size_t*)shared_memory)[0] = size;
    memcpy(shared_memory + sizeof(size_t), msg, size);
    // memcpy(
    //     shared_memory + sizeof(size_t) + size,
    //     0,
    //     SHARED_MEM_SIZE - (shared_memory + sizeof(size_t) + size - spinlock + 20)
    // );
    *(shared_memory + sizeof(size_t) + size) = 0;
    log_error("DO_SYSCALL sent: %s", shared_memory +sizeof(size_t));
    *gramine_done = 1;
    *gramine_interested = 0;
    *spinlock = 0;
}

static bool time_to_start() {
    // g_shared_memory1 = g_shared_memory;

    if (g_start_interception == 2) {
        // void** hardcoded_addr = 0x7fffffe93000;
        // if (*hardcoded_addr == NULL) {
        //     return false;
        // }
        return 1;
    } else {
        return 0;
    }
}


static int recieve_msg(char* buff) {
    char volatile *spinlock = g_shared_memory1;
    char volatile *gramine_interested = g_shared_memory1 + 1;
    char volatile *start_interception = g_shared_memory1 + 2;
    char volatile *gramine_done = g_shared_memory1 + 3;
    char volatile *agent_done = g_shared_memory1 + 4;

    char volatile *shared_memory = agent_done + 1;


    *gramine_interested = 1;

    while (*agent_done != 1) {
        ;
    }

    while ((__sync_lock_test_and_set(spinlock, 1) != 0)) {
        ;
    }

    size_t size = *((size_t*)shared_memory);
    memcpy(buff, shared_memory + sizeof(size_t), size);
    memset(shared_memory, 0, size + sizeof(size_t));
    log_always("DO_SYSCALL received %d bytes", size);
    *gramine_interested = 0;
    *agent_done = 0;
    *spinlock = 0;
    return size;
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
    static int shm_ready = 0;
    static struct sockaddr_un cl_addr = { .sun_family = AF_UNIX };
    static struct sockaddr_un sv_addr = { .sun_family = AF_UNIX };
    static int on_syscall = 0;
    static int not_handle = 0;
    static int enable_hooks = 0;
    static int start_time = 0;
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

    if ((g_start_interception == 2) && !on_syscall) {

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
            int fd = va_arg(ap_copy, int);
            char* msg = va_arg(ap_copy, char*);
            //log_always("Hooking CHECK ON NT %ld\n\n\n", nr);
            if ((fd == 2 || fd == 1) && strstr(msg, ARG_TO_SWITCH)) {
                enable_hooks = 1;
                not_handle = 0;
                on_syscall = 0;
                log_always("Hooking enabled on syscall %ld\n\n\n", nr);
                va_end(ap_copy);
                return 0;
            }
            // else if (g_start_interception == 2 && (fd == 2 || fd == 1)) {
            //     on_syscall = 1;
            //     log_always("MESSAHE MOT MATH: |%s| (fd: %d) %p", msg, fd, strstr(msg, ARG_TO_SWITCH));
            //     on_syscall = 0;
            // }
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
        //enable_hooks &= time_to_start();
        if (!enable_hooks) {
    
            not_handle = 0;
            log_debug("No Interception for %lu", nr);
            goto passthrough_syscall;
        }

        if (!shm_ready && time_to_start()) {
            on_syscall = 1;
            init_shm();
            shm_ready = 1;
            log_debug("Received    shm_ready value: %d",   shm_ready);
            on_syscall = 0;
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

        // ret = DO_SYSCALL_ORIG(
        //     sendto, shm_ready,
        //     buff, msg_len,
        //     0, (struct sockaddr *) &sv_addr,
        //     sizeof(struct sockaddr_un)
        // );
        send_msg(buff, msg_len);
        // if (ret != (int) msg_len) {
        //     log_error("send failed: %zu != %d", msg_len, ret);
        //     abort();
        // }

        for (int i = 0; i < BUFF_SIZE; i++) {
            buff[i] = 0;
        }

        log_debug("Waiting for result for nr: %ld", nr);

        // ret = DO_SYSCALL_ORIG(
        //     recvfrom,   shm_ready, buff, BUFF_SIZE, 0, NULL, NULL
        // );
        ret = recieve_msg(buff);
        // if (ret <= 0) {
        //     log_error("recvfrom error");
        //     abort();
        // }

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
