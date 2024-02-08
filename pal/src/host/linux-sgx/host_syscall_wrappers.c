#include <stdarg.h>
#include "syscall.h"
#include "host_syscall.h"

#include "log.h"

#define socket socket_orig
#include <sys/socket.h>
#undef socket


#include "api.h"
#include "base64.h"
#include <sys/un.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <linux/futex.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdatomic.h>



#define CLIENT_SOCK "/tmp/fuzz_client_sock"
#define SERVER_SOCK "/tmp/fuzz_server_sock"
#define BUFF_SIZE 8192
#define REGISTER_SIZE 8
#define DESCRIPTORS_TO_RESERVE 50
#define SYSCALL_TO_SWITCH SYS_write
#define ARG_TO_SWITCH "message1234"


#define MAP_ANONYMOUS        0x20   

#define SHARED_MEM_SIZE 8192

int g_shm_fd_out;
int g_shm_fd_in;
int g_shm_fd;
char volatile * g_shared_memory_in = NULL;
char volatile * g_shared_memory_out = NULL;
char volatile * g_shared_memory = NULL;


static void init_shm() {
    // g_shm_fd = DO_SYSCALL(memfd_create, SHARED_MEM_NAME, 0);
    g_shm_fd = DO_SYSCALL(open, "/dev/shm/shm_interface", O_RDWR);
    // g_shm_fd_out = DO_SYSCALL(open, "/dev/shm/to_agent", O_RDWR);
    // g_shm_fd_in = DO_SYSCALL(open, "/dev/shm/from_agent", O_RDWR);
    // g_shared_memory_out = (char*) DO_SYSCALL(
    //     mmap, NULL, SHARED_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd_out, 0
    // );
    //  g_shared_memory_in = (char*) DO_SYSCALL(
    //     mmap, NULL, SHARED_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd_in, 0
    // );
    g_shared_memory = (char*) DO_SYSCALL(
        mmap, NULL, SHARED_MEM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd, 0
    );
}

static void send_msg(char* msg, size_t size) {
    char volatile *spinlock = g_shared_memory;
    char volatile *gramine_interested = g_shared_memory + 1;
    char volatile *agent_interested = g_shared_memory + 2;
    char volatile *gramine_done = g_shared_memory + 3;
    char volatile *agent_done = g_shared_memory + 4;

    char volatile *shared_memory = agent_done + 1;

    log_error("Send before lock, lock: %d, agent_interested: %d, size: %d",
        *spinlock, *agent_interested, (shared_memory + sizeof(size_t))[0]
    );
    *gramine_interested = 1;
    while (__sync_lock_test_and_set(spinlock, 1) != 0) {
        log_error("Send waiting lock, lock: %d, agent_interested: %d, size: %d",
               *spinlock, *agent_interested, (shared_memory + sizeof(size_t))[0]
           );
    }
    log_error("Send lock, locked!: %d, agent_interested: %d, size: %d",
               *spinlock, *agent_interested, (shared_memory + sizeof(size_t))[0]
           );


    ((size_t*)shared_memory)[0] = size;
    memcpy(shared_memory + sizeof(size_t), msg, size);
    log_error("HERE IS THE PROOF: %s", shared_memory +sizeof(size_t));
    *gramine_done = 1;
    *gramine_interested = 0;
    *spinlock = 0;
}


static int recieve_msg(char* buff) {
    char volatile *spinlock = g_shared_memory;
    char volatile *gramine_interested = g_shared_memory + 1;
    char volatile *agent_interested = g_shared_memory + 2;
    char volatile *gramine_done = g_shared_memory + 3;
    char volatile *agent_done = g_shared_memory + 4;

    char volatile *shared_memory = agent_done + 1;


    log_error("Receive before lock, lock: %d, agent_done: %d, size: %d",
        *spinlock, *agent_done, (shared_memory + sizeof(size_t))[0]
    );
    *gramine_interested = 1;

    while (*agent_done != 1) {
        ;
    }

    while ((__sync_lock_test_and_set(spinlock, 1) != 0)) {
        ;
    }
         log_error("Receive lock, locked!: %d, agent_done: %d, size: %d",
               *spinlock, *agent_done, (shared_memory + sizeof(size_t))[0]
           );

    size_t size = *((size_t*)shared_memory);
    memcpy(buff, shared_memory + sizeof(size_t), size);
    *gramine_interested = 0;
    *agent_done = 0;
    *spinlock = 0;
    return size;
}


// static void send_msg(char* msg, size_t size) {
//     int volatile *spinlock = (int *)g_shared_memory_out;
//     int volatile *ready = (int*) (g_shared_memory_out + sizeof(int));
//     char volatile *shared_memory = g_shared_memory_out + 2 * sizeof(int);

//     log_error("Send before lock, lock: %d, ready: %d, size: %d",
//         *spinlock, *ready, (shared_memory + sizeof(size_t))[0]
//     );
//     while (__sync_lock_test_and_set(spinlock, 1) != 0) {
//         log_error("Send waiting lock, lock: %d, ready: %d, size: %d",
//                *spinlock, *ready, (shared_memory + sizeof(size_t))[0]
//            );
//     }
//     log_error("Send lock, locked!: %d, ready: %d, size: %d",
//                *spinlock, *ready, (shared_memory + sizeof(size_t))[0]
//            );


//     ((size_t*)shared_memory)[0] = size;
//     memcpy(shared_memory + sizeof(size_t), msg, size);
//     log_error("HERE IS THE PROOF: %s", shared_memory +sizeof(size_t));
//     *ready = 1;
//     *spinlock = 0;
// }

// static int recieve_msg(char* buff) {
//     int volatile *spinlock = (int *)g_shared_memory_in;
//     int volatile *ready = (int*) (g_shared_memory_in + sizeof(int));
//     char volatile *shared_memory = g_shared_memory_in + 2 * sizeof(int);

//     log_error("Receive before lock, lock: %d, ready: %d, size: %d",
//         *spinlock, *ready, (shared_memory + sizeof(size_t))[0]
//     );
//     while ((__sync_lock_test_and_set(spinlock, 1) != 0) && (*ready == 1)) {
//           log_error("Receive waiting lock, lock: %d, ready: %d, size: %d",
//                *spinlock, *ready, (shared_memory + sizeof(size_t))[0]
//            );
//     }
//          log_error("Receive lock, locked!: %d, ready: %d, size: %d",
//                *spinlock, *ready, (shared_memory + sizeof(size_t))[0]
//            );

//     size_t size = *((size_t*)shared_memory);
//     memcpy(buff, shared_memory + sizeof(size_t), size);
//     *ready = 0;
//     *spinlock = 0;
//     return size;
// }



static int init_socket_int(struct sockaddr_un* cl_addr, struct sockaddr_un* sv_addr)
{
    DO_SYSCALL_INTERRUPTIBLE_ORIG(unlink, CLIENT_SOCK);
    int sock_fd = DO_SYSCALL_INTERRUPTIBLE_ORIG(socket, AF_UNIX, SOCK_DGRAM, 0);
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

    int ret = DO_SYSCALL_INTERRUPTIBLE_ORIG(
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
long do_syscall_intr_wrapped(long nr, ...)
{
    static _Thread_local int sock_fd = 0;
    static _Thread_local struct sockaddr_un cl_addr = { .sun_family = AF_UNIX };
    static _Thread_local struct sockaddr_un sv_addr = { .sun_family = AF_UNIX };
    static _Thread_local int on_syscall = 0;
    static _Thread_local int not_handle = 0;
    static _Thread_local int enable_hooks = 0;
    static _Thread_local int use_urandom = 0;
    static _Thread_local char buff[BUFF_SIZE] = {0};
    static _Thread_local int dst[DESCRIPTORS_TO_RESERVE] = {0};

    va_list ap;
    va_start(ap, nr);

    long arg1 = 0;
    long arg2 = 0;
    long arg3 = 0;
    long arg4 = 0;
    long arg5 = 0;
    long arg6 = 0;

    arg1 = va_arg(ap, long);
    arg2 = va_arg(ap, long);
    arg3 = va_arg(ap, long);
    arg4 = va_arg(ap, long);
    arg5 = va_arg(ap, long);
    arg6 = va_arg(ap, long);
    va_end(ap);

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

    if (!on_syscall) {

        if (nr == SYS_exit) {
            goto internal_syscall;
        }

        if (nr == SYS_open) {

            char* path = (char*) arg1;

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
            int fd = arg1;
            char* msg = (char*) arg2;
            if (fd == 1 && strstr(msg, ARG_TO_SWITCH)) {
                enable_hooks = 1;
                not_handle = 0;
                on_syscall = 0;
                log_always("Hooking enabled on syscall %ld\n\n\n", nr);
                return 0;
            }
        }

        if (nr == SYS_write) {
            long fd = arg1;

            if (fd == 1 || fd == 2) {
                goto internal_syscall;
            }
        }

        if (nr == SYS_fstat || 
            nr == SYS_lstat || 
            nr == SYS_ftruncate ||
            nr == SYS_close) {

            long fd = arg1;

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
                dst[count] = DO_SYSCALL_INTERRUPTIBLE_ORIG(
                    open, "/tmp/tmpp",
                    O_RDWR | O_CREAT,
                    0777
                );
                on_syscall = 1;
            }

            on_syscall = 1;
            sock_fd = init_socket_int(&cl_addr, &sv_addr);
            init_shm();
            log_debug("Received sock_fd value: %d", sock_fd);
            on_syscall = 0;
            

            for (int i = 0; i < DESCRIPTORS_TO_RESERVE; i++) {
                DO_SYSCALL_INTERRUPTIBLE_ORIG(close, dst[i]);
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
                long fd = arg1;
                if (fd == 3 && use_urandom) {
                    log_always("skipping hook for urandom read");
                    goto passthrough_syscall;
                }
                buf = (char*) arg2;
                size_t count = (size_t) arg3;
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
                const char* filename = (const char*) arg1;
                int flags = (int) arg2;
                mode_t mode = (mode_t) arg3;
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
                long fd = arg1;
                snprintf(buff, BUFF_SIZE, "close,%ld", fd);
                break;
            }    
            case SYS_rmdir:
            {
                const char* filename = (const char*) arg1;
                snprintf(buff, BUFF_SIZE, "rmdir,%s", filename);
                break;
            }
            case SYS_unlink:
            {
                const char* filename = (const char*) arg1;
                snprintf(buff, BUFF_SIZE, "unlink,%s", filename);
                break;
            }
            case SYS_chdir:
            {
                const char* filename = (const char*) arg1;
                snprintf(buff, BUFF_SIZE, "chdir,%s", filename);
                break;
            }
            case SYS_mkdir:
            {
                const char* filename = (const char*) arg1;
                mode_t mode = (mode_t) arg2;
                snprintf(buff, BUFF_SIZE, "mkdir,%s,%d", filename, mode);
                break;
            }
            case SYS_rename:
            {
                const char* filename = (const char*) arg1;
                const char* filename_new = (const char*) arg2;
                snprintf(buff, BUFF_SIZE, "rename,%s,%s", filename, filename_new);
                break;
            }      
            case SYS_access:
            {
                const char* filename = (const char*) arg1;
                mode_t mode = (mode_t) arg2;
                snprintf(buff, BUFF_SIZE, "access,%s,%d", filename, mode);
                break;
            }
            case SYS_lseek:
            {
                long fd = arg1;
                off_t offset = (off_t) arg2;
                int whence = (int) arg3;
                snprintf(buff, BUFF_SIZE, "lseek,%ld,%lld,%d",
                         fd, (long long)offset, whence);
                break;
            }
            case SYS_pread64:
            {
                long fd = arg1;
                buf = (char*) arg2;
                size_t count = (size_t) arg3;
                off_t offset = (off_t) arg4;
                snprintf(buff, BUFF_SIZE, "pread,%ld,buff,%ld,%lld",
                         fd, count, (long long)offset);
                break;
            }
            case SYS_pwrite64:
            {
                long fd = arg1;
                buf = (char*) arg2;
                size_t count = (size_t) arg3;
                off_t offset = (off_t) arg4;
                snprintf(buff, BUFF_SIZE, "pwrite,%ld,buff,%ld,%lld,",
                         fd, count, (long long)offset);
                need_encode = count;
                break;
            }
            case SYS_fstat:
            {
                long fd = arg1;
                buf = (char*) arg2;
                snprintf(buff, BUFF_SIZE, "fstat,%ld,buff", fd);
                break;
            }
            // we use lstat here just because have it implemented
            // and probably no difference in our examples
            case SYS_stat:
            case SYS_lstat:
            {
                const char* filename = (const char*) arg1;
                buf = (char*) arg2;
                snprintf(buff, BUFF_SIZE, "lstat,%s,buff", filename);
                break;
            }
            case SYS_ftruncate:
            {
                long fd = arg1;
                off_t size = (off_t) arg2;
                snprintf(buff, BUFF_SIZE, "ftruncate,%ld,%ld", fd, size);
                break;
            }
            case SYS_fchmod:
            {
                long fd = arg1;
                mode_t mode = (mode_t) arg2;
                snprintf(buff, BUFF_SIZE, "fchmod,%ld,%u", fd, mode);
                break;
            }
            case SYS_chmod:
            {
                const char* filename = (const char*) arg1;
                mode_t mode = (mode_t) arg2;
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

        // ret = DO_SYSCALL_INTERRUPTIBLE_ORIG(
        //     sendto, sock_fd,
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

        // ret = DO_SYSCALL_INTERRUPTIBLE_ORIG(
        //     recvfrom, sock_fd, buff, BUFF_SIZE, 0, NULL, NULL
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
        return DO_SYSCALL_INTERRUPTIBLE_ORIG_BY_NUM(
            nr,
            arg1,
            arg2,
            arg3,
            arg4,
            arg5,
            arg6
        );
}