#pragma once

#include "syscall.h"

long do_syscall_intr(long nr, ...);
long do_syscall_intr_wrapped(long nr, ...);
void do_syscall_intr_after_check1(void);
void do_syscall_intr_after_check2(void);
void do_syscall_intr_eintr(void);

#ifdef FUZZER
	#define DO_SYSCALL_INTERRUPTIBLE(name, args...) do_syscall_intr_wrapped(__NR_##name, ##args)
	#define DO_SYSCALL_INTERRUPTIBLE_ORIG(name, args...) do_syscall_intr(__NR_##name, ##args)
	#define DO_SYSCALL_INTERRUPTIBLE_ORIG_BY_NUM(id, args...) do_syscall_intr(id, ##args)
#else
	#define DO_SYSCALL_INTERRUPTIBLE(name, args...) do_syscall_intr(__NR_##name, ##args)
#endif
