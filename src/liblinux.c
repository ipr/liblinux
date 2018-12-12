#include "liblinux.h"

#include <linux/unistd.h>
#include <sys/syscall.h>

long getpid()
{
    return syscall(SYS_getpid);
}
