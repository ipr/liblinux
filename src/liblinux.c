/*
 * liblinux.c 
 * 3-clause BSD-license, see LICENSE for details
 * 
 * Ilkka Prusi <ilkka.prusi@gmail.com> 2018
 */
#include "liblinux.h"

#include <linux/unistd.h>
#include <sys/syscall.h>

/* syscall number: 39 */
long getpid()
{
    return syscall(SYS_getpid);
}
