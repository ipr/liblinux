/*
 * liblinux.c 
 * 3-clause BSD-license, see LICENSE for details
 * 
 * Ilkka Prusi <ilkka.prusi@gmail.com> 2018
 */
#include "liblinux.h"

#include <linux/unistd.h>
#include <linux/types.h>
#include <sys/syscall.h>

//0	
long read(unsigned int fd, char *buf, size_t count)
{
    return syscall(SYS_read, fd, buf, count);
}

//1	
long write(unsigned int fd, const char *buf, size_t count)
{
    return syscall(SYS_write, fd, buf, count);
}

//2	
long open(const char *filename, int flags, int mode)
{
    return syscall(SYS_open, filename, flags, mode);
}

//3	
long close(unsigned int fd)
{
    return syscall(SYS_close, fd);
}

//4	
long stat(const char *filename, struct stat *statbuf)
{
    return syscall(SYS_stat, filename, statbuf);
}

//5
long fstat(unsigned int fd, struct stat *statbuf)
{
    return syscall(SYS_fstat, fd, statbuf);
}

//6	
long lstat(const char *filename, struct stat *statbuf)
{
    return syscall(SYS_lstat, filename, statbuf);
}

//7	
long poll(struct poll_fd *ufds, unsigned int nfds, long timeout_msecs)
{
    return syscall(SYS_poll, ufds, nfds, timeout_msecs);
}

//8	
long lseek(unsigned int fd, off_t offset, unsigned int origin)
{
    return syscall(SYS_lseek, fd, offset, origin);
}

//9	
long mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off)
{
    return syscall(SYS_mmap, addr, len, prot, flags, fd, off);
}

//10	
long mprotect(unsigned long start, size_t len, unsigned long prot)
{
    return syscall(SYS_mprotect, start, len, prot);
}

//11
long munmap(unsigned long addr, size_t len)
{
    return syscall(SYS_munmap, addr, len);
}

//12
long brk(unsigned long brk)
{
    return syscall(SYS_brk, brk);
}

//13	
long rt_sigaction(int sig, const struct sigaction *act, struct sigaction *oact, size_t sigsetsize)
{
    return syscall(SYS_rt_sigaction, sig, act, oact, sigsetsize);
}

//14	
long rt_sigprocmask(int how, sigset_t *nset, sigset_t *oset, size_t sigsetsize)
{
    return syscall(SYS_rt_sigprocmask, how, nset, oset, sigsetsize);
}

//15	
long rt_sigreturn(unsigned long __unused)
{
    return syscall(SYS_rt_sigreturn, __unused);
}

//16	
long ioctl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    return syscall(SYS_ioctl, fd, cmd, arg);
}

//17
long pread64(unsigned long fd, char *buf, size_t count, loff_t pos)
{
    return syscall(SYS_pread64, fd, buf, count, pos);
}

//18	
long pwrite64(unsigned int fd, const char *buf, size_t count, loff_t pos)
{
    return syscall(SYS_pwrite64, fd, buf, count, pos);
}

//19	
long readv(unsigned long fd, const struct iovec *vec, unsigned long vlen)
{
    return syscall(SYS_readv, fd, vec, vlen);
}

//20	
long writev(unsigned long fd, const struct iovec *vec, unsigned long vlen)
{
    return syscall(SYS_writev, fd, vec, vlen);
}

//21	
long access(const char *filename, int mode)
{
    return syscall(SYS_access, filename, mode);
}

//22
long pipe(int *filedes)
{
    return syscall(SYS_pipe, filedes);
}

//23	
long select(int n, fd_set *inp, fd_set *outp, fd_set *exp, struct timeval *tvp)
{
    return syscall(SYS_select, n, inp, outp, exp, tvp);
}

//24	
long sched_yield()
{
    return syscall(SYS_sched_yield);
}    

//25	
long mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr)
{
    return syscall(SYS_mremap, addr, old_len, new_len, flags, new_addr);
}

//26	
long msync(unsigned long start, size_t len, int flags)
{
    return syscall(SYS_msync, start, len, flags);
}

//27	
long mincore(unsigned long start, size_t len, unsigned char *vec)
{
    return syscall(SYS_mincore, start, len, vec);
}

//28	
long madvise(unsigned long start, size_t len_in, int behavior)
{
    return syscall(SYS_madvise, start, len_in, behavior);
}

//29	
long shmget(key_t key, size_t size, int shmflg)
{
    return syscall(SYS_shmget, key, size, shmflg);
}

//30	
long shmat(int shmid, char *shmaddr, int shmflg)
{
    return syscall(SYS_shmat, shmid, shmaddr, shmflg);
}

//31	
long shmctl(int shmid, int cmd, struct shmid_ds *buf)
{
    return syscall(SYS_shmctl, shmid, cmd, buf);
}

//32	
long dup(unsigned int fildes)
{
    return syscall(SYS_dup, fildes);
}

//33	
long dup2(unsigned int oldfd, unsigned int newfd)
{
    return syscall(SYS_dup2, oldfd, newfd);
}

//34	
long pause()
{
    return syscall(SYS_pause);
}

//35	
long nanosleep(struct timespec *rqtp, struct timespec *rmtp)
{
    return syscall(SYS_nanosleep, rqtp, rmtp);
}

//36	
long getitimer(int which, struct itimerval *value)
{
    return syscall(SYS_getitimer, which, value);
}

//37	
long alarm(unsigned int seconds)
{
    return syscall(SYS_alarm, seconds);
}

//38	
long setitimer(int which, struct itimerval *value, struct itimerval *ovalue)
{
    return syscall(SYS_setitimer, which, value, ovalue);
}

//39	
long getpid()
{
    return syscall(SYS_getpid);
}

//40	
long sendfile(int out_fd, int in_fd, off_t *offset, size_t count)
{
    return syscall(SYS_sendfile, out_fd, in_fd, offset, count);
}

//41	
long socket(int family, int type, int protocol)
{
    return syscall(SYS_socket, family, type, protocol);
}

//42	
long connect(int fd, struct sockaddr *uservaddr, int addrlen)
{
    return syscall(SYS_connect, fd, uservaddr, addrlen);
}

//43	
long accept(int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen)
{
    return syscall(SYS_accept, fd, upeer_sockaddr, upeer_addrlen);
}

//44	
long sendto(int fd, void *buff, size_t len, unsigned flags, struct sockaddr *addr, int addr_len)
{
    return syscall(SYS_sendto, fd, buff, len, flags, addr, addr_len);
}

//45	
long recvfrom(int fd, void *ubuf, size_t size, unsigned flags, struct sockaddr *addr, int *addr_len)
{
    return syscall(SYS_recvfrom, fd, ubuf, size, flags, addr, addr_len);
}

//46	
long sendmsg(int fd, struct msghdr *msg, unsigned flags)
{
    return syscall(SYS_sendmsg, fd, msg, flags);
}

//47	
long recvmsg(int fd, struct msghdr *msg, unsigned int flags)
{
    return syscall(SYS_recvmsg, fd, msg, flags);
}

//48	
long shutdown(int fd, int how)
{
    return syscall(SYS_shutdown, fd, how);
}

//49	
long bind(int fd, struct sockaddr *umyaddr, int addrlen)
{
    return syscall(SYS_bind, fd, umyaddr, addrlen);
}

//50	
long listen(int fd, int backlog)
{
    return syscall(SYS_listen, fd, backlog);
}

//51	
long getsockname(int fd, struct sockaddr *usockaddr, int *usockaddr_len)
{
    return syscall(SYS_getsockname, fd, usockaddr, usockaddr_len);
}

//52	
long getpeername(int fd, struct sockaddr *usockaddr, int *usockaddr_len)
{
    return syscall(SYS_getpeername, fd, usockaddr, usockaddr_len);
}

//53	
long socketpair(int family, int type, int protocol, int *usockvec)
{
    return syscall(SYS_socketpair, family, type, protocol, usockvec);
}

//54	
long setsockopt(int fd, int level, int optname, char *optval, int optlen)
{
    return syscall(SYS_setsockopt, fd, level, optname, optval, optlen);
}

//55	
long getsockopt(int fd, int level, int optname, char *optval, int *optlen)
{
    return syscall(SYS_getsockopt, fd, level, optname, optval, optlen);
}

//56	
long clone(unsigned long clone_flags, unsigned long newsp, void *parent_tid, void *child_tid)
{
    return syscall(SYS_clone, clone_flags, newsp, parent_tid, child_tid);
}

//57	
long fork()
{
    return syscall(SYS_fork);
}

//58	
long vfork()
{
    return syscall(SYS_vfork);
}

//59	
long execve(const char *filename, const char *const argv[], const char *const envp[])
{
    return syscall(SYS_execve, filename, argv, envp);
}

//60	
long exit(int error_code)
{
    return syscall(SYS_exit, error_code);
}

//61	
long wait4(pid_t upid, int *stat_addr, int options, struct rusage *ru)
{
    return syscall(SYS_wait4, upid, stat_addr, options, ru);
}

//62	
long kill(pid_t pid, int sig)
{
    return syscall(SYS_kill, pid, sig);
}

//63	
long uname(struct old_utsname *name)
{
    return syscall(SYS_uname, name);
}

//64	
long semget(key_t key, int nsems, int semflg)
{
    return syscall(SYS_semget, key, nsmes, semflg);
}

//65	
long semop(int semid, struct sembuf *tsops, unsigned nsops)
{
    return syscall(SYS_semop, semid, tsops, nsops);
}

//66	
long semctl(int semid, int semnum, int cmd, union semun arg)
{
    return syscall(SYS_semctl, semid, semnum, cmd, arg);
}

//67	
long shmdt(char *shmaddr)
{
    return syscall(SYS_shmdt, shmaddr);
}

//68	
long msgget(key_t key, int msgflg)
{
    return syscall(SYS_msgget, key, msgflg);
}

//69	
long msgsnd(int msqid, struct msgbuf *msgp, size_t msgsz, int msgflg)
{
    return syscall(SYS_msgsnd, msqid, msgp, msgsz, msgflg);
}

//70	
long msgrcv(int msqid, struct msgbuf *msgp, size_t msgsz, long msgtyp, int msgflg)
{
    return syscall(SYS_msgrcv, msqid, msgp, msgsz, msgtyp, msgflg);
}

//71	
long msgctl(int msqid, int cmd, struct msqid_ds *buf)
{
    return syscall(SYS_msgctl, msqid, cmd, buf);
}

//72	
long fcntl(unsigned int fd, unsigned int cmd, unsigned long arg)
{
    return syscall(SYS_fcntl, fd, cmd, arg);
}

//73	
long flock(unsigned int fd, unsigned int cmd)
{
    return syscall(SYS_flock, fd, cmd);
}

//74	
long fsync(unsigned int fd)
{
    return syscall(SYS_fsync, fd);
}

//75	
long fdatasync(unsigned int fd)
{
    return syscall(SYS_fdatasync, fd);
}

//76	
long truncate(const char *path, long length)
{
    return syscall(SYS_truncate, path, length);
}

//77	
long ftruncate(unsigned int fd, unsigned long length)
{
    return syscall(SYS_ftruncate, fd, length);
}

//78	
long getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count)
{
    return syscall(SYS_getdents, fd, dirent, count);
}

//79	
long getcwd(char *buf, unsigned long size)
{
    return syscall(SYS_getcwd, buf, size);
}

//80	
long chdir(const char *filename)
{
    return syscall(SYS_chdir, filename);
}

//81	
long fchdir(unsigned int fd)
{
    return syscall(SYS_fchdir, fd);
}

//82	
long rename(const char *oldname, const char *newname)
{
    return syscall(SYS_rename, oldname, newname);
}

//83	
long mkdir(const char *pathname, int mode)
{
    return syscall(SYS_mkdir, pathname, mode);
}

//84	
long rmdir(const char *pathname)
{
    return syscall(SYS_rmdir, pathname);
}

//85	
long creat(const char *pathname, int mode)
{
    return syscall(SYS_creat, pathname, mode);
}

//86	
long link(const char *oldname, const char *newname)
{
    return syscall(SYS_link, oldname, newname);
}

//87	
long unlink(const char *pathname)
{
    return syscall(SYS_unlink, pathname);
}

//88	
long symlink(const char *oldname, const char *newname)
{
    return syscall(SYS_symlink, oldname, newname);
}

//89	
long readlink(const char *path, char *buf, int bufsiz)
{
    return syscall(SYS_readlink, path, buf, bufsiz);
}

//90	
long chmod(const char *filename, mode_t mode)
{
    return syscall(SYS_chmod, filename, mode);
}

//91	
long fchmod(unsigned int fd, mode_t mode)
{
    return syscall(SYS_fchmod, fd, mode);
}

//92	
long chown(const char *filename, uid_t user, gid_t group)
{
    return syscall(SYS_chown, filename, user, group);
}

//93	
long fchown(unsigned int fd, uid_t user, gid_t group)
{
    return syscall(SYS_fchown, fd, user, group);
}

//94	
long lchown(const char *filename, uid_t user, gid_t group)
{
    return syscall(SYS_lchown, filename, user, group);
}

//95	
long umask(int mask)
{
    return syscall(SYS_umask, mask);
}

//96	
long gettimeofday(struct timeval *tv, struct timezone *tz)
{
    return syscall(SYS_gettimeofday, tv, tz);
}

//97	
long getrlimit(unsigned int resource, struct rlimit *rlim)
{
    return syscall(SYS_getrlimit, resource, rlim);
}

//98	
long getrusage(int who, struct rusage *ru)
{
    return syscall(SYS_getrusage, who, ru);
}

//99	
long sysinfo(struct sysinfo *info)
{
    return syscall(SYS_sysinfo, info);
}

//100	
long times(struct sysinfo *info)
{
    return syscall(SYS_times, info);
}

//101	
long ptrace(long request, long pid, unsigned long addr, unsigned long data)
{
    return syscall(SYS_ptrace, request, pid, addr, data);
}

//102	
long getuid()
{
    return syscall(SYS_getuid);
}

//103	
long syslog(int type, char *buf, int len)
{
    return syscall(SYS_syslog, type, buf, len);
}

//104	
long getgid()
{
    return syscall(SYS_getgid);
}

//105	
long setuid(uid_t uid)
{
    return syscall(SYS_setuid, uid);
}

//106	
long setgid(gid_t gid)
{
    return syscall(SYS_setgid, gid);
}

//107	
long geteuid()
{
    return syscall(SYS_geteuid);
}

//108	
long getegid()
{
    return syscall(SYS_getegid);
}

//109	
long setpgid(pid_t pid, pid_t pgid)
{
    return syscall(SYS_setpgid, pid, pgid);
}

//110	
long getppid()
{
    return syscall(SYS_getppid);
}

//111	
long getpgrp()
{
    return syscall(SYS_getpgrp);
}

//112	
long setsid()
{
    return syscall(SYS_setsid);
}

//113	
long setreuid(uid_t ruid, uid_t euid)
{
    return syscall(SYS_setreuid, ruid, euid);
}

//114	
long setregid(gid_t rgid, gid_t egid)
{
    return syscall(SYS_setregid, rgid, egid);
}

//115	
long getgroups(int gidsetsize, gid_t *grouplist)
{
    return syscall(SYS_getgroups, gidsetsize, grouplist);
}

//116	
long setgroups(int gidsetsize, gid_t *grouplist)
{
    return syscall(SYS_setgroups, gidsetsize, grouplist);
}

//117	
long setresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
    return syscall(SYS_setresuid, ruid, euid, suid);
}

//118	
long getresuid(uid_t *ruid, uid_t *euid, uid_t *suid)
{
    return syscall(SYS_getresuid, ruid, euid, suid);
}

//119	
long setresgid(gid_t rgid, gid_t egid, gid_t sgid)
{
    return syscall(SYS_setresgid, rgid, egid, sgid);
}

//120	
long getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid)
{
    return syscall(SYS_getresgid, rgid, egid, sgid);
}

//121	
long getpgid(pid_t pid)
{
    return syscall(SYS_getpgid, pid);
}

//122	
long setfsuid(uid_t uid)
{
    return syscall(SYS_setfsuid, uid);
}

//123	
long setfsgid(gid_t gid)
{
    return syscall(SYS_setfsgid, gid);
}

//124	
long getsid(pid_t pid)
{
    return syscall(SYS_getsid, pid);
}

//125	
long capget(cap_user_header_t header, cap_user_data_t dataptr)
{
    return syscall(SYS_capget, header, dataptr);
}

//126	
long capset(cap_user_header_t header, const cap_user_data_t data)
{
    return syscall(SYS_capset, header, data);
}

//127	
long rt_sigpending(sigset_t *set, size_t sigsetsize)
{
    return syscall(SYS_rt_sigpending, set, sigsetsize);
}

//128	
long rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo, const struct timespec *uts, size_t sigsetsize)
{
    return syscall(SYS_rt_sigtimedwait, uthese, uinfo, uts, sigsetsize);
}

//129	
long rt_sigqueueinfo(pid_t pid, int sig	siginfo_t *uinfo)
{
    return syscall(SYS_rt_sigqueueinfo, pid, uinfo);
}

//130	
long rt_sigsuspend(sigset_t *unewset, size_t sigsetsize)
{
    return syscall(SYS_rt_sigsuspend, unewset, sigsetsize);
}

//131	
long sigaltstack(const stack_t *uss, stack_t *uoss)
{
    return syscall(SYS_sigaltstack, uss, uoss);
}

//132	
long utime(char *filename, struct utimbuf *times)
{
    return syscall(SYS_utime, filename, times);
}

//133	
long mknod(const char *filename, umode_t mode, unsigned dev)
{
    return syscall(SYS_mknod, filename, mode, dev);
}

//134	NOT IMPLEMENTED
long uselib()
{
    return syscall(SYS_uselib);
}					

//135	
long personality(unsigned int personality)
{
    return syscall(SYS_personality, personality);
}

//136	
long ustat(unsigned dev, struct ustat *ubuf)
{
    return syscall(SYS_ustat, dev, ubuf);
}

//137	
long statfs(const char *pathname, struct statfs *buf)
{
    return syscall(SYS_statfs, pathname, buf);
}

//138	
long fstatfs(unsigned int fd, struct statfs *buf)
{
    return syscall(SYS_fstatfs, fd, buf);
}

//139	
long sysfs(int option, unsigned long arg1, unsigned long arg2)
{
    return syscall(SYS_sysfs, option, arg1, arg2);
}

//140	
long getpriority(int which, int who)
{
    return syscall(SYS_getpriority, which, who);
}

//141	
long setpriority(int which, int who, int niceval)
{
    return syscall(SYS_setpriority, which, who, niceval);
}

//142	
long sched_setparam(pid_t pid, struct sched_param *param)
{
    return syscall(SYS_sched_setparam, pid, param);
}

//143	
long sched_getparam(pid_t pid, struct sched_param *param)
{
    return syscall(SYS_sched_getparam, pid, param);
}

//144	
long sched_setscheduler(pid_t pid, int policy, struct sched_param *param)
{
    return syscall(SYS_sched_setscheduler, pid, policy, param);
}

//145	
long sched_getscheduler(pid_t pid)
{
    return syscall(SYS_sched_getscheduler, pid);
}

//146	
long sched_get_priority_max(int policy)
{
    return syscall(SYS_sched_get_priority_max, policy);
}

//147	
long sched_get_priority_min(int policy)
{
    return syscall(SYS_sched_get_priority_min, policy);
}

//148	
long sched_rr_get_interval(pid_t pid, struct timespec *interval)
{
    return syscall(SYS_sched_rr_get_interval, pid, interval);
}

//149	
long mlock(unsigned long start, size_t len)
{
    return syscall(SYS_mlock, start, len);
}

//150	
long munlock(unsigned long start, size_t len)
{
    return syscall(SYS_munlock, start, len);
}

//151	
long mlockall(int flags)
{
    return syscall(SYS_mlockall, flags);
}

//152	
long munlockall()
{
    return syscall(SYS_munlockall);
}

//153	
long vhangup()
{
    return syscall(SYS_vhangup);
}

//154	
long modify_ldt(int func, void *ptr, unsigned long bytecount)
{
    return syscall(SYS_modify_ldt, func, ptr, bytecount);
}

//155	
long pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

//156	
long __sysctl(struct __sysctl_args *args)
{
    return syscall(SYS__sysctl, args);
}

//157	
long prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    return syscall(SYS_prctl, option, arg2, arg3, arg4, arg5);
}

//158	
long arch_prctl(struct task_struct *task, int code, unsigned long *addr)
{
    return syscall(SYS_arch_prctl, task, code, addr);
}

//159	
long adjtimex(struct timex *txc_p)
{
    return syscall(SYS_adjtimex, txc_p);
}

//160	
long setrlimit(unsigned int resource, struct rlimit *rlim)
{
    return syscall(SYS_setrlimit, resource, rlim);
}

//161	
long chroot(const char *filename)
{
    return syscall(SYS_chroot, filename);
}

//162	
long sync()
{
    return syscall(SYS_sync);
}

//163	
long acct(const char *name)
{
    return syscall(SYS_acct, name);
}

//164	
long settimeofday(struct timeval *tv, struct timezone *tz)
{
    return syscall(SYS_settimeofday, tv, tz);
}

//165	
long mount(char *dev_name, char *dir_name, char *type, unsigned long flags, void *data)
{
    return syscall(SYS_mount, dev_name, dir_name, type, flags, data);
}

//166	
long umount2(const char *target, int flags)
{
    return syscall(SYS_umount2, target, flags);
}

//167	
long swapon(const char *specialfile, int swap_flags)
{
    return syscall(SYS_swapon, specialfile, swap_flags);
}

//168	
long swapoff(const char *specialfile)
{
    return syscall(SYS_swapoff, specialfile);
}

//169	
long reboot(int magic1, int magic2, unsigned int cmd, void *arg)
{
    return syscall(SYS_reboot, magic1, magic2, cmd, arg);
}

//170	
long sethostname(char *name, int len)
{
    return syscall(SYS_sethostname, name, len);
}

//171	
long setdomainname(char *name, int len)
{
    return syscall(SYS_setdomainname, name, len);
}

//172	
long iopl(unsigned int level, struct pt_regs *regs)
{
    return syscall(SYS_iopl, level, regs);
}

//173	
long ioperm(unsigned long from, unsigned long num, int turn_on)
{
    return syscall(SYS_ioperm, from, num, turn_on);
}

//174	REMOVED IN Linux 2.6
long create_module()
{
    return syscall(SYS_create_module);
}

//175	
long init_module(void *umod, unsigned long len, const char *uargs)
{
    return syscall(SYS_init_module, umod, len, uargs);
}

//176	
long delete_module(const chat *name_user, unsigned int flags)
{
    return syscall(SYS_delete_module, name_user, flags);
}

//177	REMOVED IN Linux 2.6
long get_kernel_syms()
{
    return syscall(SYS_get_kernel_syms);
}

//178	REMOVED IN Linux 2.6
long query_module()
{
    return syscall(SYS_query_module);
}

//179	
long quotactl(unsigned int cmd, const char *special, qid_t id, void *addr)
{
    return syscall(SYS_quotactl, cmd, special, id, addr);
}

//180	NOT IMPLEMENTED
long nfsservctl()
{
    return syscall(SYS_nfsservctl);
}

//181	NOT IMPLEMENTED
long getpmsg()
{
    return syscall(SYS_getpmsg);
}

//182	NOT IMPLEMENTED
long putpmsg()
{
    return syscall(SYS_putpmsg);
}

//183	NOT IMPLEMENTED
long afs_syscall()
{
    return syscall(SYS_afs_syscall);
}

//184	NOT IMPLEMENTED
long tuxcall()
{
    return syscall(SYS_tuxcall);
}

//185	NOT IMPLEMENTED
long security()
{
    return syscall(SYS_security);
}

//186	
long gettid()
{
    return syscall(SYS_gettid);
}

//187	
long readahead(int fd, loff_t offset, size_t count)
{
    return syscall(SYS_readahead, fd, offset, count);
}

//188	
long setxattr(const char *pathname, const char *name, const void *value, size_t size, int flags)
{
    return syscall(SYS_setxattr, pathname, name, value, size, flags);
}

//189	
long lsetxattr(const char *pathname, const char *name, const void *value, size_t size, int flags)
{
    return syscall(SYS_lsetxattr, pathname, name, value, size, flags);
}

//190	
long fsetxattr(int fd, const char *name, const void *value, size_t size, int flags)
{
    return syscall(SYS_fsetxattr, fd, name, value, size, flags);
}

//191	
long getxattr(const char *pathname, const char *name, void *value, size_t size)
{
    return syscall(SYS_getxattr, pathname, name, value, size);
}

//192	
long lgetxattr(const char *pathname, const char *name, void *value, size_t size)
{
    return syscall(SYS_lgetxattr, pathname, name, value, size);
}

//193	
long fgetxattr(int fd, const char *name, void *value, size_t size)
{
    return syscall(SYS_fgetxattr, fd, name, value, size);
}

//194	
long listxattr(const char *pathname, char *list, size_t size)
{
    return syscall(SYS_listxattr, pathname, list, size);
}

//195	
long llistxattr(const char *pathname, char *list, size_t size)
{
    return syscall(SYS_llistxattr, pathname, list, size);
}

//196	
long flistxattr(int fd, char *list, size_t size)
{
    return syscall(SYS_flistxattr, fd, list, size);
}

//197	
long removexattr(const char *pathname, const char *name)
{
    return syscall(SYS_removexattr, pathname, name);
}

//198	
long lremovexattr(const char *pathname, const char *name)
{
    return syscall(SYS_lremovexattr, pathname, name);
}

//199	
long fremovexattr(int fd, const char *name)
{
    return syscall(SYS_fremovexattr, fd, name);
}

//200	
long tkill(pid_t pid, ing sig)
{
    return syscall(SYS_tkill, pid, sig);
}

//201	
long time(time_t *tloc)
{
    return syscall(SYS_time, tloc);
}

//202	
long futex(u32 *uaddr, int op, u32 val, struct timespec *utime, u32 *uaddr2, u32 val3)
{
    return syscall(SYS_futex, uaddr, op, val, utime, uaddr2, val3);
}

//203	
long sched_setaffinity(pid_t pid, unsigned int len, unsigned long *user_mask_ptr)
{
    return syscall(SYS_sched_setaffinity, pid, len, user_mask_ptr);
}

//204	
long sched_getaffinity(pid_t pid, unsigned int len, unsigned long *user_mask_ptr)
{
    return syscall(SYS_sched_getaffinity, pid, len, user_mask_ptr);
}

//205	NOT IMPLEMENTED. Use arch_prctl
long set_thread_area()
{
    return syscall(SYS_set_thread_area);
}

//206	
long io_setup(unsigned nr_events, aio_context_t *ctxp)
{
    return syscall(SYS_io_setup, nr_events, ctxp);
}

//207	
long io_destroy(aio_context_t ctx)
{
    return syscall(SYS_io_destroy, ctx);
}

//208	
long io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events)
{
    return syscall(SYS_io_getevents, ctx_id, min_nr, nr, events);
}

//209	
long io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp)
{
    return syscall(SYS_io_submit, ctx_id, nr, iocbpp);
}

//210	
long io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result)
{
    return syscall(SYS_io_cancel, ctx_id, iocb, result);
}

//211	NOT IMPLEMENTED. Use arch_prctl
long get_thread_area()
{
    return syscall(SYS_get_thread_area);
}

//212	
long lookup_dcookie(u64 cookie64, long buf, long len)
{
    return syscall(SYS_lookup_dcookie, cookie64, buf, len);
}

//213	
long epoll_create(int size)
{
    return syscall(SYS_epoll_create, size);
}

//214	NOT IMPLEMENTED
long epoll_ctl_old()
{
    return syscall(SYS_epoll_ctl_old);
}

//215	NOT IMPLEMENTED
long epoll_wait_old()
{
    return syscall(SYS_epoll_wait_old);
}

//216	
long remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags)
{
    return syscall(SYS_remap_file_pages, start, size, prot, pgoff, flags);
}

//217	
long getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count)
{
    return syscall(SYS_getdents64, fd, dirent, count);
}

//218	
long set_tid_address(int *tidptr)
{
    return syscall(SYS_set_tid_address, tidptr);
}

//219	
long restart_syscall()
{
    return syscall(SYS_restart_syscall);
}

//220	
long semtimedop(int semid, struct sembuf *tsops, unsigned nsops, const struct timespec *timeout)
{
    return syscall(SYS_semtimedop, semid, tsops, nsops, timeout);
}

//221	
long fadvise64(int fd, loff_t offset, size_t len, int advice)
{
    return syscall(SYS_fadvise64, fd, offset, len, advice);
}

//222	
long timer_create(const clockid_t which_clock, struct sigevent *timer_event_spec, timer_t *created_timer_id)
{
    return syscall(SYS_timer_create, which_clock, timer_event_spec, created_timer_id);
}

//223	
long timer_settime(timer_t timer_id, int flags, const struct itimerspec *new_setting, struct itimerspec *old_setting)
{
    return syscall(SYS_timer_settime, timer_id, flags, new_setting, old_setting);
}

//224	
long timer_gettime(timer_t timer_id, struct itimerspec *setting)
{
    return syscall(SYS_timer_gettime, timer_id, setting);
}

//225	
long timer_getoverrun(timer_t timer_id)
{
    return syscall(SYS_timer_getoverrun, timer_id);
}

//226	
long timer_delete(timer_t timer_id)
{
    return syscall(SYS_timer_delete, timer_id);
}

//227	
long clock_settime(const clockid_t which_clock, const struct timespec *tp)
{
    return syscall(SYS_clock_settime, which_clock, tp);
}

//228	
long clock_gettime(const clockid_t which_clock, struct timespec *tp)
{
    return syscall(SYS_clock_gettime, which_clock, tp);
}

//229	
long clock_getres(const clockid_t which_clock, struct timespec *tp)
{
    return syscall(SYS_clock_getres, which_clock, tp);
}

//230	
long clock_nanosleep(const clockid_t which_clock, int flags, const struct timespec *rqtp, struct timespec *rmtp)
{
    return syscall(SYS_clock_nanosleep, which_clock. flags, rqtp, rmtp);
}

//231	
long exit_group(int error_code)
{
    return syscall(SYS_exit_group, error_code);
}

//232	
long epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout)
{
    return syscall(SYS_epoll_wait, epfd, events, maxevents, timeout);
}

//233	
long epoll_ctl(int epfd, int op, int fd, struct epoll_event *event)
{
    return syscall(SYS_epoll_ctl, epfd, op, fd, event);
}

//234	
long tgkill(pid_t tgid, pid_t pid, int sig)
{
    return syscall(SYS_tgkill, tgid, pid, sig);
}

//235	
long utimes(char *filename, struct timeval *utimes)
{
    return syscall(SYS_utimes, filename, utimes);
}

//236	NOT IMPLEMENTED
long vserver()
{
    return syscall(SYS_vserver);
}

//237	
long mbind(unsigned long start, unsigned long len, unsigned long mode, unsigned long *nmask, unsigned long maxnode, unsigned flags)
{
    return syscall(SYS_mbind, start, len, mode, nmask, maxnode, flags);
}

//238	
long set_mempolicy(int mode, unsigned long *nmask, unsigned long maxnode)
{
    return syscall(SYS_set_mempolicy, mode, nmask, maxnode);
}

//239	
long get_mempolicy(int *policy, unsigned long *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags)
{
    return syscall(SYS_get_mempolicy, policy, nmask, maxnode, addr, flags);
}

//240	
long mq_open(const char *u_name, int oflag, mode_t mode, struct mq_attr *u_attr)
{
    return syscall(SYS_mq_open, u_name, oflag, mode, u_attr);
}

//241	
long mq_unlink(const char *u_name)
{
    return syscall(SYS_mq_unlink, u_name);
}

//242	
long mq_timedsend(mqd_t mqdes, const char *u_msg_ptr, size_t msg_len, unsigned int msg_prio, const stuct timespec *u_abs_timeout)
{
    return syscall(SYS_mq_timedsend, mqdes, u_msg_ptr, msg_len, msg_prio, u_abs_timeout);
}

//243	
long mq_timedreceive(mqd_t mqdes, char *u_msg_ptr, size_t msg_len, unsigned int *u_msg_prio, const struct timespec *u_abs_timeout)
{
    return syscall(SYS_mq_timedreceive, mqdes, u_msg_ptr, msg_len, u_msg_prio, u_abs_timeout);
}

//244	
long mq_notify(mqd_t mqdes, const struct sigevent *u_notification)
{
    return syscall(SYS_mq_notify, mqdes, u_notification);
}

//245	
long mq_getsetattr(mqd_t mqdes, const struct mq_attr *u_mqstat, struct mq_attr *u_omqstat)
{
    return syscall(SYS_mq_getsetattr, mqdes, u_mqstat, u_omqstat);
}

//246	
long kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags)
{
    return syscall(SYS_kexec_load, entry, nr_segments, segments, flags);
}

//247	
long waitid(int which, pid_t upid, struct siginfo *infop, int options, struct rusage *ru)
{
    return syscall(SYS_waitid, which, upid, infop, options, ru);
}

//248	
long add_key(const char *_type, const char *_description, const void *_payload, size_t plen)
{
    return syscall(SYS_add_key, _type, _description, _payload, plen);
}

//249	
long request_key(const char *_type, const char *_description, const char *_callout_info, key_serial_t destringid)
{
    return syscall(SYS_request_key, _type, _description, _callout_info, destringid);
}

//250	
long keyctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5)
{
    return syscall(SYS_keyctl, option, arg2, arg3, arg4, arg5);
}

//251	
long ioprio_set(int which, int who, int ioprio)
{
    return syscall(SYS_ioprio_set, which, who, ioprio);
}

//252	
long ioprio_get(int which, int who)
{
    return syscall(SYS_ioprio_get, which, who);
}

//253	
long inotify_init()
{
    return syscall(SYS_inotify_init);
}

//254	
long inotify_add_watch(int fd, const char *pathname, u32 mask)
{
    return syscall(SYS_inotify_add_watch, fd, pathname, mask);
}

//255	
long inotify_rm_watch(int fd, __s32 wd)
{
    return syscall(SYS_inotify_rm_watch, fd, wd);
}

//256	
long migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes)
{
    return syscall(SYS_migrate_pages, pid, maxnode, old_nodes, new_nodes);
}

//257	
long openat(int dfd, const char *filename, int flags, int mode)
{
    return syscall(SYS_openat, dfd, filename, flags, mode);
}

//258	
long mkdirat(int dfd, const char *pathname, int mode)
{
    return syscall(SYS_mkdirat, dfd, pathname, mode);
}

//259	
long mknodat(int dfd, const char *filename, int mode, unsigned dev)
{
    return syscall(SYS_mknodat, dfd, filename, mode, dev);
}

//260	
long fchownat(int dfd, const char *filename, uid_t user, gid_t group, int flag)
{
    return syscall(SYS_fchownat, dfd, filename, user, group, flag);
}

//261	
long futimesat(int dfd, const char *filename, struct timeval *utimes)
{
    return syscall(SYS_futimesat, dfd, filename, utimes);
}

//262	
long newfstatat(int dfd, const char *filename, struct stat *statbuf, int flag)
{
    return syscall(SYS_newfstatat, dfd, filename, statbuf, flag);
}

//263	
long unlinkat(int dfd, const char *pathname, int flag)
{
    return syscall(SYS_unlinkat, dfd, pathname, flag);
}

//264	
long renameat(int oldfd, const char *oldname, int newfd, const char *newname)
{
    return syscall(SYS_renameat, oldfd, oldname, newfd, newname);
}

//265	
long linkat(int oldfd, const char *oldname, int newfd, const char *newname, int flags)
{
    return syscall(SYS_linkat, oldfd, oldname, newfd, newname, flags);
}

//266	
long symlinkat(const char *oldname, int newfd, const char *newname)
{
    return syscall(SYS_symlinkat, oldname, newfd, newname);
}

//267	
long readlinkat(int dfd, const char *pathname, char *buf, int bufsiz)
{
    return syscall(SYS_readlinkat, dfd, pathname, buf, bufsiz);
}

//268	
long fchmodat(int dfd, const char *filename, mode_t mode)
{
    return syscall(SYS_fchmodat, dfd, filename, mode);
}

//269	
long faccessat(int dfd, const char *filename, int mode)
{
    return syscall(SYS_faccessat, dfd, filename, mode);
}

//270	
long pselect6(int n, fd_set *inp, fd_set *outp, fd_set *exp, struct timespec *tsp, void *sig)
{
    return syscall(SYS_pselect6, n, inp, outp, exp, tsp, sig);
}

//271	
long ppoll(struct pollfd *ufds, unsigned int nfds, struct timespec *tsp, const sigset_t *sigmask, size_t sigsetsize)
{
    return syscall(SYS_ppoll, ufds, nfds, tsp, sigmask, sigsetsize);
}

//272	
long unshare(unsigned long unshare_flags)
{
    return syscall(SYS_unshare, flags);
}

//273	
long set_robust_list(struct robust_list_head *head, size_t len)
{
    return syscall(SYS_set_robust_list, head, len);
}

//274	
long get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr)
{
    return syscall(SYS_get_robust_list, pid, head_ptr, len_ptr);
}

//275	
long splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags)
{
    return syscall(SYS_splice, fd_in, off_in, fd_out, off_out, len, flags);
}

//276	
long tee(int fdin, int fdout, size_t len, unsigned int flags)
{
    return syscall(SYS_tee, fdin, fdout, len, flags);
}

//277	
long sync_file_range(long fd, loff_t offset, loff_t bytes, long flags)
{
    return syscall(SYS_sync_file_range, fd, offset, bytes, flags);
}

//278	
long vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags)
{
    return syscall(SYS_vmsplice, fd, iov, nr_segs, flags);
}

//279	
long move_pages(pid_t pid, unsigned long nr_pages, const void **pages, const int *nodes, int *status, int flags)
{
    return syscall(SYS_move_pages, pid, nr_pages, pages, nodes, status, flags);
}

//280	
long utimensat(int dfd, const char *filename, struct timespec *utimes, int flags)
{
    return syscall(SYS_utimensat, dfd, filename, utimes, flags);
}

//281	
long epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask, size_t sigsetsize)
{
    return syscall(SYS_epoll_pwait, epfd, events, maxevents, timeout, sigmask, sigsetsize);
}

//282	
long signalfd(int ufd, sigset_t *user_mask, size_t sizemask)
{
    return syscall(SYS_signalfd, ufd, user_mask, sizemask);
}

//283	
long timerfd_create(int clockid, int flags)
{
    return syscall(SYS_timerfd_create, clockid, flags);
}

//284	
long eventfd(unsigned int count)
{
    return syscall(SYS_eventfd, count);
}

//285	
long fallocate(long fd, long mode, loff_t offset, loff_t len)
{
    return syscall(SYS_fallocate, fd, mode, offset, len);
}

//286	
long timerfd_settime(int ufd, int flags, const struct itimerspec *utmr, struct itimerspec *otmr)
{
    return syscall(SYS_timerfd_settime, ufd, flags, utmr, otmr);
}

//287	
long timerfd_gettime(int ufd, struct itimerspec *otmr)
{
    return syscall(SYS_timerfd_gettime, ufd, otmr);
}

//288	
long accept4(int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags)
{
    return syscall(SYS_accept4, fd, upeer_sockaddr, upeer_addrlen, flags);
}

//289	
long signalfd4(int ufd, sigset_t *user_mask, size_t sizemask, int flags)
{
    return syscall(SYS_signalfd4, ufd, user_mask, sizemask, flags);
}

//290	
long eventfd2(unsigned int count, int flags)
{
    return syscall(SYS_eventfd2, count, flags);
}

//291	
long epoll_create1(int flags)
{
    return syscall(SYS_epoll_create1, flags);
}

//292	
long dup3(unsigned int oldfd, unsigned int newfd, int flags)
{
    return syscall(SYS_dup3, oldfd, newfd, flags);
}

//293	
long pipe2(int *filedes, int flags)
{
    return syscall(SYS_pipe2, filedes, flags);
}

//294	
long inotify_init1(int flags)
{
    return syscall(SYS_inotify_init1, flags);
}

//295	
long preadv(unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
    return syscall(SYS_preadv, fd, vec, vlen, pos_l, pos_h);
}

//296	
long pwritev(unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h)
{
    return syscall(SYS_pwritev, fd, vec, vlen, pos_l, pos_h);
}

//297	
long rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig, siginfo_t *uinfo)
{
    return syscall(SYS_rt_tgsigqueueinfo, tgid, pid, sig, uinfo);
}

//298	
long perf_event_open(struct perf_event_attr *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags)
{
    return syscall(SYS_perf_event_open, attr_uptr, pid, cpu, group_fd, flags);
}

//299	
long recvmmsg(int fd, struct msghdr *mmsg, unsigned int vlen, unsigned int flags, struct timespec *timeout)
{
    return syscall(SYS_recvmmsg, fd, mmsg, vlen, flags, timeout);
}

//300	
long fanotify_init(unsigned int flags, unsigned int event_f_flags)
{
    return syscall(SYS_fanotify_init, flags, event_f_flags);
}

//301	
long fanotify_mark(long fanotify_fd, long flags, __u64 mask, long dfd, long pathname)
{
    return syscall(SYS_fanotify_mark, fanotify_fd, flags, mask, dfd, pathname);
}

//302	
long prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *old_rlim)
{
    return syscall(SYS_prlimit64, pid, resource, new_rlim, old_rlim);
}

//303	
long name_to_handle_at(int dfd, const char *name, struct file_handle *handle, int *mnt_id, int flag)
{
    return syscall(SYS_name_to_handle_at, dfd, name, handle, mnt_id, flag);
}

//304	
long open_by_handle_at(int dfd, const char *name, struct file_handle *handle, int *mnt_id, int flags)
{
    return syscall(SYS_open_by_handle_at, dfd, name, handle, mnt_id, flags);
}

//305	
long clock_adjtime(clockid_t which_clock, struct timex *tx)
{
    return syscall(SYS_clock_adjtime, which_clock, tx);
}

//306	
long syncfs(int fd)
{
    return syscall(SYS_syncfs, fd);
}

//307	
long sendmmsg(int fd, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags)
{
    return syscall(SYS_sendmmsg, fd, mmsg, vlen, flags);
}

//308	
long setns(int fd, int nstype)
{
    return syscall(SYS_setns, fd, nstype);
}

//309	
long getcpu(unsigned *cpup, unsigned *nodep, struct getcpu_cache *unused)
{
    return syscall(SYS_getcpu, cpup, nodep, unused);
}

//310	
long process_vm_readv(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags)
{
    return syscall(SYS_process_vm_readv, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

//311	
long process_vm_writev(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovcc *rvec, unsigned long riovcnt, unsigned long flags)
{
    return syscall(SYS_process_vm_writev, pid, lvec, liovcnt, rvec, riovcnt, flags);
}

//312	
long kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2)
{
    return syscall(SYS_kcmp, pid1, pid2, type, idx1, idx2);
}

//313	
long finit_module(int fd, const char __user *uargs, int flags)
{
    return syscall(SYS_finit_module, fd, uargs, flags);
}

//314	
long sched_setattr(pid_t pid, struct sched_attr __user *attr, unsigned int flags)
{
    return syscall(SYS_sched_setattr, pid, attr, flags);
}

//315	
long sched_getattr(pid_t pid, struct sched_attr __user *attr, unsigned int size, unsigned int flags)
{
    return syscall(SYS_sched_getattr, pid, attr, size, flags);
}

//316	
long renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags)
{
    return syscall(SYS_renameat2, olddfd, oldname, newdfd, newname, flags);
}

//317	
long seccomp(unsigned int op, unsigned int flags, const char __user *uargs)
{
    return syscall(SYS_seccomp, op, flags, uargs);
}

//318	
long getrandom(char __user *buf, size_t count, unsigned int flags)
{
    return syscall(SYS_getrandom, buf, count, flags);
}

//319	
long memfd_create(const char __user *uname_ptr, unsigned int flags)
{
    return syscall(SYS_memfd_create, uname_ptr, flags);
}

//320	
long kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char __user *cmdline_ptr, unsigned long flags)
{
    return syscall(SYS_kexec_file_load, kernel_fd, initrd_fd, cmdline_len, cmdline_ptr, flags);
}

//321	
long bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    return syscall(SYS_bpf, cmd, attr, size);
}

//322	
/*
long stub_execveat(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags)
{
    return syscall(SYS_stub_execveat, dfd, filename, argv, envp, flags);
}
*/

//323	
long userfaultfd(int flags)
{
    return syscall(SYS_userfaultfd, flags);
}

//324	
long membarrier(int cmd, int flags)
{
    return syscall(SYS_membarrier, cmd, flags);
}

//325	
long mlock2(unsigned long start, size_t len, int flags)
{
    return syscall(SYS_mlock2, start, len, flags);
}

//326	
long copy_file_range(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user * off_out, size_t len, unsigned int flags)
{
    return syscall(SYS_copy_file_range, fd_in, off_in, fd_out, off_out, len, flags);
}

//327	
long preadv2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, int flags)
{
    return syscall(SYS_preadv2, fd, vec, vlen, pos_l, pos_h, flags);
}

//328	
long pwritev2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, int flags)
{
    return syscall(SYS_pwritev2, fd, vec, vlen, pos_l, pos_h, flags);
}
