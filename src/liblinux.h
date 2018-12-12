/*
 * liblinux.h 
 * 3-clause BSD-license, see LICENSE for details
 * 
 * Ilkka Prusi <ilkka.prusi@gmail.com> 2018
 */

#ifndef _LIBLINUX_H_
#define _LIBLINUX_H_

//0	
long read(unsigned int fd, char *buf, size_t count);

//1	
long write(unsigned int fd, const char *buf, size_t count);

//2	
long open(const char *filename, int flags, int mode);

//3	
long close(unsigned int fd);

//4	
long stat(const char *filename, struct stat *statbuf);

//5
long fstat(unsigned int fd, struct stat *statbuf);

//6	
long lstat(const char *filename, struct stat *statbuf);

//7	
long poll(struct poll_fd *ufds, unsigned int nfds, long timeout_msecs);

//8	
long lseek(unsigned int fd, off_t offset, unsigned int origin);

//9	
long mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, unsigned long fd, unsigned long off);

//10	
long mprotect(unsigned long start, size_t len, unsigned long prot);

//11
long munmap(unsigned long addr, size_t len);

//12
long brk(unsigned long brk);

//13	
long rt_sigaction(int sig, const struct sigaction *act, struct sigaction *oact, size_t sigsetsize);

//14	
long rt_sigprocmask(int how, sigset_t *nset, sigset_t *oset, size_t sigsetsize);

//15	
long rt_sigreturn(unsigned long __unused);

//16	
long ioctl(unsigned int fd, unsigned int cmd, unsigned long arg);

//17
long pread64(unsigned long fd, char *buf, size_t count, loff_t pos);

//18	
long pwrite64(unsigned int fd, const char *buf, size_t count, loff_t pos);

//19	
long readv(unsigned long fd, const struct iovec *vec, unsigned long vlen);

//20	
long writev(unsigned long fd, const struct iovec *vec, unsigned long vlen);

//21	
long access(const char *filename, int mode);

//22
long pipe(int *filedes);

//23	
long select(int n, fd_set *inp, fd_set *outp, fd_set *exp, struct timeval *tvp);

//24	
long sched_yield();

//25	
long mremap(unsigned long addr, unsigned long old_len, unsigned long new_len, unsigned long flags, unsigned long new_addr);

//26	
long msync(unsigned long start, size_t len, int flags);

//27	
long mincore(unsigned long start, size_t len, unsigned char *vec);

//28	
long madvise(unsigned long start, size_t len_in, int behavior);

//29	
long shmget(key_t key, size_t size, int shmflg);

//30	
long shmat(int shmid, char *shmaddr, int shmflg);

//31	
long shmctl(int shmid, int cmd, struct shmid_ds *buf);

//32	
long dup(unsigned int fildes);

//33	
long dup2(unsigned int oldfd, unsigned int newfd);

//34	
long pause();

//35	
long nanosleep(struct timespec *rqtp, struct timespec *rmtp);

//36	
long getitimer(int which, struct itimerval *value);

//37	
long alarm(unsigned int seconds);

//38	
long setitimer(int which, struct itimerval *value, struct itimerval *ovalue);

//39	
long getpid();

//40	
long sendfile(int out_fd, int in_fd, off_t *offset, size_t count);

//41	
long socket(int family, int type, int protocol);

//42	
long connect(int fd, struct sockaddr *uservaddr, int addrlen);

//43	
long accept(int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen);

//44	
long sendto(int fd, void *buff, size_t len, unsigned flags, struct sockaddr *addr, int addr_len);

//45	
long recvfrom(int fd, void *ubuf, size_t size, unsigned flags, struct sockaddr *addr, int *addr_len);

//46	
long sendmsg(int fd, struct msghdr *msg, unsigned flags);

//47	
long recvmsg(int fd, struct msghdr *msg, unsigned int flags);

//48	
long shutdown(int fd, int how);

//49	
long bind(int fd, struct sockaddr *umyaddr, int addrlen);

//50	
long listen(int fd, int backlog);

//51	
long getsockname(int fd, struct sockaddr *usockaddr, int *usockaddr_len);

//52	
long getpeername(int fd, struct sockaddr *usockaddr, int *usockaddr_len);

//53	
long socketpair(int family, int type, int protocol, int *usockvec);

//54	
long setsockopt(int fd, int level, int optname, char *optval, int optlen);

//55	
long getsockopt(int fd, int level, int optname, char *optval, int *optlen);

//56	
long clone(unsigned long clone_flags, unsigned long newsp, void *parent_tid, void *child_tid);

//57	
long fork();

//58	
long vfork();

//59	
long execve(const char *filename, const char *const argv[], const char *const envp[]);

//60	
long exit(int error_code);

//61	
long wait4(pid_t upid, int *stat_addr, int options, struct rusage *ru);

//62	
long kill(pid_t pid, int sig);

//63	
long uname(struct old_utsname *name);

//64	
long semget(key_t key, int nsems, int semflg);

//65	
long semop(int semid, struct sembuf *tsops, unsigned nsops);

//66	
long semctl(int semid, int semnum, int cmd, union semun arg);

//67	
long shmdt(char *shmaddr);

//68	
long msgget(key_t key, int msgflg);

//69	
long msgsnd(int msqid, struct msgbuf *msgp, size_t msgsz, int msgflg);

//70	
long msgrcv(int msqid, struct msgbuf *msgp, size_t msgsz, long msgtyp, int msgflg);

//71	
long msgctl(int msqid, int cmd, struct msqid_ds *buf);

//72	
long fcntl(unsigned int fd, unsigned int cmd, unsigned long arg);

//73	
long flock(unsigned int fd, unsigned int cmd);

//74	
long fsync(unsigned int fd);

//75	
long fdatasync(unsigned int fd);

//76	
long truncate(const char *path, long length);

//77	
long ftruncate(unsigned int fd, unsigned long length);

//78	
long getdents(unsigned int fd, struct linux_dirent *dirent, unsigned int count);

//79	
long getcwd(char *buf, unsigned long size);

//80	
long chdir(const char *filename);

//81	
long fchdir(unsigned int fd);

//82	
long rename(const char *oldname, const char *newname);

//83	
long mkdir(const char *pathname, int mode);

//84	
long rmdir(const char *pathname);

//85	
long creat(const char *pathname, int mode);

//86	
long link(const char *oldname, const char *newname);

//87	
long unlink(const char *pathname);

//88	
long symlink(const char *oldname, const char *newname);

//89	
long readlink(const char *path, char *buf, int bufsiz);

//90	
long chmod(const char *filename, mode_t mode);

//91	
long fchmod(unsigned int fd, mode_t mode);

//92	
long chown(const char *filename, uid_t user, gid_t group);

//93	
long fchown(unsigned int fd, uid_t user, gid_t group);

//94	
long lchown(const char *filename, uid_t user, gid_t group);

//95	
long umask(int mask);

//96	
long gettimeofday(struct timeval *tv, struct timezone *tz);

//97	
long getrlimit(unsigned int resource, struct rlimit *rlim);

//98	
long getrusage(int who, struct rusage *ru);

//99	
long sysinfo(struct sysinfo *info);

//100	
long times(struct sysinfo *info);

//101	
long ptrace(long request, long pid, unsigned long addr, unsigned long data);

//102	
long getuid();

//103	
long syslog(int type, char *buf, int len);

//104	
long getgid();

//105	
long setuid(uid_t uid);

//106	
long setgid(gid_t gid);

//107	
long geteuid();

//108	
long getegid();

//109	
long setpgid(pid_t pid, pid_t pgid);

//110	
long getppid();

//111	
long getpgrp();

//112	
long setsid();

//113	
long setreuid(uid_t ruid, uid_t euid);

//114	
long setregid(gid_t rgid, gid_t egid);

//115	
long getgroups(int gidsetsize, gid_t *grouplist);

//116	
long setgroups(int gidsetsize, gid_t *grouplist);

//117	
long setresuid(uid_t *ruid, uid_t *euid, uid_t *suid);

//118	
long getresuid(uid_t *ruid, uid_t *euid, uid_t *suid);

//119	
long setresgid(gid_t rgid, gid_t egid, gid_t sgid);

//120	
long getresgid(gid_t *rgid, gid_t *egid, gid_t *sgid);

//121	
long getpgid(pid_t pid);

//122	
long setfsuid(uid_t uid);

//123	
long setfsgid(gid_t gid);

//124	
long getsid(pid_t pid);

//125	
long capget(cap_user_header_t header, cap_user_data_t dataptr);

//126	
long capset(cap_user_header_t header, const cap_user_data_t data);

//127	
long rt_sigpending(sigset_t *set, size_t sigsetsize);

//128	
long rt_sigtimedwait(const sigset_t *uthese, siginfo_t *uinfo, const struct timespec *uts, size_t sigsetsize);

//129	
long rt_sigqueueinfo(pid_t pid, int sig	siginfo_t *uinfo);

//130	
long rt_sigsuspend(sigset_t *unewset, size_t sigsetsize);

//131	
long sigaltstack(const stack_t *uss, stack_t *uoss);

//132	
long utime(char *filename, struct utimbuf *times);

//133	
long mknod(const char *filename, umode_t mode, unsigned dev);

//134	NOT IMPLEMENTED
long uselib();

//135	
long personality(unsigned int personality);

//136	
long ustat(unsigned dev, struct ustat *ubuf);

//137	
long statfs(const char *pathname, struct statfs *buf);

//138	
long fstatfs(unsigned int fd, struct statfs *buf);

//139	
long sysfs(int option, unsigned long arg1, unsigned long arg2);

//140	
long getpriority(int which, int who);

//141	
long setpriority(int which, int who, int niceval);

//142	
long sched_setparam(pid_t pid, struct sched_param *param):

//143	
long sched_getparam(pid_t pid, struct sched_param *param);

//144	
long sched_setscheduler(pid_t pid, int policy, struct sched_param *param);

//145	
long sched_getscheduler(pid_t pid);

//146	
long sched_get_priority_max(int policy);

//147	
long sched_get_priority_min(int policy);

//148	
long sched_rr_get_interval(pid_t pid, struct timespec *interval);

//149	
long mlock(unsigned long start, size_t len);

//150	
long munlock(unsigned long start, size_t len);

//151	
long mlockall(int flags);

//152	
long munlockall();

//153	
long vhangup();

//154	
long modify_ldt(int func, void *ptr, unsigned long bytecount);

//155	
long pivot_root(const char *new_root, const char *put_old);

//156	
long __sysctl(struct __sysctl_args *args);

//157	
long prctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

//158	
long arch_prctl(struct task_struct *task, int code, unsigned long *addr);

//159	
long adjtimex(struct timex *txc_p);

//160	
long setrlimit(unsigned int resource, struct rlimit *rlim);

//161	
long chroot(const char *filename);

//162	
long sync();

//163	
long acct(const char *name);

//164	
long settimeofday(struct timeval *tv, struct timezone *tz);

//165	
long mount(char *dev_name, char *dir_name, char *type, unsigned long flags, void *data);

//166	
long umount2(const char *target, int flags);

//167	
long swapon(const char *specialfile, int swap_flags);

//168	
long swapoff(const char *specialfile);

//169	
long reboot(int magic1, int magic2, unsigned int cmd, void *arg);

//170	
long sethostname(char *name, int len);

//171	
long setdomainname(char *name, int len);

//172	
long iopl(unsigned int level, struct pt_regs *regs);

//173	
long ioperm(unsigned long from, unsigned long num, int turn_on);

//174	REMOVED IN Linux 2.6
long create_module();

//175	
long init_module(void *umod, unsigned long len, const char *uargs);

//176	
long delete_module(const chat *name_user, unsigned int flags);

//177	REMOVED IN Linux 2.6
long get_kernel_syms();

//178	REMOVED IN Linux 2.6
long query_module();

//179	
long quotactl(unsigned int cmd, const char *special, qid_t id, void *addr);

//180	NOT IMPLEMENTED
long nfsservctl();

//181	NOT IMPLEMENTED
long getpmsg();

//182	NOT IMPLEMENTED
long putpmsg();

//183	NOT IMPLEMENTED
long afs_syscall();

//184	NOT IMPLEMENTED
long tuxcall();

//185	NOT IMPLEMENTED
long security();

//186	
long gettid();

//187	
long readahead(int fd, loff_t offset, size_t count);

//188	
long setxattr(const char *pathname, const char *name, const void *value, size_t size, int flags);

//189	
long lsetxattr(const char *pathname, const char *name, const void *value, size_t size, int flags);

//190	
long fsetxattr(int fd, const char *name, const void *value, size_t size, int flags);

//191	
long getxattr(const char *pathname, const char *name, void *value, size_t size);

//192	
long lgetxattr(const char *pathname, const char *name, void *value, size_t size);

//193	
long fgetxattr(int fd, const char *name, void *value, size_t size);

//194	
long listxattr(const char *pathname, char *list, size_t size);

//195	
long llistxattr(const char *pathname, char *list, size_t size);

//196	
long flistxattr(int fd, char *list, size_t size);

//197	
long removexattr(const char *pathname, const char *name);

//198	
long lremovexattr(const char *pathname, const char *name);

//199	
long fremovexattr(int fd, const char *name);

//200	
long tkill(pid_t pid, ing sig);

//201	
long time(time_t *tloc);

//202	
long futex(u32 *uaddr, int op, u32 val, struct timespec *utime, u32 *uaddr2, u32 val3);

//203	
long sched_setaffinity(pid_t pid, unsigned int len, unsigned long *user_mask_ptr);

//204	
long sched_getaffinity(pid_t pid, unsigned int len, unsigned long *user_mask_ptr);

//205	NOT IMPLEMENTED. Use arch_prctl
long set_thread_area();

//206	
long io_setup(unsigned nr_events, aio_context_t *ctxp);

//207	
long io_destroy(aio_context_t ctx);

//208	
long io_getevents(aio_context_t ctx_id, long min_nr, long nr, struct io_event *events);

//209	
long io_submit(aio_context_t ctx_id, long nr, struct iocb **iocbpp);

//210	
long io_cancel(aio_context_t ctx_id, struct iocb *iocb, struct io_event *result);

//211	NOT IMPLEMENTED. Use arch_prctl
long get_thread_area();

//212	
long lookup_dcookie(u64 cookie64, long buf, long len);

//213	
long epoll_create(int size);

//214	NOT IMPLEMENTED
long epoll_ctl_old();

//215	NOT IMPLEMENTED
long epoll_wait_old();

//216	
long remap_file_pages(unsigned long start, unsigned long size, unsigned long prot, unsigned long pgoff, unsigned long flags);

//217	
long getdents64(unsigned int fd, struct linux_dirent64 *dirent, unsigned int count);

//218	
long set_tid_address(int *tidptr);

//219	
long restart_syscall();

//220	
long semtimedop(int semid, struct sembuf *tsops, unsigned nsops, const struct timespec *timeout);

//221	
long fadvise64(int fd, loff_t offset, size_t len, int advice);

//222	
long timer_create(const clockid_t which_clock, struct sigevent *timer_event_spec, timer_t *created_timer_id);

//223	
long timer_settime(timer_t timer_id, int flags, const struct itimerspec *new_setting, struct itimerspec *old_setting);

//224	
long timer_gettime(timer_t timer_id, struct itimerspec *setting);

//225	
long timer_getoverrun(timer_t timer_id);

//226	
long timer_delete(timer_t timer_id);

//227	
long clock_settime(const clockid_t which_clock, const struct timespec *tp);

//228	
long clock_gettime(const clockid_t which_clock, struct timespec *tp);

//229	
long clock_getres(const clockid_t which_clock, struct timespec *tp);

//230	
long clock_nanosleep(const clockid_t which_clock, int flags, const struct timespec *rqtp, struct timespec *rmtp);

//231	
long exit_group(int error_code);

//232	
long epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout);

//233	
long epoll_ctl(int epfd, int op, int fd, struct epoll_event *event);

//234	
long tgkill(pid_t tgid, pid_t pid, int sig);

//235	
long utimes(char *filename, struct timeval *utimes);

//236	NOT IMPLEMENTED
long vserver();

//237	
long mbind(unsigned long start, unsigned long len, unsigned long mode, unsigned long *nmask, unsigned long maxnode, unsigned flags);

//238	
long set_mempolicy(int mode, unsigned long *nmask, unsigned long maxnode);

//239	
long get_mempolicy(int *policy, unsigned long *nmask, unsigned long maxnode, unsigned long addr, unsigned long flags);

//240	
long mq_open(const char *u_name, int oflag, mode_t mode, struct mq_attr *u_attr);

//241	
long mq_unlink(const char *u_name);

//242	
long mq_timedsend(mqd_t mqdes, const char *u_msg_ptr, size_t msg_len, unsigned int msg_prio, const stuct timespec *u_abs_timeout);

//243	
long mq_timedreceive(mqd_t mqdes, char *u_msg_ptr, size_t msg_len, unsigned int *u_msg_prio, const struct timespec *u_abs_timeout);

//244	
long mq_notify(mqd_t mqdes, const struct sigevent *u_notification);

//245	
long mq_getsetattr(mqd_t mqdes, const struct mq_attr *u_mqstat, struct mq_attr *u_omqstat);

//246	
long kexec_load(unsigned long entry, unsigned long nr_segments, struct kexec_segment *segments, unsigned long flags);

//247	
long waitid(int which, pid_t upid, struct siginfo *infop, int options, struct rusage *ru);

//248	
long add_key(const char *_type, const char *_description, const void *_payload, size_t plen);

//249	
long request_key(const char *_type, const char *_description, const char *_callout_info, key_serial_t destringid);

//250	
long keyctl(int option, unsigned long arg2, unsigned long arg3, unsigned long arg4, unsigned long arg5);

//251	
long ioprio_set(int which, int who, int ioprio);

//252	
long ioprio_get(int which, int who);

//253	
long inotify_init();

//254	
long inotify_add_watch(int fd, const char *pathname, u32 mask);

//255	
long inotify_rm_watch(int fd, __s32 wd);

//256	
long migrate_pages(pid_t pid, unsigned long maxnode, const unsigned long *old_nodes, const unsigned long *new_nodes);

//257	
long openat(int dfd, const char *filename, int flags, int mode);

//258	
long mkdirat(int dfd, const char *pathname, int mode);

//259	
long mknodat(int dfd, const char *filename, int mode, unsigned dev);

//260	
long fchownat(int dfd, const char *filename, uid_t user, gid_t group, int flag);

//261	
long futimesat(int dfd, const char *filename, struct timeval *utimes);

//262	
long newfstatat(int dfd, const char *filename, struct stat *statbuf, int flag);

//263	
long unlinkat(int dfd, const char *pathname, int flag);

//264	
long renameat(int oldfd, const char *oldname, int newfd, const char *newname);

//265	
long linkat(int oldfd, const char *oldname, int newfd, const char *newname, int flags);

//266	
long symlinkat(const char *oldname, int newfd, const char *newname);

//267	
long readlinkat(int dfd, const char *pathname, char *buf, int bufsiz);

//268	
long fchmodat(int dfd, const char *filename, mode_t mode);

//269	
long faccessat(int dfd, const char *filename, int mode);

//270	
long pselect6(int n, fd_set *inp, fd_set *outp, fd_set *exp, struct timespec *tsp, void *sig);

//271	
long ppoll(struct pollfd *ufds, unsigned int nfds, struct timespec *tsp, const sigset_t *sigmask, size_t sigsetsize);

//272	
long unshare(unsigned long unshare_flags);

//273	
long set_robust_list(struct robust_list_head *head, size_t len);

//274	
long get_robust_list(int pid, struct robust_list_head **head_ptr, size_t *len_ptr);

//275	
long splice(int fd_in, loff_t *off_in, int fd_out, loff_t *off_out, size_t len, unsigned int flags);

//276	
long tee(int fdin, int fdout, size_t len, unsigned int flags);

//277	
long sync_file_range(long fd, loff_t offset, loff_t bytes, long flags);

//278	
long vmsplice(int fd, const struct iovec *iov, unsigned long nr_segs, unsigned int flags);

//279	
long move_pages(pid_t pid, unsigned long nr_pages, const void **pages, const int *nodes, int *status, int flags);

//280	
long utimensat(int dfd, const char *filename, struct timespec *utimes, int flags);

//281	
long epoll_pwait(int epfd, struct epoll_event *events, int maxevents, int timeout, const sigset_t *sigmask, size_t sigsetsize);

//282	
long signalfd(int ufd, sigset_t *user_mask, size_t sizemask);

//283	
long timerfd_create(int clockid, int flags);

//284	
long eventfd(unsigned int count);

//285	
long fallocate(long fd, long mode, loff_t offset, loff_t len);

//286	
long timerfd_settime(int ufd, int flags, const struct itimerspec *utmr, struct itimerspec *otmr);

//287	
long timerfd_gettime(int ufd, struct itimerspec *otmr);

//288	
long accept4(int fd, struct sockaddr *upeer_sockaddr, int *upeer_addrlen, int flags);

//289	
long signalfd4(int ufd, sigset_t *user_mask, size_t sizemask, int flags);

//290	
long eventfd2(unsigned int count, int flags);

//291	
long epoll_create1(int flags);

//292	
long dup3(unsigned int oldfd, unsigned int newfd, int flags);

//293	
long pipe2(int *filedes, int flags);

//294	
long inotify_init1(int flags);

//295	
long preadv(unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);

//296	
long pwritev(unsigned long fd, const struct iovec *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h);

//297	
long rt_tgsigqueueinfo(pid_t tgid, pid_t pid, int sig, siginfo_t *uinfo);

//298	
long perf_event_open(struct perf_event_attr *attr_uptr, pid_t pid, int cpu, int group_fd, unsigned long flags);

//299	
long recvmmsg(int fd, struct msghdr *mmsg, unsigned int vlen, unsigned int flags, struct timespec *timeout);

//300	
long fanotify_init(unsigned int flags, unsigned int event_f_flags);

//301	
long fanotify_mark(long fanotify_fd, long flags, __u64 mask, long dfd, long pathname);

//302	
long prlimit64(pid_t pid, unsigned int resource, const struct rlimit64 *new_rlim, struct rlimit64 *old_rlim);

//303	
long name_to_handle_at(int dfd, const char *name, struct file_handle *handle, int *mnt_id, int flag);

//304	
long open_by_handle_at(int dfd, const char *name, struct file_handle *handle, int *mnt_id, int flags);

//305	
long clock_adjtime(clockid_t which_clock, struct timex *tx);

//306	
long syncfs(int fd);

//307	
long sendmmsg(int fd, struct mmsghdr *mmsg, unsigned int vlen, unsigned int flags);

//308	
long setns(int fd, int nstype);

//309	
long getcpu(unsigned *cpup, unsigned *nodep, struct getcpu_cache *unused);

//310	
long process_vm_readv(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovec *rvec, unsigned long riovcnt, unsigned long flags);

//311	
long process_vm_writev(pid_t pid, const struct iovec *lvec, unsigned long liovcnt, const struct iovcc *rvec, unsigned long riovcnt, unsigned long flags);

//312	
long kcmp(pid_t pid1, pid_t pid2, int type, unsigned long idx1, unsigned long idx2);

//313	
long finit_module(int fd, const char __user *uargs, int flags);

//314	
long sched_setattr(pid_t pid, struct sched_attr __user *attr, unsigned int flags);

//315	
long sched_getattr(pid_t pid, struct sched_attr __user *attr, unsigned int size, unsigned int flags);

//316	
long renameat2(int olddfd, const char __user *oldname, int newdfd, const char __user *newname, unsigned int flags);

//317	
long seccomp(unsigned int op, unsigned int flags, const char __user *uargs);

//318	
long getrandom(char __user *buf, size_t count, unsigned int flags);

//319	
long memfd_create(const char __user *uname_ptr, unsigned int flags);

//320	
long kexec_file_load(int kernel_fd, int initrd_fd, unsigned long cmdline_len, const char __user *cmdline_ptr, unsigned long flags);

//321	
long bpf(int cmd, union bpf_attr *attr, unsigned int size);

//322	
/*
long stub_execveat(int dfd, const char __user *filename, const char __user *const __user *argv, const char __user *const __user *envp, int flags);
*/

//323	
long userfaultfd(int flags);

//324	
long membarrier(int cmd, int flags);

//325	
long mlock2(unsigned long start, size_t len, int flags);

//326	
long copy_file_range(int fd_in, loff_t __user *off_in, int fd_out, loff_t __user * off_out, size_t len, unsigned int flags);

//327	
long preadv2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, int flags);

//328	
long pwritev2(unsigned long fd, const struct iovec __user *vec, unsigned long vlen, unsigned long pos_l, unsigned long pos_h, int flags);

#endif //

