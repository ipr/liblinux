# liblinux
Linux syscall wrapper

Q: What is this?
A: Lightweight wrapper for kernel syscalls.

Q: Derp derp?
A: Syscalls are interface provided by kernel, which need transition from user-space to kernel-space. 
This is wrapper for that.

Q: How do I use it?
A: Just build as part of your program or put it in shared library.

Q: Aren't there others?
A: Yes. 

Q: But why?
A: For fun?

# Long(er) description
Just a simplistic and light-weight wrapper for syscalls in Linux. 
Mainly intended for building directly as part of your software put you can put this in a shared library if you wish.

Definitions are based on list at http://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
There are a couple of kernel releases since that was last updated.

In addition, there are some architecture specific things which are not handled at this moment (looking into it).

Performance could be improved by adding caching for some things and adding support for vDSO.

- Ilkka Prusi <ilkka.prusi@gmail.com> 12.12.2018

