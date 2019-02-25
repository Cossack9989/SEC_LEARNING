### How to trigger `malloc` in `printf`

##### where is the exploitable `malloc`

stdio-common/printf.c -> stdio-common/vfprintf.c line 1474(glibc-2.27)

```c
#define L_(Str)		Str
#define EXTSIZ		32
enum { WORK_BUFFER_SIZE = 1000};

// glibc/stdio-common/vfprintf.c 1474
if (width >= WORK_BUFFER_SIZE - EXTSIZ)
{
	/* We have to use a special buffer.  */
	size_t needed = ((size_t) width + EXTSIZ) * sizeof (CHAR_T);
	if (__libc_use_alloca (needed))
		workend = (CHAR_T *) alloca (needed) + width + EXTSIZ;
	else
	{
		workstart = (CHAR_T *) malloc (needed);
		if (workstart == NULL)
		{
			done = -1;
			goto all_done;
		}
		workend = workstart + width + EXTSIZ;
	}
}
```
---
and to trigger `malloc`, we should set the size more than 65536
```c
/* Minimum size for a thread.  We are free to choose a reasonable value.  */
#define PTHREAD_STACK_MIN        	  16384
#define __MAX_ALLOCA_CUTOFF        	65536

int __libc_use_alloca (size_t size)
{
	return (__builtin_expect (size <= PTHREAD_STACK_MIN / 4, 1)
	        || __builtin_expect (__libc_alloca_cutoff (size), 1));
}

int __libc_alloca_cutoff (size_t size)
{
	return size <= (MIN (__MAX_ALLOCA_CUTOFF, THREAD_GETMEM (THREAD_SELF, stackblock_size) / 4 ? : __MAX_ALLOCA_CUTOFF * 4));
	/* The main thread, before the thread library is
	initialized, has zero in the stackblock_size
	element.  Since it is the main thread we can
	assume the maximum available stack space.  */
}

# define THREAD_GETMEM(descr, member) \
  ({ __typeof (descr->member) __value;                                              \
     if (sizeof (__value) == 1)                                                      \
       asm volatile ("movb %%fs:%P2,%b0"                                      \
                     : "=q" (__value)                                              \
                     : "0" (0), "i" (offsetof (struct pthread, member)));     \
     else if (sizeof (__value) == 4)                                              \
       asm volatile ("movl %%fs:%P1,%0"                                              \
                     : "=r" (__value)                                              \
                     : "i" (offsetof (struct pthread, member)));              \
     else                                                                      \
       {                                                                      \
         if (sizeof (__value) != 8)                                              \
           /* There should not be any value with a size other than 1,              \
              4 or 8.  */                                                      \
           abort ();                                                              \
                                                                              \
         asm volatile ("movq %%fs:%P1,%q0"                                      \
                       : "=r" (__value)                                              \
                       : "i" (offsetof (struct pthread, member)));              \
       }                                                                      \
     __value; })
```
---