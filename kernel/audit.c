#include "types.h"
#include "param.h"
#include "memlayout.h"
#include "riscv.h"
#include "spinlock.h"
#include "sleeplock.h"
#include "fs.h"
#include "file.h"
#include "proc.h"
#include "defs.h"
#include "syscall.h"

#define AUDIT_N 128

struct audit_rec {
  int pid;
  int uid;
  int tick;
  int scnum;
  uint64 epc;
  char extra[16];
};

static struct audit_rec audit_ring[AUDIT_N];
static uint audit_seq;
static struct spinlock audit_lock;

static void
append_hex(char *dst, int *pos, int max, uint64 v)
{
  char hex[] = "0123456789abcdef";
  int i;
  for(i = 60; i >= 0; i -= 4){
    if(*pos >= max - 1)
      break;
    dst[(*pos)++] = hex[(v >> i) & 0xf];
  }
  dst[*pos] = 0;
}

static void
append_int(char *dst, int *pos, int max, int n)
{
  char tmp[12];
  int i = 0, neg = 0;
  if(n < 0){
    neg = 1;
    n = -n;
  }
  if(n == 0)
    tmp[i++] = '0';
  else {
    while(n && i < (int)sizeof(tmp)){
      tmp[i++] = '0' + (n % 10);
      n /= 10;
    }
  }
  if(neg && *pos < max - 1)
    dst[(*pos)++] = '-';
  while(i > 0 && *pos < max - 1)
    dst[(*pos)++] = tmp[--i];
  dst[*pos] = 0;
}

void
auditinit(void)
{
  initlock(&audit_lock, "audit");
}

static void
audit_push(int scnum, uint64 epc, char *extra)
{
  struct proc *p = myproc();
  uint idx;
  struct audit_rec *r;

  acquire(&audit_lock);
  idx = audit_seq % AUDIT_N;
  r = &audit_ring[idx];
  r->pid = p->pid;
  r->uid = p->uid;
  acquire(&tickslock);
  r->tick = (int)ticks;
  release(&tickslock);
  r->scnum = scnum;
  r->epc = epc;
  memset(r->extra, 0, sizeof(r->extra));
  if(extra)
    safestrcpy(r->extra, extra, sizeof(r->extra));
  audit_seq++;
  release(&audit_lock);
}

void
audit_syscall(int scnum, uint64 epc)
{
  audit_push(scnum, epc, 0);
}

void
audit_perm_denial(int scnum, char *path)
{
  char tail[16];
  int len = strlen(path);
  if(len > 15){
    memmove(tail, path + len - 15, 16);
  } else {
    safestrcpy(tail, path, sizeof(tail));
  }
  audit_push(-scnum, 0, tail);
}

void
audit_login_event(int ok, char *user)
{
  audit_push(ok ? 998 : 999, 0, user);
}

const char *
syscall_name(int num)
{
  static const char *names[] = {
    [SYS_fork]    "fork",
    [SYS_exit]    "exit",
    [SYS_wait]    "wait",
    [SYS_pipe]    "pipe",
    [SYS_read]    "read",
    [SYS_kill]    "kill",
    [SYS_exec]    "exec",
    [SYS_fstat]   "fstat",
    [SYS_chdir]   "chdir",
    [SYS_dup]     "dup",
    [SYS_getpid]  "getpid",
    [SYS_sbrk]    "sbrk",
    [SYS_pause]   "pause",
    [SYS_uptime]  "uptime",
    [SYS_open]    "open",
    [SYS_write]   "write",
    [SYS_mknod]   "mknod",
    [SYS_unlink]  "unlink",
    [SYS_link]    "link",
    [SYS_mkdir]   "mkdir",
    [SYS_close]   "close",
    [SYS_useradd] "useradd",
    [SYS_setuid]  "setuid",
    [SYS_setgid]  "setgid",
    [SYS_chmod]   "chmod",
    [SYS_chown]   "chown",
    [SYS_userdel] "userdel",
    [SYS_passwd]  "passwd",
    [SYS_audit_read] "audit_read",
    [SYS_whoami]  "whoami",
    [SYS_audit_login] "audit_login",
  };
  if(num > 0 && num < (int)NELEM(names) && names[num])
    return names[num];
  return "unknown";
}

void
audit_sync_disk(int scnum, uint64 epc)
{
  struct proc *p = myproc();

  if(scnum == SYS_read || scnum == SYS_write)
    return;
  char line[160];
  int pos = 0;
  uint t;
  struct inode *ip;

  acquire(&tickslock);
  t = ticks;
  release(&tickslock);

  append_int(line, &pos, sizeof(line), (int)t);
  if(pos < (int)sizeof(line) - 1)
    line[pos++] = ' ';
  append_int(line, &pos, sizeof(line), p->pid);
  if(pos < (int)sizeof(line) - 1)
    line[pos++] = ' ';
  append_int(line, &pos, sizeof(line), p->uid);
  if(pos < (int)sizeof(line) - 1)
    line[pos++] = ' ';
  safestrcpy(line + pos, syscall_name(scnum), sizeof(line) - pos);
  pos = strlen(line);
  if(pos < (int)sizeof(line) - 4){
    line[pos++] = ' ';
    line[pos++] = '0';
    line[pos++] = 'x';
    append_hex(line, &pos, sizeof(line) - 1, epc);
  }
  if(pos < (int)sizeof(line) - 1)
    line[pos++] = '\n';
  line[pos] = 0;

  begin_op();
  ip = namei("/audit/syscall.log");
  if(ip == 0){
    end_op();
    return;
  }
  ilock(ip);
  if(writei(ip, 0, (uint64)line, ip->size, strlen(line)) != (int)strlen(line)){
    // ignore write errors
  }
  iunlock(ip);
  iput(ip);
  end_op();
}

uint64
sys_audit_read(void)
{
  struct proc *p = myproc();
  int n, i;
  uint64 addr;
  uint start;
  uint count;

  if(p->uid != 0)
    return -1;
  argint(0, &n);
  argaddr(1, &addr);
  if(n < 0 || n > AUDIT_N)
    return -1;

  acquire(&audit_lock);
  count = audit_seq < (uint)n ? audit_seq : (uint)n;
  start = audit_seq - count;
  for(i = 0; i < (int)count; i++){
    struct audit_rec *r = &audit_ring[(start + i) % AUDIT_N];
    if(copyout(p->pagetable, addr + i * sizeof(struct audit_rec),
                (char *)r, sizeof(struct audit_rec)) < 0){
      release(&audit_lock);
      return -1;
    }
  }
  release(&audit_lock);
  return count;
}

uint64
sys_audit_login(void)
{
  int ok;
  char user[32];

  if(myproc()->uid != 0)
    return -1;
  argint(0, &ok);
  if(argstr(1, user, sizeof(user)) < 0)
    return -1;
  audit_login_event(ok, user);
  return 0;
}
