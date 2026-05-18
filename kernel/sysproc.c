#include "types.h"
#include "riscv.h"
#include "defs.h"
#include "param.h"
#include "memlayout.h"
#include "spinlock.h"
#include "proc.h"
#include "vm.h"
#include "fs.h"
#include "fcntl.h"
#include "stat.h"
#include "sleeplock.h"
#include "file.h"

// extern declarations for fs functions
extern struct inode* namei(char *path);
extern struct inode* create(char *path, short type, short major, short minor);
extern int writei(struct inode *ip, int user_dst, uint64 dst, uint off, uint n);

// Simple XOR cipher for password hashing
void
hash_password(char *password, char *hashed, int len)
{
  for(int i = 0; i < len; i++){
    hashed[i] = password[i] ^ 0xAA;
  }
  hashed[len] = '\0';
}

static void
append_uint(char **pp, int n)
{
  char tmp[12];
  int i = 0;
  if(n == 0)
    tmp[i++] = '0';
  else {
    while(n > 0 && i < (int)sizeof(tmp)){
      tmp[i++] = '0' + (n % 10);
      n /= 10;
    }
  }
  while(i > 0)
    *(*pp)++ = tmp[--i];
}

// Format one /etc/passwd line: user:hash:uid:gid\n
void
format_entry(char *buf, char *username, char *hashed, int uid, int gid)
{
  char *p = buf;
  while(*username)
    *p++ = *username++;
  *p++ = ':';
  while(*hashed)
    *p++ = *hashed++;
  *p++ = ':';
  append_uint(&p, uid);
  *p++ = ':';
  append_uint(&p, gid);
  *p++ = '\n';
  *p = 0;
}

uint64
sys_exit(void)
{
  int n;
  argint(0, &n);
  kexit(n);
  return 0;  // not reached
}

uint64
sys_getpid(void)
{
  return myproc()->pid;
}

uint64
sys_fork(void)
{
  return kfork();
}

uint64
sys_wait(void)
{
  uint64 p;
  argaddr(0, &p);
  return kwait(p);
}

uint64
sys_sbrk(void)
{
  uint64 addr;
  int t;
  int n;

  argint(0, &n);
  argint(1, &t);
  addr = myproc()->sz;

  if(t == SBRK_EAGER || n < 0) {
    if(growproc(n) < 0) {
      return -1;
    }
  } else {
    // Lazily allocate memory for this process: increase its memory
    // size but don't allocate memory. If the processes uses the
    // memory, vmfault() will allocate it.
    if(addr + n < addr)
      return -1;
    if(addr + n > TRAPFRAME)
      return -1;
    myproc()->sz += n;
  }
  return addr;
}

uint64
sys_pause(void)
{
  int n;
  uint ticks0;

  argint(0, &n);
  if(n < 0)
    n = 0;
  acquire(&tickslock);
  ticks0 = ticks;
  while(ticks - ticks0 < n){
    if(killed(myproc())){
      release(&tickslock);
      return -1;
    }
    sleep(&ticks, &tickslock);
  }
  release(&tickslock);
  return 0;
}

uint64
sys_kill(void)
{
  int pid;

  argint(0, &pid);
  return kkill(pid);
}

// return how many clock tick interrupts have occurred
// since start.
uint64
sys_uptime(void)
{
  uint xticks;

  acquire(&tickslock);
  xticks = ticks;
  release(&tickslock);
  return xticks;
}

uint64
sys_useradd(void)
{
  char username[32], password[32], hashed[32], buf[128];
  int role;

  // Only admin can add users
  if(myproc()->uid != 0)
    return -1;

  if(argstr(0, username, sizeof(username)) < 0 ||
     argstr(1, password, sizeof(password)) < 0)
    return -1;
  argint(2, &role);

  if(strlen(password) == 0 || strchr(password, ':'))
    return -1;

  // Hash the password (never store plaintext)
  hash_password(password, hashed, strlen(password));

  // Assign uid/gid based on role (ADMIN=0, PATIENT=1, DOCTOR=2)
  int uid, gid;
  if(role == 0){
    uid = 0;
    gid = 0;
  } else if(role == 1){
    uid = 1;
    gid = 1;
  } else if(role == 2){
    uid = 2;
    gid = 2;
  } else {
    return -1;
  }

  format_entry(buf, username, hashed, uid, gid);
  int len = strlen(buf);

  begin_op();

  struct inode *ip = namei("/etc/passwd");
  if(ip == 0){
    ip = create("/etc/passwd", T_FILE, 0, 0);
    if(ip == 0){
      end_op();
      return -1;
    }
  }
  ilock(ip);
  if(ip->size > 0){
    char existing[1024];
    int m = readi(ip, 0, (uint64)existing, 0, sizeof(existing) - 1);
    if(m > 0){
      char *line = existing;
      existing[m] = 0;
      while(*line){
        char *colon = strchr(line, ':');
        if(!colon)
          break;
        *colon = 0;
        if(strcmp(line, username) == 0){
          *colon = ':';
          iunlockput(ip);
          end_op();
          return -1;
        }
        *colon = ':';
        char *nl = strchr(line, '\n');
        if(!nl)
          break;
        line = nl + 1;
      }
    }
  }
  uint off = ip->size;
  if(writei(ip, 0, (uint64)buf, off, len) != len){
    iunlockput(ip);
    end_op();
    return -1;
  }
  iunlockput(ip);
  end_op();
  return 0;
}

uint64
sys_setuid(void)
{
  int uid;
  struct proc *p = myproc();

  argint(0, &uid);
  if(p->uid != 0 && uid != p->uid)
    return -1;
  p->uid = uid;
  return 0;
}

uint64
sys_setgid(void)
{
  int gid;
  struct proc *p = myproc();

  argint(0, &gid);
  if(p->uid != 0 && gid != p->gid)
    return -1;
  p->gid = gid;
  return 0;
}

uint64
sys_userdel(void)
{
  char username[32];
  char buf[1024], out[1024];

  if(myproc()->uid != 0)
    return -1;
  if(argstr(0, username, sizeof(username)) < 0)
    return -1;

  begin_op();
  struct inode *ip = namei("/etc/passwd");
  if(ip == 0){
    end_op();
    return -1;
  }
  ilock(ip);
  int n = readi(ip, 0, (uint64)buf, 0, sizeof(buf) - 1);
  if(n < 0){
    iunlockput(ip);
    end_op();
    return -1;
  }
  buf[n] = 0;
  char *line = buf, *op = out;
  while(*line){
    char *nl = strchr(line, '\n');
    if(!nl)
      break;
    char save = *nl;
    *nl = 0;
    char *c1 = strchr(line, ':');
    if(!c1){
      *nl = save;
      int linelen = nl - line + 1;
      if(op + linelen >= out + sizeof(out)){
        iunlockput(ip);
        end_op();
        return -1;
      }
      memmove(op, line, linelen);
      op += linelen;
      line = nl + 1;
      continue;
    }
    *c1 = 0;
    if(strcmp(line, username) == 0){
      *c1 = ':';
      *nl = save;
      line = nl + 1;
      continue;
    }
    *c1 = ':';
    *nl = save;
    int linelen = nl - line + 1;
    if(op + linelen >= out + sizeof(out)){
      iunlockput(ip);
      end_op();
      return -1;
    }
    memmove(op, line, linelen);
    op += linelen;
    line = nl + 1;
  }
  *op = 0;
  int newlen = op - out;
  itrunc(ip);
  if(newlen > 0 && writei(ip, 0, (uint64)out, 0, newlen) != newlen){
    iunlockput(ip);
    end_op();
    return -1;
  }
  iupdate(ip);
  iunlockput(ip);
  end_op();
  return 0;
}

static int
katoi(char *s)
{
  int n = 0;
  while(*s >= '0' && *s <= '9')
    n = n * 10 + *s++ - '0';
  return n;
}

// Parse one passwd line (single line, no trailing \n). Temporarily mutates line.
static int
parse_line_fields(char *line, char *user, char *hash, int *uid, int *gid)
{
  char *c1 = strchr(line, ':');
  if(!c1)
    return -1;
  *c1 = 0;
  safestrcpy(user, line, 32);
  char *c2 = strchr(c1 + 1, ':');
  if(!c2){
    *c1 = ':';
    return -1;
  }
  *c2 = 0;
  safestrcpy(hash, c1 + 1, 64);
  char *c3 = strchr(c2 + 1, ':');
  if(!c3){
    *c1 = ':';
    *c2 = ':';
    return -1;
  }
  *c3 = 0;
  *uid = katoi(c2 + 1);
  *gid = katoi(c3 + 1);
  *c3 = ':';
  *c2 = ':';
  *c1 = ':';
  return 0;
}

uint64
sys_passwd(void)
{
  struct proc *p = myproc();
  char uname[32], passa[64], passb[64];
  char newhash[64], oldhash[64], buf[1024], out[1024], u[32], h[64];
  int uid, gid;
  char *line, *op, *nl;
  int n, newlen, found;

  if(p->uid == 0){
    if(argstr(0, uname, sizeof(uname)) < 0 || argstr(1, passb, sizeof(passb)) < 0)
      return -1;
    if(strlen(passb) == 0 || strchr(passb, ':'))
      return -1;
    hash_password(passb, newhash, strlen(passb));
  } else {
    if(argstr(0, passa, sizeof(passa)) < 0 || argstr(1, passb, sizeof(passb)) < 0)
      return -1;
    if(strlen(passb) == 0 || strchr(passb, ':'))
      return -1;
    hash_password(passa, oldhash, strlen(passa));
    hash_password(passb, newhash, strlen(passb));
  }

  begin_op();
  struct inode *ip = namei("/etc/passwd");
  if(ip == 0){
    end_op();
    return -1;
  }
  ilock(ip);
  n = readi(ip, 0, (uint64)buf, 0, sizeof(buf) - 1);
  if(n < 0){
    iunlockput(ip);
    end_op();
    return -1;
  }
  buf[n] = 0;
  line = buf;
  op = out;
  found = 0;
  while(*line){
    nl = strchr(line, '\n');
    if(!nl)
      break;
    *nl = 0;
    if(parse_line_fields(line, u, h, &uid, &gid) < 0){
      *nl = '\n';
      iunlockput(ip);
      end_op();
      return -1;
    }
    if(p->uid == 0){
      if(strcmp(u, uname) == 0){
        format_entry(op, u, newhash, uid, gid);
        op += strlen(op);
        found = 1;
      } else {
        int l = strlen(line);
        if(op + l + 2 > out + sizeof(out)){
          iunlockput(ip);
          end_op();
          return -1;
        }
        memmove(op, line, l);
        op += l;
        *op++ = '\n';
        *op = 0;
      }
    } else {
      if(uid == p->uid){
        if(strcmp(h, oldhash) != 0){
          iunlockput(ip);
          end_op();
          return -1;
        }
        format_entry(op, u, newhash, uid, gid);
        op += strlen(op);
        found = 1;
      } else {
        int l = strlen(line);
        if(op + l + 2 > out + sizeof(out)){
          iunlockput(ip);
          end_op();
          return -1;
        }
        memmove(op, line, l);
        op += l;
        *op++ = '\n';
        *op = 0;
      }
    }
    *nl = '\n';
    line = nl + 1;
  }
  if(!found){
    iunlockput(ip);
    end_op();
    return -1;
  }
  newlen = op - out;
  itrunc(ip);
  if(newlen > 0 && writei(ip, 0, (uint64)out, 0, newlen) != newlen){
    iunlockput(ip);
    end_op();
    return -1;
  }
  iupdate(ip);
  iunlockput(ip);
  end_op();
  return 0;
}

uint64
sys_whoami(void)
{
  struct proc *p = myproc();
  uint64 addr;
  int max, n, uid, gid;
  char buf[1024], linebuf[128], u[32], h[64];
  char *line, *nl;

  argaddr(0, &addr);
  argint(1, &max);
  if(max < 1 || max > 64)
    return -1;

  begin_op();
  struct inode *ip = namei("/etc/passwd");
  if(ip == 0){
    end_op();
    return -1;
  }
  ilock(ip);
  n = readi(ip, 0, (uint64)buf, 0, sizeof(buf) - 1);
  iunlockput(ip);
  end_op();
  if(n < 0)
    return -1;
  buf[n] = 0;
  for(line = buf; *line; line = nl + 1){
    nl = strchr(line, '\n');
    if(!nl)
      break;
    *nl = 0;
    if(strlen(line) >= sizeof(linebuf)){
      *nl = '\n';
      return -1;
    }
    memmove(linebuf, line, strlen(line) + 1);
    *nl = '\n';
    if(parse_line_fields(linebuf, u, h, &uid, &gid) < 0)
      continue;
    if(uid == p->uid){
      if(copyout(p->pagetable, addr, u, strlen(u) + 1) < 0)
        return -1;
      return 0;
    }
  }
  return -1;
}
