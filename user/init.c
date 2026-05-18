// init: The initial user-level program

#include "kernel/types.h"
#include "kernel/stat.h"
#include "kernel/spinlock.h"
#include "kernel/sleeplock.h"
#include "kernel/fs.h"
#include "kernel/file.h"
#include "user/user.h"
#include "kernel/fcntl.h"

char *argv[] = { "sh", 0 };

void add_user(int pf, const char *u, const char *pw, int uid, int gid) {
  char line[64], *p = line;
  while(*u) *p++ = *u++;
  *p++ = ':';
  while(*pw) *p++ = *pw++ ^ (char)0xaa;
  *p++ = ':';
  *p++ = '0' + uid;
  *p++ = ':';
  *p++ = '0' + gid;
  *p++ = '\n';
  write(pf, line, p - line);
}

int
main(void)
{
  int pid, wpid;

  if(open("console", O_RDWR) < 0){
    mknod("console", CONSOLE, 0);
    open("console", O_RDWR);
  }
  dup(0);  // stdout
  dup(0);  // stderr

  // Create directories
  mkdir("/etc");
  mkdir("/device");
  mkdir("/patient");
  mkdir("/dosage");
  mkdir("/audit");

  // Bootstrap root account (password "x") if /etc/passwd is empty
  {
    int pf = open("/etc/passwd", O_CREATE | O_RDWR);
    if(pf >= 0){
      char b[8];
      int n = read(pf, b, sizeof(b));
      if(n == 0){
        add_user(pf, "root", "x", 0, 0);
        add_user(pf, "patient1", "p1", 1, 1);
        add_user(pf, "patient2", "p2", 1, 1);
        add_user(pf, "patient3", "p3", 1, 1);
        add_user(pf, "doctor1", "d1", 2, 2);
        add_user(pf, "doctor2", "d2", 2, 2);
        add_user(pf, "doctor3", "d3", 2, 2);
      }
      close(pf);
    }
  }

  // Protected files (CCY4304: PATIENT uid=1, DOCTOR uid=2)
  int fd;
  if((fd = open("/device/config", O_CREATE | O_RDWR)) >= 0){
    close(fd);
    chmod("/device/config", 0700);
    chown("/device/config", 0, 0);
  }
  if((fd = open("/patient/records", O_CREATE | O_RDWR)) >= 0){
    close(fd);
    chmod("/patient/records", 0440);
    chown("/patient/records", 1, 2);
  }
  if((fd = open("/dosage/insulin.log", O_CREATE | O_RDWR)) >= 0){
    close(fd);
    chmod("/dosage/insulin.log", 0640);
    chown("/dosage/insulin.log", 2, 1);
  }
  if((fd = open("/audit/syscall.log", O_CREATE | O_RDWR)) >= 0){
    close(fd);
    chmod("/audit/syscall.log", 0600);
    chown("/audit/syscall.log", 0, 0);
  }

  for(;;){
    printf("init: starting login\n");
    pid = fork();
    if(pid < 0){
      printf("init: fork failed\n");
      exit(1);
    }
    if(pid == 0){
      exec("login", argv);
      printf("init: exec login failed\n");
      exit(1);
    }

    for(;;){
      // this call to wait() returns if the shell exits,
      // or if a parentless process exits.
      wpid = wait((int *) 0);
      if(wpid == pid){
        // the login exited; restart it.
        break;
      } else if(wpid < 0){
        printf("init: wait returned an error\n");
        exit(1);
      } else {
        // it was a parentless process; do nothing.
      }
    }
  }
}
