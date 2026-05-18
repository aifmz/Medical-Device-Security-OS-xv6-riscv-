// Automated security compliance checks (CCY4304 bonus-style).
// Run as root after login: `seccompliance`

#include "kernel/types.h"
#include "kernel/stat.h"
#include "user/user.h"
#include "kernel/fcntl.h"

static int tests;
static int failed;

static void
ok(char *name)
{
  tests++;
  printf("PASS [%d] %s\n", tests, name);
}

static void
bad(char *name)
{
  tests++;
  failed++;
  printf("FAIL [%d] %s\n", tests, name);
}

static int
waitstatus(void)
{
  int st;
  if(wait(&st) < 0)
    return -1;
  return st;
}

static void
as_patient(void)
{
  if(setgid(1) < 0 || setuid(1) < 0)
    exit(10);
  if(open("/device/config", O_RDONLY) >= 0)
    exit(11);
  if(open("/patient/records", O_RDONLY) < 0)
    exit(12);
  if(open("/patient/records", O_RDWR) >= 0)
    exit(15);
  if(open("/dosage/insulin.log", O_RDONLY) < 0)
    exit(13);
  if(open("/dosage/insulin.log", O_RDWR) >= 0)
    exit(14);
  exit(0);
}

static void
as_doctor(void)
{
  if(setgid(2) < 0 || setuid(2) < 0)
    exit(20);
  if(open("/patient/records", O_RDONLY) < 0)
    exit(21);
  int fd = open("/dosage/insulin.log", O_RDWR);
  if(fd < 0)
    exit(22);
  if(write(fd, "d", 1) != 1)
    exit(23);
  close(fd);
  exit(0);
}

static void
as_patient_audit(void)
{
  struct audit_rec r[4];
  if(setgid(1) < 0 || setuid(1) < 0)
    exit(30);
  if(audit_read(1, r) >= 0)
    exit(31);
  exit(0);
}

int
main(int argc, char *argv[])
{
  char name[32];
  struct audit_rec recs[32];
  int pid, n;

  (void)argc;
  (void)argv;

  printf("seccompliance: starting (run as root after login)\n");

  if(whoami(name, sizeof(name)) < 0 || strcmp(name, "root") != 0)
    bad("whoami shows root");
  else
    ok("whoami shows root");

  userdel("pat");
  userdel("doc");

  if(useradd("pat", "passw", 1) < 0)
    bad("useradd patient");
  else
    ok("useradd patient");

  if(useradd("doc", "passw", 2) < 0)
    bad("useradd doctor");
  else
    ok("useradd doctor");

  pid = fork();
  if(pid == 0)
    as_patient();
  if(pid < 0)
    bad("fork patient");
  else if(waitstatus() != 0)
    bad("patient permission matrix");
  else
    ok("patient permission matrix");

  pid = fork();
  if(pid == 0)
    as_doctor();
  if(pid < 0)
    bad("fork doctor");
  else if(waitstatus() != 0)
    bad("doctor permission matrix");
  else
    ok("doctor permission matrix");

  pid = fork();
  if(pid == 0)
    as_patient_audit();
  if(pid < 0)
    bad("fork patient audit");
  else if(waitstatus() != 0)
    bad("audit_read EPERM for patient");
  else
    ok("audit_read EPERM for patient");

  n = audit_read(8, recs);
  if(n <= 0)
    bad("audit_read returns data for root");
  else
    ok("audit_read returns data for root");

  if(userdel("doc") < 0)
    bad("userdel doctor");
  else
    ok("userdel doctor");

  if(passwd("pat", "newpw") < 0)
    bad("root passwd change for pat");
  else
    ok("root passwd change for pat");

  if(open("/device/config", O_RDONLY) < 0)
    bad("root open device config");
  else
    ok("root open device config");

  if(open("/audit/syscall.log", O_RDONLY) < 0)
    bad("root read audit log file");
  else
    ok("root read audit log file");

  pid = fork();
  if(pid == 0){
    if(setgid(2) < 0 || setuid(2) < 0)
      exit(40);
    if(open("/device/config", O_RDONLY) >= 0)
      exit(41);
    exit(0);
  }
  if(pid < 0)
    bad("fork doctor2");
  else if(waitstatus() != 0)
    bad("doctor blocked from device config");
  else
    ok("doctor blocked from device config");

  printf("seccompliance: %d tests, %d failed\n", tests, failed);
  exit(failed ? 1 : 0);
}
