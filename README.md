# Medical Device Security OS (xv6-riscv)



### Project Description
This project extends the vanilla xv6-riscv kernel with three integrated medical-grade security layers:
1. **User Authentication**: Role-based access control, hashed credentials, and login enforcement.
2. **File Access Control**: UNIX-style file permissions (chmod/chown) protecting critical medical records.
3. **Syscall Audit Log**: Persistent ring-buffer auditing to trace medical device interactions.


