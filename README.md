# Medical Device Security OS (xv6-riscv)

**University Name:** [Insert your University Name]
**Course Code:** CCY4304 (Operating Systems Security)
**Lecturers:** Prof. Dr. Ayman Adel, TA Abdelrahman Solyman
**Student Name:** [Insert your Name]

### Project Description
This project extends the vanilla xv6-riscv kernel with three integrated medical-grade security layers:
1. **User Authentication**: Role-based access control, hashed credentials, and login enforcement.
2. **File Access Control**: UNIX-style file permissions (chmod/chown) protecting critical medical records.
3. **Syscall Audit Log**: Persistent ring-buffer auditing to trace medical device interactions.

This project was built to simulate the security architecture required by FDA and IEC 62443 for life-critical embedded devices.
