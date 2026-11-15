# Memory

Where qlogin and qlogind allocate. Audited 2026-11-15: `tests/run_qdbus`, `tests/run_login1` (qlogind and the test client both
ASan + UBSan + LeakSanitizer) and `tests/run_qlogin` (greeter and qlogind rebuilt with ASan + UBSan, run in tmux on a private
bus with a fake PAM stack) are clean, no sanitizer report.

## What uses the heap

- `qd_buf` (qdbus.h): one growable byte buffer per message being built, `realloc` doubling, `abort()` on out of memory. Justified,
  the size is not known up front. `qd_conn.rb` is the same for the receive side.
- One `malloc` per received message (`m->raw`) plus one queue node (`qd_msg`) when a message arrives while a call waits for its
  reply. The `qdbus_test` suite does 7 malloc and 14 realloc in total, so this is not hot. If it ever matters: a per-connection
  receive arena reset after each dispatch (messages are handled one at a time), and a fixed pool for the queue nodes.
- Greeter (greeter.h): `calloc` and `strdup` in the PAM conversation (libpam takes ownership and frees them, so the heap is
  required by the interface); about ten `strdup` for the session environment in the forked child right before `exec`, which
  the exec reclaims.
- qlogind state (sessions, seats, inhibitors) is static tables, no heap.

## Candidates

None worth a rewrite. The receive arena above is the only one, and it would save a handful of allocations per login.
