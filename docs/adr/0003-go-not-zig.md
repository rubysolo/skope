# Go, not Zig

Skope is written in Go. Both produce a single static binary, but this service is I/O-bound (HTTP, zip downloads, SMTP, SQLite), so Zig's performance would not show. Go's standard library covers HTTP, TLS, SMTP, zip and crypto, and there are mature pure-Go libraries for SQLite, CycloneDX and per-ecosystem version comparison. In Zig most of those would be hand-written. Pure-Go SQLite (no cgo) keeps cross-compilation and the scratch/distroless image trivial.
