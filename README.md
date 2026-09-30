# dns sinkhole

Tiny rust DNS sinkhole service.

This intercepts and blocks DNS queries per a user-supplied blocklist in [Adblock Plus file format](https://adblockplus.org/filter-cheatsheet#blocking2).

```
OS stub resolver -> DNS blocker -> DNS server
```

GOALS:
- fast, minimal footprint; should comfortably run in the background on a modest laptop.
- simple logic with few dependencies (only handle as much DNS protocol as needed for effective use).
    - only RFC1035 and a little of RFC6891


TODO LIST:
- [x] better compressed message parsing
- [x] cli
- [ ] better tracing / logging
- [ ] TCP retry
- [ ] resolve all compiler warnings
