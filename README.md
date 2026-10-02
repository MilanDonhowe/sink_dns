# dns sinkhole

Tiny rust DNS sinkhole service.

This intercepts and blocks DNS queries per a user-supplied blocklist in [Adblock Plus file format](https://adblockplus.org/filter-cheatsheet#blocking2).


```
OS stub resolver -> sink_dns -> DNS server
                    sink_dns sends null reply for blocked domains in A/AAAA domain requests
                    otherwise it acts as a proxy to the real DNS service.
```

## demo:

![cli gif of dig queries running against the sinkhole](https://raw.githubusercontent.com/MilanDonhowe/sink_dns/main/misc/demo.gif)

## Goals & TODOs
GOALS:
- fast, minimal footprint; should comfortably run in the background on a modest laptop.
- simple logic with few dependencies (only handle as much DNS protocol as needed for effective use).
    - only RFC1035 and a little of RFC6891


TODO LIST:
- [x] better compressed message parsing
- [x] cli
- [ ] rotating blocklist remote
- [ ] better tracing / logging
- [ ] TCP retry
- [x] resolve all compiler warnings
