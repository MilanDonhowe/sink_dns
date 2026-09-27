# dns sinkhole

Tiny rust dns sinkhole service.

This intercepts and blocks DNS queries per a blocklist.  

OS stub resolver -> DNS blocker -> DNS server

TODO LIST:
- [ ] better compressed message parsing
- [ x ] cli
- [ ] better tracing / logging

