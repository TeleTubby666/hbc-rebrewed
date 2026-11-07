#!/usr/bin/env python3
# Print DOL segment table and flag sizes that are not 32-byte aligned.
import struct, sys
d = open(sys.argv[1], 'rb').read()
offs = struct.unpack('>18I', d[0:0x48])
addrs = struct.unpack('>18I', d[0x48:0x90])
sizes = struct.unpack('>18I', d[0x90:0xd8])
bss_addr, bss_size, entry = struct.unpack('>3I', d[0xd8:0xe4])
bad = 0
for i in range(18):
    if sizes[i]:
        kind = 'text%d' % i if i < 7 else 'data%d' % (i - 7)
        flag = '' if sizes[i] % 32 == 0 and offs[i] % 32 == 0 else '  <-- NOT 32-byte aligned'
        bad += bool(flag)
        print('%-6s off=0x%06x addr=0x%08x size=0x%06x%s' % (kind, offs[i], addrs[i], sizes[i], flag))
print('bss    addr=0x%08x size=0x%x  entry=0x%08x' % (bss_addr, bss_size, entry))
print('unaligned segments:', bad)
