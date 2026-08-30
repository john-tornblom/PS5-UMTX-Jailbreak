/* Copyright (C) 2026 John Törnblom

This program is free software; you can redistribute it and/or modify it
under the terms of the GNU General Public License as published by the
Free Software Foundation; either version 3, or (at your option) any
later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; see the file COPYING. If not, see
<http://www.gnu.org/licenses/>.  */

function _numToInt64(n) {
    if (n !== null && typeof n === 'object' && 'low' in n) {
        return n;
    }
    return new int64(n >>> 0, Math.floor(n / 4294967296));
}

function _int64ToNum(v) {
    if (typeof v === 'number') return v;
    return v.hi * 4294967296 + (v.low >>> 0);
}

const umtxSyscall = {
    async mmap(addr, length, prot, flags, fd, offset) {
        const ret = p.malloc(0x8);
        await chain.add_syscall_ret(ret, SYS_MMAP,
            _numToInt64(addr), length, prot, flags, fd, offset);
        await chain.run();
        return _int64ToNum(p.read8(ret));
    },

    async munmap(addr, size) {
        await chain.syscall(SYS_MUNMAP, _numToInt64(addr), size);
    },

    async mprotect(addr, size, prot) {
        await chain.syscall(SYS_MPROTECT, _numToInt64(addr), size, prot);
    },

    async jitshm_create(addr, size, prot) {
        const r = await chain.syscall(SYS_JITSHM_CREATE, addr, size, prot);
        return r.low;
    },

    async jitshm_alias(fd, prot) {
        const r = await chain.syscall(SYS_JITSHM_ALIAS, fd, prot);
        return r.low;
    },

    async close(fd) {
        await chain.syscall(SYS_CLOSE, fd);
    }
};

const umtxLibC = {
    malloc: function(size) {
        return p.malloc(size);
    },

    free: function(_addr) {
    },

    memcpy: function(dst, src, size) {
        if (!size) {
            return;
        }

        const s = _numToInt64(src);
        const d = _numToInt64(dst);

        const srcArr = p.array_from_address(s, size);
        const snapshot = new Uint8Array(new Uint8Array(srcArr.buffer, 0, size));
        const dstArr = p.array_from_address(d, size);
        new Uint8Array(dstArr.buffer, 0, size).set(snapshot);
    }
};

const umtxJsio = {
    copyin: function(buf, addr) {
        const bytes = new Uint8Array(buf.buffer);
        const dst = p.array_from_address(_numToInt64(addr), bytes.length);
        new Uint8Array(dst.buffer, 0, bytes.length).set(bytes);
    }
};

async function run_elfldr(opts) {
    const dlsym_addr  = opts.dlsym_addr;
    const pipe_mem    = opts.pipe_mem;
    const pipe_addr   = opts.pipe_addr;
    const kdata_base  = opts.kdata_base;
    const master_sock = opts.master_sock;
    const victim_sock = opts.victim_sock;

    debug_log("[elfldr] loading elfldr.elf ...");

    const loader = ElfLoader.create(umtxSyscall, umtxLibC, umtxJsio);

    let entry;
    try {
        entry = await loader.load("elfldr.elf");
    } catch (e) {
        debug_log("[elfldr] load failed: " + e);
        return;
    }
    debug_log("[elfldr] entry point: 0x" + entry.toString(16));

    // Build the argument block the payload entry-point receives.
    const args   = p.malloc(0x8 * 6);
    for (let i = 0; i < 0x8 * 6; i++) p.write1(args.add32(i), 0);

    const rwpair = p.malloc(0x8);
    p.write4(rwpair.add32(0x00), master_sock);
    p.write4(rwpair.add32(0x04), victim_sock);

    const payout = p.malloc(0x8);
    p.write8(payout, 0);

    p.write8(args.add32(0x00), dlsym_addr);  // arg1 = dlsym_t* dlsym
    p.write8(args.add32(0x08), pipe_mem);    // arg2 = int *rwpipe[2]
    p.write8(args.add32(0x10), rwpair);      // arg3 = int *rwpair[2]
    p.write8(args.add32(0x18), pipe_addr);   // arg4 = uint64_t kpipe_addr
    p.write8(args.add32(0x20), kdata_base);  // arg5 = uint64_t kdata_base_addr
    p.write8(args.add32(0x28), payout);      // arg6 = int *payloadout

    const pthread_handle = p.malloc(0x8);
    p.write8(pthread_handle, 0);

    await chain.call(
        libKernelBase.add32(OFFSET_lk_pthread_create_name_np),
        pthread_handle,          // pthread_t *thread
        0,                       // pthread_attr_t *attr  (NULL = defaults)
        _numToInt64(entry),      // void *(*start_routine)(void *)
        args,                    // void *arg
        p.stringify("elfldr")    // const char *name
    );
    
    debug_log("[elfldr] ELF loader listening on :9021");
}

/*
  Local Variables:
  js-indent-level: 4
  indent-tabs-mode: nil
  End:
*/
