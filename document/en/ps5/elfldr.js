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


DataView.prototype.getUint64 = function(byteOffset, littleEndian) {
    let low, high;
    if (littleEndian === undefined) littleEndian = true;

    if (littleEndian) {
        low  = this.getUint32(byteOffset,     true);
        high = this.getUint32(byteOffset + 4, true);
    } else {
        high = this.getUint32(byteOffset,     false);
        low  = this.getUint32(byteOffset + 4, false);
    }

    const value = high * 4294967296 + low; // 4294967296 == 2**32
    if (!Number.isSafeInteger(value)) {
        throw new Error("Overflow: value exceeds 53-bit safe integer limit");
    }
    return value;
};

DataView.prototype.setUint64 = function(byteOffset, value, littleEndian) {
    if (littleEndian === undefined) littleEndian = true;

    if (!Number.isSafeInteger(value)) {
        throw new Error("Overflow: value exceeds 53-bit safe integer limit");
    }

    const high = Math.floor(value / 4294967296);
    const low  = value >>> 0;

    if (littleEndian) {
        this.setUint32(byteOffset,     low,  true);
        this.setUint32(byteOffset + 4, high, true);
    } else {
        this.setUint32(byteOffset,     high, false);
        this.setUint32(byteOffset + 4, low,  false);
    }
};

const Syscall = {
    async mmap(addr, length, prot, flags, fd, offset) {
        throw new Error("Syscall.mmap: not implemented");
    },
    async munmap(addr, size) {
        throw new Error("Syscall.munmap: not implemented");
    },
    async mprotect(addr, size, flags) {
        throw new Error("Syscall.mprotect: not implemented");
    },
    async jitshm_create(addr, size, prot) {
        throw new Error("Syscall.jitshm_create: not implemented");
    },
    async jitshm_alias(fd, prot) {
        throw new Error("Syscall.jitshm_alias: not implemented");
    },
    async close(fd) {
        throw new Error("Syscall.close: not implemented");
    }
};

const LibC = {
    malloc(size) {
        throw new Error("LibC.malloc: not implemented");
    },
    free(addr) {
        throw new Error("LibC.free: not implemented");
    },
    memcpy(dst, src, size) {
        throw new Error("LibC.memcpy: not implemented");
    }
};

const JSIO = {
    copyin(buf, addr) {
        throw new Error("JSIO.copyin: not implemented");
    }
};


const ElfLoader = {
    PROT_READ:  0x1,
    PROT_WRITE: 0x2,
    PROT_EXEC:  0x4,

    MAP_SHARED:    0x001,
    MAP_PRIVATE:   0x002,
    MAP_FIXED:     0x010,
    MAP_ANONYMOUS: 0x1000,

    PAGE_SIZE: 0x4000,

    PF_X: 0x1,
    PF_W: 0x2,
    PF_R: 0x4,

    EHDR_SIZE:      0x40,
    EHDR_OFF_ENTRY: 0x18,
    EHDR_OFF_PHOFF: 0x20,
    EHDR_OFF_SHOFF: 0x28,
    EHDR_OFF_PHNUM: 0x38,
    EHDR_OFF_SHNUM: 0x3c,

    PHDR_SIZE:       0x38,
    PHDR_OFF_TYPE:   0x00,
    PHDR_OFF_FLAGS:  0x04,
    PHDR_OFF_OFFSET: 0x08,
    PHDR_OFF_VADDR:  0x10,
    PHDR_OFF_FILESZ: 0x20,
    PHDR_OFF_MEMSZ:  0x28,

    SHDR_SIZE:       0x40,
    SHDR_OFF_TYPE:   0x04,
    SHDR_OFF_OFFSET: 0x18,
    SHDR_OFF_SIZE:   0x20,

    RELA_SIZE:       0x18,
    RELA_OFF_OFFSET: 0x00,
    RELA_OFF_INFO:   0x08,
    RELA_OFF_ADDEND: 0x10,

    R_X86_64_RELATIVE: 8,
    SHT_RELA:          4,
    PT_LOAD:           1,

    ROUND_PG: function(x) {
        return (x + (ElfLoader.PAGE_SIZE - 1)) & ~(ElfLoader.PAGE_SIZE - 1);
    },

    TRUNC_PG: function(x) {
        return x & ~(ElfLoader.PAGE_SIZE - 1);
    },

    PFLAGS: function(x) {
        let y = 0;
        if (x & ElfLoader.PF_R) y |= ElfLoader.PROT_READ;
        if (x & ElfLoader.PF_W) y |= ElfLoader.PROT_WRITE;
        if (x & ElfLoader.PF_X) y |= ElfLoader.PROT_EXEC;
        return y;
    },

    create: function(syscall, libc, jsio) {
        return {
            syscall: syscall,
            libc:    libc,
            jsio:    jsio,

            pt_reload: async function(elf, phdr, base) {
                const p_vaddr = elf.getUint64(phdr + ElfLoader.PHDR_OFF_VADDR, true);
                const p_memsz = elf.getUint64(phdr + ElfLoader.PHDR_OFF_MEMSZ, true);
                const p_flags = elf.getUint32(phdr + ElfLoader.PHDR_OFF_FLAGS, true);
                const memsz   = ElfLoader.ROUND_PG(p_memsz);
                const prot    = ElfLoader.PFLAGS(p_flags);
                const addr    = base + p_vaddr;

                // backup the existing segment bytes
                const data = this.libc.malloc(memsz);
                this.libc.memcpy(data, addr, memsz);

                // create a jit-shm descriptor
                const shm_fd = await this.syscall.jitshm_create(
                    0, memsz, prot | ElfLoader.PROT_READ | ElfLoader.PROT_WRITE
                );

                // map shm at the original address (replaces the anonymous mapping)
                await this.syscall.mmap(addr, memsz, prot,
                    ElfLoader.MAP_FIXED | ElfLoader.MAP_SHARED, shm_fd, 0);

                // create a writable alias
                const alias_fd = await this.syscall.jitshm_alias(
                    shm_fd, ElfLoader.PROT_READ | ElfLoader.PROT_WRITE
                );

                // map the alias somewhere writable
                const rwaddr = await this.syscall.mmap(
                    0, memsz,
                    ElfLoader.PROT_READ | ElfLoader.PROT_WRITE,
                    ElfLoader.MAP_SHARED, alias_fd, 0
                );

                // restore the original bytes through the writable alias
                this.libc.memcpy(rwaddr, data, memsz);

                // clean up
                await this.syscall.munmap(rwaddr, memsz);
                this.libc.free(data);
                await this.syscall.close(alias_fd);
                await this.syscall.close(shm_fd);
            },

            load: async function(url) {
                const resp = await fetch(url);
                if (!resp.ok) {
                    throw new Error("Network error " + resp.status
                        + ": failed to fetch " + url);
                }

                const elf     = new DataView(await resp.arrayBuffer());
                const e_entry = elf.getUint64(ElfLoader.EHDR_OFF_ENTRY, true);
                const e_phoff = elf.getUint64(ElfLoader.EHDR_OFF_PHOFF, true);
                const e_shoff = elf.getUint64(ElfLoader.EHDR_OFF_SHOFF, true);
                const e_phnum = elf.getUint16(ElfLoader.EHDR_OFF_PHNUM, true);
                const e_shnum = elf.getUint16(ElfLoader.EHDR_OFF_SHNUM, true);

                // compute the virtual-address span of PT_LOAD segments
                let min_vaddr = Number.MAX_SAFE_INTEGER;
                let max_vaddr = 0;
                for (let i = 0; i < e_phnum; i++) {
                    const phdr   = e_phoff + i * ElfLoader.PHDR_SIZE;
                    const p_type = elf.getUint32(phdr + ElfLoader.PHDR_OFF_TYPE, true);
                    if (p_type !== ElfLoader.PT_LOAD) continue;

                    const p_vaddr = elf.getUint64(phdr + ElfLoader.PHDR_OFF_VADDR, true);
                    const p_memsz = elf.getUint64(phdr + ElfLoader.PHDR_OFF_MEMSZ, true);
                    if (!p_memsz) continue;

                    if (p_vaddr < min_vaddr) min_vaddr = p_vaddr;
                    if (p_vaddr + p_memsz > max_vaddr) max_vaddr = p_vaddr + p_memsz;
                }

                if (min_vaddr === Number.MAX_SAFE_INTEGER) {
                    throw new Error("ELF has no PT_LOAD segments");
                }

                min_vaddr = ElfLoader.TRUNC_PG(min_vaddr);
                max_vaddr = ElfLoader.ROUND_PG(max_vaddr);

                const load_size = max_vaddr - min_vaddr;

                // reserve an anonymous rw mapping to stage the image
                const base = await this.syscall.mmap(
                    0x0000000926100000, load_size,
                    ElfLoader.PROT_READ | ElfLoader.PROT_WRITE,
                    ElfLoader.MAP_PRIVATE | ElfLoader.MAP_ANONYMOUS,
                    0xffffffff, 0
                );

                // staging buffer in JS heap
                const buf = new ArrayBuffer(load_size);
                const img = new DataView(buf);

                // copy PT_LOAD file bytes into the staging buffer
                for (let i = 0; i < e_phnum; i++) {
                    const phdr   = e_phoff + i * ElfLoader.PHDR_SIZE;
                    const p_type = elf.getUint32(phdr + ElfLoader.PHDR_OFF_TYPE, true);
                    if (p_type !== ElfLoader.PT_LOAD) continue;

                    const p_memsz  = elf.getUint64(phdr + ElfLoader.PHDR_OFF_MEMSZ,  true);
                    if (!p_memsz) continue;

                    const p_vaddr  = elf.getUint64(phdr + ElfLoader.PHDR_OFF_VADDR,  true);
                    const p_filesz = elf.getUint64(phdr + ElfLoader.PHDR_OFF_FILESZ, true);
                    const p_offset = elf.getUint64(phdr + ElfLoader.PHDR_OFF_OFFSET, true);

                    for (let j = 0; j < p_filesz; j++) {
                        img.setUint8(p_vaddr - min_vaddr + j, elf.getUint8(p_offset + j));
                    }
                }

                // apply relocations from section headers
                for (let i = 0; i < e_shnum; i++) {
                    const shdr    = e_shoff + i * ElfLoader.SHDR_SIZE;
                    const sh_type = elf.getUint32(shdr + ElfLoader.SHDR_OFF_TYPE, true);
                    if (sh_type !== ElfLoader.SHT_RELA) continue;

                    const sh_offset = elf.getUint64(shdr + ElfLoader.SHDR_OFF_OFFSET, true);
                    const sh_size   = elf.getUint64(shdr + ElfLoader.SHDR_OFF_SIZE,   true);

                    for (let j = 0; j < sh_size / ElfLoader.RELA_SIZE; j++) {
                        const rela   = sh_offset + ElfLoader.RELA_SIZE * j;
                        const r_info = elf.getUint64(rela + ElfLoader.RELA_OFF_INFO, true);

                        if ((r_info & 0xFFFFFFFF) !== ElfLoader.R_X86_64_RELATIVE) continue;

                        const r_offset = elf.getUint64(rela + ElfLoader.RELA_OFF_OFFSET, true);
                        const r_addend = elf.getUint64(rela + ElfLoader.RELA_OFF_ADDEND, true);

                        img.setUint64(r_offset - min_vaddr, base + r_addend, true);
                    }
                }

                // bulk-copy the staged image into the mmap'd region
                this.jsio.copyin(img, base);

                // apply protection flags to each PT_LOAD segment
                for (let i = 0; i < e_phnum; i++) {
                    const phdr   = e_phoff + i * ElfLoader.PHDR_SIZE;
                    const p_type = elf.getUint32(phdr + ElfLoader.PHDR_OFF_TYPE, true);
                    if (p_type !== ElfLoader.PT_LOAD) continue;

                    const p_memsz = elf.getUint64(phdr + ElfLoader.PHDR_OFF_MEMSZ, true);
                    if (!p_memsz) continue;

                    const p_flags = elf.getUint32(phdr + ElfLoader.PHDR_OFF_FLAGS, true);
                    const p_vaddr = elf.getUint64(phdr + ElfLoader.PHDR_OFF_VADDR, true);

                    if (p_flags & ElfLoader.PF_X) {
                        await this.pt_reload(elf, phdr, base);
                    } else {
                        await this.syscall.mprotect(
                            base + p_vaddr - min_vaddr,
                            ElfLoader.ROUND_PG(p_memsz),
                            ElfLoader.PFLAGS(p_flags)
                        );
                    }
                }

                return base + e_entry; // absolute entry-point address
            }
        };
    }
};

/*
  Local Variables:
  js-indent-level: 4
  indent-tabs-mode: nil
  End:
*/
