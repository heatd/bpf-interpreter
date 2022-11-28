/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <assert.h>
#include <err.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <vector>

/* Written using https://www.freebsd.org/cgi/man.cgi?bpf and linux/{filter,bpf-common}.h as sources */

#include "bpf_defs.h"

struct mem_region
{
    u8 *data;
    size_t len;
};

struct bpf_state
{
    struct mem_region data;
    u32 acc{0};
    u32 idx{0};
    u32 pc{0};
    struct mem_region mem;
    size_t accepted{0};
    bool ended{false};
    struct bpf_instr *prog;
    size_t prog_len;

    bpf_state(struct bpf_instr *prog, size_t proglen, mem_region &data)
        : data{data}, prog{prog}, prog_len{proglen}
    {
        // Don't hardcode?
        mem.data = new u8[4096];
        mem.len = 4096;
        memset(mem.data, 0, mem.len);
    }

    ~bpf_state()
    {
        delete[] mem.data;
    }
};

u32 do_bounded_access(int acclen, size_t offset, struct mem_region &reg, bool is_data = true)
{
    if (offset >= reg.len) [[unlikely]]
        errx(1, "bpf: Bad access to offset %zx (region is size %zx)\n", offset, reg.len);

    u8 *ptr = reg.data + offset;
    switch (acclen)
    {
        case BPF_B:
            return *ptr;
        case BPF_H:
            if (offset + 2 > reg.len)
                errx(1, "bpf: Bad access to offset %zx (region is size %zx)\n", offset, reg.len);
            u16 h;
            memcpy(&h, ptr, sizeof(h));
            return is_data ? ntohs(h) : h;
        case BPF_W:
            if (offset + 4 > reg.len)
                errx(1, "bpf: Bad access to offset %zx (region is size %zx)\n", offset, reg.len);
            u32 w;
            memcpy(&w, ptr, sizeof(u32));
            return is_data ? ntohl(w) : w;
        default:
            errx(1, "bpf: bad access size %x\n", acclen);
    }
}

void do_bpf_ld(struct bpf_state *state, struct bpf_instr *ins)
{
    auto size = BPF_SIZE(ins->code);
    auto mode = BPF_MODE(ins->code);
    switch (mode)
    {
        case BPF_IMM:
            state->acc = ins->k;
            break;
        case BPF_ABS:
            state->acc = do_bounded_access(size, ins->k, state->data);
            break;
        case BPF_IND:
            state->acc = do_bounded_access(size, ins->k + state->idx, state->data);
            break;
        case BPF_LEN:
            state->acc = state->data.len;
            break;
        case BPF_MEM:
            state->acc = do_bounded_access(size, ins->k * 4UL, state->mem, false);
            break;
    }
}

bool validate_bpf_size(int size)
{
    switch (size)
    {
        case BPF_W:
        case BPF_H:
        case BPF_B:
            return true;
        [[unlikely]]
        default:
            return false;
    }
}

bool validate_bpf_ld(struct bpf_state *state, struct bpf_instr *ins)
{
    auto size = BPF_SIZE(ins->code);
    auto mode = BPF_MODE(ins->code);

    switch (mode)
    {
        case BPF_IMM:
        case BPF_ABS:
        case BPF_IND:
        case BPF_LEN:
        case BPF_MEM:
            break;
        default:
            return false; // Bad mode
    }

    return validate_bpf_size(size);
}

void do_bpf_ldx(struct bpf_state *state, struct bpf_instr *ins)
{
    auto size = BPF_SIZE(ins->code);
    auto mode = BPF_MODE(ins->code);

    u8 msh_tmp = 0;

    switch (mode)
    {
        case BPF_IMM:
            state->idx = ins->k;
            break;
        case BPF_MSH:
            msh_tmp = (u8) do_bounded_access(BPF_B, ins->k, state->data);
            msh_tmp &= 0xf;
            state->idx = (u32) msh_tmp * 4;
            break;
        case BPF_LEN:
            state->idx = state->data.len;
            break;
        case BPF_MEM:
            state->idx = do_bounded_access(size, ins->k * 4UL, state->mem, false);
            break;
    }
}

bool validate_bpf_ldx(struct bpf_state *state, struct bpf_instr *ins)
{
    auto size = BPF_SIZE(ins->code);
    auto mode = BPF_MODE(ins->code);

    switch (mode)
    {
        case BPF_IMM:
        case BPF_MSH:
        case BPF_LEN:
        case BPF_MEM:
            break;
        default:
            return false; // Bad mode
    }

    return validate_bpf_size(size);
}

void do_bpf_st(struct bpf_state *state, struct bpf_instr *ins, u32 val)
{
    auto off = ins->k;

    if (off >= state->mem.len)
        errx(1, "Bad BPF_ST to %x (M[] len %zx)\n", off, state->mem.len);
    u32 *ptr = (u32 *) state->mem.data;
    ptr[off] = val;
}

bool validate_bpf_st(struct bpf_state *state, struct bpf_instr *ins)
{
    return ins->k < state->mem.len;
}

void do_bpf_alu(struct bpf_state *state, struct bpf_instr *ins)
{
    auto src = BPF_SRC(ins->code);
    auto op = BPF_OP(ins->code);

    auto rhs = src == BPF_K ? ins->k : state->idx;
    switch (op)
    {
        case BPF_ADD:
            state->acc += rhs;
            break;
        case BPF_SUB:
            state->acc -= rhs;
            break;
        case BPF_MUL:
            state->acc *= rhs;
            break;
        case BPF_DIV:
            if (rhs == 0)
                err(1, "BPF_DIV tried to divide by zero\n");
            state->acc /= rhs;
            break;
        case BPF_MOD:
            if (rhs == 0)
                err(1, "BPF_MOD tried to divide by zero\n");
            state->acc %= rhs;
            break;
        case BPF_OR:
            state->acc |= rhs;
            break;
        case BPF_XOR:
            state->acc ^= rhs;
            break;
        case BPF_AND:
            state->acc &= rhs;
            break;
        case BPF_LSH:
            // Note: rhs is unsigned so it's always >= 0
            if (/* rhs < 0  || */ rhs > 32)
                err(1, "BPF_LSH bad shift (%d)", rhs);
            state->acc <<= rhs;
            break;
        case BPF_RSH:
            if (/* rhs < 0  || */ rhs > 32)
                err(1, "BPF_LSH bad shift (%d)", rhs);
            state->acc >>= rhs;
            break;
        case BPF_NEG:
            state->acc = ~state->acc;
            break;
        default:
            err(1, "BPF_ALU bad op %x\n", op);
    }
}

bool validate_bpf_alu(struct bpf_state *state, struct bpf_instr *ins)
{
    auto src = BPF_SRC(ins->code);
    auto op = BPF_OP(ins->code);

    switch (op)
    {
        case BPF_ADD:
        case BPF_SUB:
        case BPF_MUL:
        case BPF_DIV:
        case BPF_OR:
        case BPF_AND:
        case BPF_LSH:
        case BPF_RSH:
        case BPF_NEG:
        case BPF_MOD:
        case BPF_XOR:
            break;
        default:
            return false; // Bad op
    }

    // Detect invalid ALU operations when the operand is const (K)

    switch (op)
    {
        case BPF_DIV:
        case BPF_MOD:
            if (src == BPF_K && ins->k == 0)
                return false; // Tried to divide by zero
            break;
        case BPF_LSH:
        case BPF_RSH:
            if (src == BPF_K && ins->k > 32)
                return false; // Bad shift
            break;
    }

    return true;
}

#define A state->acc
#define X state->idx

void do_bpf_jmp(struct bpf_state *state, struct bpf_instr *ins)
{
    auto src = BPF_SRC(ins->code);
    auto op = BPF_OP(ins->code);

    auto rhs = src == BPF_K ? ins->k : X;

    switch (op)
    {
        case BPF_JA:
            state->pc += ins->k;
            break;
        case BPF_JEQ:
            state->pc += (A == rhs) ? ins->jt : ins->jf;
            break;
        case BPF_JGT:
            state->pc += (A > rhs) ? ins->jt : ins->jf;
            break;
        case BPF_JGE:
            state->pc += (A >= rhs) ? ins->jt : ins->jf;
            break;
        case BPF_JSET:
            state->pc += (A & rhs) ? ins->jt : ins->jf;
            break;
        default:
            errx(1, "BPF_JMP bad op %x\n", op);
    }
}

constexpr size_t bitslong = sizeof(unsigned long) * 8;

bool bad_jmp(struct bpf_state *st, u32 dstpc, std::vector<unsigned long> &accessed)
{
    if (dstpc >= st->prog_len)
        return true;
    return accessed[dstpc / bitslong] & (1UL << (dstpc % bitslong));
}

bool validate_bpf_jmp(struct bpf_state *state, struct bpf_instr *ins, std::vector<unsigned long> &accessed)
{
    auto src = BPF_SRC(ins->code);
    auto op = BPF_OP(ins->code);

    switch (op)
    {
        case BPF_JA:
            return !bad_jmp(state, state->pc + ins->k, accessed);
        case BPF_JEQ:
        case BPF_JGT:
        case BPF_JGE:
        case BPF_JSET:
            return !bad_jmp(state, state->pc + ins->jt, accessed)
            && !bad_jmp(state, state->pc + ins->jf, accessed);
        default:
            return false;
    }
}

void do_bpf_ret(struct bpf_state *state, struct bpf_instr *ins)
{
    auto rval = BPF_RVAL(ins->code);

    size_t accept;

    switch (rval)
    {
        case BPF_K:
            accept = ins->k;
            break;
        case BPF_A:
            accept = A;
            break;
        default:
            errx(1, "BPF_RET bad BPF_RVAL %x\n", rval);
    }

    state->accepted = accept;
    state->ended = true;
}

bool validate_bpf_ret(struct bpf_state *state, struct bpf_instr *ins)
{
    auto rval = BPF_RVAL(ins->code);
    switch (rval)
    {
        case BPF_K:
        case BPF_A:
            return true;
        default:
            return false;
    }
}

void do_bpf_misc(struct bpf_state *state, struct bpf_instr *ins)
{
    auto op = BPF_MISCOP(ins->code);

    switch (op)
    {
        case BPF_TAX:
            X = A;
            break;
        case BPF_TXA:
            A = X;
            break;
        default:
            errx(1, "BPF_MISC bad op %x\n", op);
    }
}

bool validate_bpf_misc(struct bpf_state *state, struct bpf_instr *ins)
{
    auto op = BPF_MISCOP(ins->code);

    switch (op)
    {
        case BPF_TAX:
        case BPF_TXA:
            return true;
        default:
            return false;
    }
}

void do_instr(struct bpf_state *state, struct bpf_instr *ins)
{
    auto opclass = BPF_CLASS(ins->code);

    switch (opclass)
    {
        case BPF_LD:
            do_bpf_ld(state, ins);
            break;
        case BPF_LDX:
            do_bpf_ldx(state, ins);
            break;
        case BPF_ST:
            do_bpf_st(state, ins, state->acc);
            break;
        case BPF_STX:
            do_bpf_st(state, ins, state->idx);
            break;
        case BPF_ALU:
            do_bpf_alu(state, ins);
            break;
        case BPF_JMP:
            do_bpf_jmp(state, ins);
            break;
        case BPF_RET:
            do_bpf_ret(state, ins);
            break;
        case BPF_MISC:
            do_bpf_misc(state, ins);
            break;
        default:
            errx(1, "Bad bpf class %x\n", opclass);
    }
}

void do_interpret_bpf(struct bpf_state *state)
{
    auto prog = state->prog;
    while (!state->ended)
    {
        if (state->pc >= state->prog_len)
            errx(1, "BPF execution fell off the program (pc %x)\n", state->pc);

#ifdef CBPF_VERBOSE
        printf("PC %x\n", state->pc);
#endif
        auto ins = prog + state->pc;

#ifdef CBPF_VERBOSE
        bpfi i;
        i.bi = *ins;
        printf("insn %lx\n", i.raw);
#endif
        state->pc++;
        do_instr(state, ins);
    }
}

bool validate_insn(struct bpf_state *state, struct bpf_instr *ins, std::vector<unsigned long>& accessed)
{
    auto opclass = BPF_CLASS(ins->code);

    switch (opclass)
    {
        case BPF_LD:
            return validate_bpf_ld(state, ins);
        case BPF_LDX:
            return validate_bpf_ldx(state, ins);
        case BPF_ST:
        case BPF_STX:
            return validate_bpf_st(state, ins);
        case BPF_ALU:
            return validate_bpf_alu(state, ins);
        case BPF_JMP:
            return validate_bpf_jmp(state, ins, accessed);
        case BPF_RET:
            return validate_bpf_ret(state, ins);
        case BPF_MISC:
            return validate_bpf_misc(state, ins);
        default:
            // errx(1, "Bad bpf class %x\n", opclass);
            return false;
    }
}

bool validate_bpf_prog(struct bpf_state *state)
{
    std::vector<unsigned long> accessed;
    accessed.resize((state->prog_len / bitslong) + (state->prog_len % bitslong != 0), 0);

    while (true)
    {
        if (state->pc >= state->prog_len)
        {
            // BPF execution fell off the program. This is not an error because we do not
            // follow jumps nor exits here.
            break;
        }

        auto ins = state->prog + state->pc++;
        accessed[state->pc / bitslong] |= 1UL << (state->prog_len % bitslong);

        if (!validate_insn(state, ins, accessed))
            return false;
    }

    return true;
}

size_t interpret_bpf(struct bpf_instr *prog, size_t proglen, mem_region &&data)
{
    bpf_state st{prog, proglen, data};

    do_interpret_bpf(&st);
#ifdef CBPF_VERBOSE
    printf("Accepted: %zx\n", st.accepted);
#endif
    return st.accepted;
}

// accept-tcp-packet
struct bpf_instr insns[] = {
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12), BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 3),
    BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23), BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_TCP, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, (u_int) -1),  BPF_STMT(BPF_RET + BPF_K, 0),
};

struct bpf_instr tcp_80_prog[] = {
    { 0x28, 0, 0, 0x0000000c },
    { 0x15, 0, 6, 0x000086dd },
    { 0x30, 0, 0, 0x00000014 },
    { 0x15, 0, 15, 0x00000006 },
    { 0x28, 0, 0, 0x00000036 },
    { 0x15, 12, 0, 0x00000050 },
    { 0x28, 0, 0, 0x00000038 },
    { 0x15, 10, 11, 0x00000050 },
    { 0x15, 0, 10, 0x00000800 },
    { 0x30, 0, 0, 0x00000017 },
    { 0x15, 0, 8, 0x00000006 },
    { 0x28, 0, 0, 0x00000014 },
    { 0x45, 6, 0, 0x00001fff },
    { 0xb1, 0, 0, 0x0000000e },
    { 0x48, 0, 0, 0x0000000e },
    { 0x15, 2, 0, 0x00000050 },
    { 0x48, 0, 0, 0x00000010 },
    { 0x15, 0, 1, 0x00000050 },
    { 0x6, 0, 0, 0x00040000 },
    { 0x6, 0, 0, 0x00000000 },
};

u8 arp_packet[] = "\xff\xff\xff\xff\xff\xff\x52\x54\x00\x12\x34\x56\x08\x06\x00\x01"
                  "\x08\x00\x06\x04\x00\x01\x52\x54\x00\x12\x34\x56\x0a\x00\x02\x0f"
                  "\xff\xff\xff\xff\xff\xff\x0a\x00\x02\x02";

u8 dns_packet[] = "\x52\x54\x00\x12\x34\x56\x52\x56\x00\x00\x11\x11\x86\xdd\x60\x00"
                  "\x00\x00\x00\x34\x11\xff\x26\x06\x47\x00\x47\x00\x00\x00\x00\x00"
                  "\x00\x00\x00\x00\x11\x11\xfe\xc0\x00\x00\x00\x00\x00\x00\x50\x54"
                  "\x00\xff\xfe\x12\x34\x56\x00\x35\x83\xdd\x00\x34\x4c\xa3\x3b\x50"
                  "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00\x06\x67\x6f\x6f\x67\x6c"
                  "\x65\x03\x63\x6f\x6d\x00\x00\x01\x00\x01\xc0\x0c\x00\x01\x00\x01"
                  "\x00\x00\x00\x35\x00\x04\x8e\xfa\xc8\x6e";

u8 tcp_packet[] = "\x52\x55\x0a\x00\x02\x02\x52\x54\x00\x12\x34\x56\x08\x00\x45\x00"
                  "\x00\x2c\x80\x1a\x00\x00\x40\x06\xa7\x9a\x0a\x00\x02\x0f\x8e\xfa"
                  "\xb8\x0e\xbd\x7b\x00\x50\x5e\x4e\xb1\x01\x00\x00\x00\x00\x60\x02"
                  "\xff\xff\x77\xf3\x00\x00\x02\x04\x05\xb4";

int main()
{
    assert(interpret_bpf(insns, sizeof(insns) / sizeof(insns[0]),
                         mem_region{arp_packet, sizeof(arp_packet)}) == 0);
    assert(interpret_bpf(insns, sizeof(insns) / sizeof(insns[0]),
                         mem_region{dns_packet, sizeof(dns_packet)}) == 0);
    assert(interpret_bpf(insns, sizeof(insns) / sizeof(insns[0]),
                         mem_region{tcp_packet, sizeof(tcp_packet)}) == (uint) -1);
    assert(interpret_bpf(tcp_80_prog, sizeof(tcp_80_prog) / sizeof(tcp_80_prog[0]),
                         mem_region{arp_packet, sizeof(arp_packet)}) == 0);
    assert(interpret_bpf(tcp_80_prog, sizeof(tcp_80_prog) / sizeof(tcp_80_prog[0]),
                         mem_region{dns_packet, sizeof(dns_packet)}) == 0);
    assert(interpret_bpf(tcp_80_prog, sizeof(tcp_80_prog) / sizeof(tcp_80_prog[0]),
                         mem_region{tcp_packet, sizeof(tcp_packet)}) == (uint) 0x00040000);
}
