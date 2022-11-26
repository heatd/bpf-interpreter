/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is  released under the terms of the MIT License
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

/* Written using https://www.freebsd.org/cgi/man.cgi?bpf and linux/{filter,bpf-common}.h as sources */

using u64 = uint64_t;
using u32 = uint32_t;
using u16 = uint16_t;
using u8 = uint8_t;

struct bpf_instr
{
    u16 code;
    u8 jt;
    u8 jf;
    u32 k;
};

union bpfi {
    struct bpf_instr bi;
    u64 raw;
};

#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_LD          0x0
#define BPF_LDX         0x1
#define BPF_ST          0x2
#define BPF_STX         0x3
#define BPF_ALU         0x4
#define BPF_JMP         0x5
#define BPF_RET         0x6
#define BPF_MISC        0x7

/* LD/LDX widths */
/* W = 32-bits, H = 16-bits, 8 = 8-bits */
#define BPF_SIZE(code) ((code) & 0x18)
#define BPF_W          0x00
#define BPF_H          0x08
#define BPF_B          0x10

/* Addressing modes */
#define BPF_MODE(code) ((code) & 0xe0)
#define BPF_IMM        0x00
#define BPF_ABS        0x20
#define BPF_IND        0x40
#define BPF_MEM        0x60
#define BPF_LEN        0x80
#define BPF_MSH        0xa0

/* BPF_ALU/BPF_JMP have an OP field */
#define BPF_OP(code) ((code) & 0xf0)

/* ALU ops */
#define BPF_ADD      0x00
#define BPF_SUB      0x10
#define BPF_MUL      0x20
#define BPF_DIV      0x30
#define BPF_OR       0x40
#define BPF_AND      0x50
#define BPF_LSH      0x60
#define BPF_RSH      0x70
#define BPF_NEG      0x80
#define BPF_MOD      0x90
#define BPF_XOR      0xa0

/* JMP ops */
#define BPF_JA        0x00
#define BPF_JEQ       0x10
#define BPF_JGT       0x20
#define BPF_JGE       0x30
#define BPF_JSET      0x40

/* SRC field - used to distinguish if rhs = K or X in a bunch of ops */
#define BPF_SRC(code) ((code) & 0x08)
#define BPF_K         0x00
#define BPF_X         0x08


#define BPF_RVAL(code) ((code) & 0x18)
#define BPF_A          0x10

/* BPF_MISC operations */
#define BPF_MISCOP(code) ((code) & 0xf8)

// TAX = A -> X
// TXA = X -> A
#define BPF_TAX 0x00
#define BPF_TXA 0x80

#define BPF_STMT(code, k) {(unsigned short) (code), 0, 0, k}
#define BPF_JUMP(code, k, jt, jf) {(unsigned short) (code), jt, jf, k}

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

void do_bpf_st(struct bpf_state *state, struct bpf_instr *ins, u32 val)
{
    auto off = ins->k;

    if (off >= state->mem.len)
        errx(1, "Bad BPF_ST to %x (M[] len %zx)\n", off, state->mem.len);
    u32 *ptr = (u32 *) state->mem.data;
    ptr[off] = val;
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
}
