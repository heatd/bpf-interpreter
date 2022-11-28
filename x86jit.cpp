/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */

#include <netinet/ether.h>
#include <netinet/ip.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <vector>

#include "bpf_defs.h"

// clang-format off

#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7
#define R8  0
#define R9  1
#define R10 2
#define R11 3
#define R12 4
#define R13 5
#define R14 6
#define R15 7

#define EAX  0
#define ECX  1
#define EDX  2
#define EBX  3
#define ESP  4
#define EBP  5
#define ESI  6
#define EDI  7
#define R8D  0
#define R9D  1
#define R10D 2
#define R11D 3
#define R12D 4
#define R13D 5
#define R14D 6
#define R15D 7

#define AX 0
#define CX 1
#define DX 2
#define BX 3
#define SP 4
#define BP 5
#define SI 6
#define DI 7

#define AL 0
#define CL 1
#define DL 2
#define BL 3

#define REXW 0x48

struct jmp_reloc
{
    enum class jmp_type
    {
        JMP_TYPE_REL_IMM32
    } type;

    u32 location;
    u32 dst_bpf_pc;
};

class stream
{
private:
    std::vector<u8> data_;
    std::deque<jmp_reloc> jmps;
    bool needs_bswap{false};
public:
    void push_back(u8 byte)
    {
        data_.push_back(byte);
    }

    void add_jmp(jmp_reloc::jmp_type type, u32 progpc, u32 dstbpfpc)
    {
        jmps.push_back(jmp_reloc{type, progpc, dstbpfpc});
    }

    void handle_jmp(u32 bpfpc, u32 realpc)
    {
        auto find_jmp = [&](const jmp_reloc &rel) -> bool
        {
            return bpfpc == rel.dst_bpf_pc;
        };
    
        auto it = std::find_if(jmps.begin(), jmps.end(), find_jmp);

        while (it != jmps.end())
        {
            jmp_reloc &rel = *it;
            u32 target = realpc - rel.location - 5;
            memcpy(&data_[rel.location + 1], &target, sizeof(u32));

            it = std::find_if(it + 1, jmps.end(), find_jmp);
        }
    }

    u8 *data()
    {
        return data_.data(); 
    }

    size_t size() const
    {
        return data_.size();
    }

    bool should_swap() const
    {
        return needs_bswap;
    }
};

void jit(stream &s, u8 byte)
{
    s.push_back(byte);
}

void jits(stream &s, u8 *bytes, size_t n)
{
    while(n--)
        s.push_back(*bytes++);
}

void jitl(stream &s, u32 word)
{
    u8 str[4];
    memcpy(&str, &word, sizeof(word));
    jits(s, str, sizeof(str));
}


#define PUSHrq(str, reg) \
    jit(str, 0x50 | (reg))
#define POPrq(str, reg) \
    jit(str, 0x58 | (reg))

#define MODRM_REG (3 << 6)

#define MOVr32(str, src, dst) \
    jit(str, 0x89); \
    jit(str, MODRM_REG | ((src) << 3) | (dst))

#define MOVr64(str, src, dst) \
    jit(str, REXW); \
    MOVr32(str, src, dst)

#define MOVli(str, src, imm) \
    jit(str, 0xb8 + (src)); \
    jitl(str, imm)

#define XORr32(str, src, dst) \
    jit(str, 0x31); \
    jit(str, (3 << 6) | ((src) << 3) | (dst))

void mov_imm_reg(stream &strm, u32 imm, int reg)
{
    if (imm == 0)
    {
        // xor reg, reg is the fastest zeroing pattern
        XORr32(strm, reg, reg);
    }
    else
    {
        MOVli(strm, reg, imm);
    }
}

#define MOVldl(str, src, srcoff, dstreg) \
    jit(str, 0x8b); \
    jit(str, (1 << 7) | ((dstreg) << 3) | (src)); \
    jitl(str, srcoff)

#define MOVldw(str, src, srcoff, dstreg) \
    jit(str, 0x66); \
    jit(str, 0x8b); \
    jit(str, (1 << 7) | ((dstreg) << 3) | (src)); \
    jitl(str, srcoff)

#define MOVldb(str, src, srcoff, dstreg) \
    jit(str, 0x8a); \
    jit(str, (1 << 7) | ((dstreg) << 3) | (src)); \
    jitl(str, srcoff)

#define RET(str) jit(str, 0xc3)

#define LEA(str, src, srcoff, dstreg) \
    jit(str, 0x48); \
    jit(str, 0x8d); \
    jit(str, (1 << 7) | ((dstreg) << 3) | (src)); \
    jitl(str, srcoff)

#define MOVldla(str, src, addendreg, dstreg) \
    jit(str, 0x8b); \
    jit(str, (dstreg) << 3 | (1 << 2)); \
    jit(str, ((addendreg) << 3) | (src));

// TRUNCAB = Truncate A to byte = and $0xff, %eax
#define TRUNCAB(str) \
    jit(str, 0x25); \
    jitl(str, 0xff);

// TRUNCAW = Truncate A to word = and $0xffff, %eax
#define TRUNCAW(str) \
    jit(str, 0x25); \
    jitl(str, 0xffff);

#define MOVzw(str, src, srcoff, dstreg) \
    jit(str, 0x0f); \
    jit(str, 0xb7); \
    jit(str, (1 << 7) | ((dstreg) << 3) | (src)); \
    jitl(str, srcoff)

#define MOVzw_short(str, src, srcoff, dstreg) \
    jit(str, 0x0f); \
    jit(str, 0xb7); \
    jit(str, (1 << 6) | ((dstreg) << 3) | (src)); \
    jit(str, (u8) (srcoff))

#define MOVzb(str, src, srcoff, dstreg) \
    jit(str, 0x0f); \
    jit(str, 0xb6); \
    jit(str, (1 << 7) | ((dstreg) << 3) | (src)); \
    jitl(str, srcoff)

#define MOVzb_short(str, src, srcoff, dstreg) \
    jit(str, 0x0f); \
    jit(str, 0xb6); \
    jit(str, (1 << 6) | ((dstreg) << 3) | (src)); \
    jit(str, (u8) (srcoff))

#define MOVzwa(str, src, addendreg, dstreg) \
    jit(str, 0x0f); \
    jit(str, 0xb7); \
    jit(str, (dstreg) << 3 | (1 << 2)); \
    jit(str, ((addendreg) << 3) | (src));

#define MOVzba(str, src, addendreg, dstreg) \
    jit(str, 0x0f); \
    jit(str, 0xb6); \
    jit(str, (dstreg) << 3 | (1 << 2)); \
    jit(str, ((addendreg) << 3) | (src));

#define BSWAP16(str) \
    jit(str, 0x86); \
    jit(str, 0xe0)

#define BSWAP32(str, reg) \
    jit(str, 0x0f); \
    jit(str, (3 << 6) | (8 + (reg))) 

#define ANDB4(str, reg, imm4) \
    jit(str, 0x83); \
    jit(str, 0xe0 + (reg)); \
    jit(str, (imm4))

#define SHLi(str, imm, reg) \
    jit(str, 0xc1); \
    jit(str, 0xe0 + (reg)); \
    jit(str, (imm))

#define MOVstli8(str, reg, dstreg, off) \
    jit(str, 0x89); \
    jit(str, (1 << 6) | (reg) << 3 | (dstreg)); \
    jit(str, (u8) (off))

#define MOVstli32(str, reg, dstreg, off) \
    jit(str, 0x89); \
    jit(str, (1 << 7) | (reg) << 3 | (dstreg)); \
    jitl(str, off)

#define INC(str, reg) \
    jit(str, 0xff); \
    jit(str, 0xc0 | (reg))

#define DEC(str, reg) \
    jit(str, 0xff); \
    jit(str, 0xc8 + (reg))

#define ADDi32AX(str, imm) \
    jit(str, 0x05); \
    jitl(str, imm)

#define ADDi32(str, imm, reg) \
    jit(str, 0x81); \
    jit(str, 0xc0 | (reg)); \
    jitl(str, imm)

#define SUBi32AX(str, imm) \
    jit(str, 0x2d); \
    jitl(str, imm)

#define SUBi32(str, imm, reg) \
    jit(str, 0x81); \
    jit(str, 0xe8 + (reg)); \
    jitl(str, imm)

void add_imm_r32(stream &strm, int reg, u32 imm)
{
    if (reg == EAX)
    {
        ADDi32AX(strm, imm);
    }
    else
    {
        ADDi32(strm, imm, reg);
    }
}

void sub_imm_r32(stream &strm, int reg, u32 imm)
{
    if (reg == EAX)
    {
        SUBi32AX(strm, imm);
    }
    else
    {
        SUBi32(strm, imm, reg);
    }
}

#define ADDr32(str, srcreg, dstreg) \
    jit(str, 0x01); \
    jit(str, 0xc0 | (srcreg) << 3 | (dstreg))

#define SUBr32(str, srcreg, dstreg) \
    jit(str, 0x01); \
    jit(str, 0xc0 | (srcreg) << 3 | (dstreg))

#define NEGr32(str, reg) \
    jit(str, 0xf7); \
    jit(str, 0xd8 + (reg))

#define ANDi32AX(str, imm) \
    jit(str, 0x25); \
    jitl(str, imm)

#define ANDi32(str, imm, reg) \
    jit(str, 0x81); \
    jit(str, 0xe0 | (reg)); \
    jitl(str, imm)

void and_imm_r32(stream &strm, int reg, u32 imm)
{
    if (reg == EAX)
    {
        ANDi32AX(strm, imm);
    }
    else
    {
        ANDi32(strm, imm, reg);
    }
}

#define ANDr32(str, reg, dstreg) \
    jit(str, 0x21); \
    jit(str, (3 << 6) | (reg) << 3 | (dstreg))

#define JMPimm32(str, imm) \
    jit(str, 0xe9); \
    jitl(str, imm)

#define CMPi32AX(str, imm) \
    jit(str, 0x3d); \
    jitl(str, imm)

#define CMPi32(str, imm, reg) \
    jit(str, 0x81); \
    jit(str, 0xf8 + (reg)); \
    jitl(str, imm)

#define CMPi8_short(str, imm, reg) \
    jit(str, 0x83); \
    jit(str, 0xf8 + (reg)); \
    jit(str, (u8)(imm))

void cmp_imm_r32(stream &strm, u32 imm, int reg)
{
    if (imm < 0x80)
    {
        CMPi8_short(strm, imm, reg);
    }
    else if (reg == EAX)
    {
        CMPi32AX(strm, imm);
    }
    else
    {
        CMPi32(strm, imm, reg);
    }
}

#define JEimm32(str, imm) \
    jit(str, 0x0f); \
    jit(str, 0x84); \
    jitl(str, imm)

#define JNEimm32(str, imm) \
    jit(str, 0x0f); \
    jit(str, 0x85); \
    jitl(str, imm)

#define JNEshort(str, imm) \
    jit(str, 0x75); \
    jit(str, (u8)(imm))

void emit_jne_imm(stream &str, u32 imm)
{
    // TODO: Get a way to relax jmps from 32 to 8
    // This would save some considerable bytes on small programs
    if (0 && imm < 0x80)
    {
        JNEshort(str, imm);
    }
    else
    {
        JNEimm32(str, imm);
    }
}

#define CMPr32(str, src, dst) \
    jit(str, 0x39); \
    jit(str, (3 << 6) | (src) << 3 | (dst))

#define JAEimm32(str, imm) \
    jit(str, 0x0f); \
    jit(str, 0x83); \
    jitl(str, imm)

#define JNAEimm32(str, imm) \
    jit(str, 0x0f); \
    jit(str, 0x82); \
    jitl(str, imm)

#define JAimm32(str, imm) \
    jit(str, 0x0f); \
    jit(str, 0x87); \
    jitl(str, imm)

#define JNAimm32(str, imm) \
    jit(str, 0x0f); \
    jit(str, 0x86); \
    jitl(str, imm)

#define TESTi32AX(str, imm) \
    jit(str, 0xa9); \
    jitl(str, imm)

#define TESTi32(str, imm, reg) \
    jit(str, 0xf7); \
    jit(str, 0xc0 + (reg)); \
    jitl(str, imm)

void test_imm_r32(stream &strm, u32 imm, int reg)
{
    if (reg == EAX)
    {
        TESTi32AX(strm, imm);
    }
    else
    {
        TESTi32(strm, imm, reg);
    }
}

#define TESTr32(str, src, dst) \
    jit(str, 0x85); \
    jit(str, (3 << 6) | (src) << 3 | (dst))

#define X86_ARG0 RDI
#define X86_ARG1 RSI
#define X86_ARG2 RDX

#define X86_A   EAX
#define X86_X   ECX
#define X86_TMP EBX

void x86_jit_start(stream &strm)
{
    PUSHrq(strm, RBP);
    MOVr64(strm, RBP, RSP);
}

void x86_jit_end(stream &strm)
{
    POPrq(strm, RBP);
    RET(strm);
}

struct bpf_instr insns[] = {
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IP, 0, 3),
    BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 23),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_TCP, 0, 1),
    BPF_STMT(BPF_RET + BPF_K, (u32) -1),
    BPF_STMT(BPF_RET + BPF_K, 0),
};

struct bpf_instr ldinsn[] = {
    BPF_STMT(BPF_LD | BPF_IMM, 0x1000),
    BPF_STMT(BPF_LD + BPF_W + BPF_ABS, 12),
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
    BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 12),
    BPF_STMT(BPF_LD + BPF_W + BPF_IND, 12),
    BPF_STMT(BPF_LD + BPF_H + BPF_IND, 12),
    BPF_STMT(BPF_LD + BPF_B + BPF_IND, 12),
    BPF_STMT(BPF_LD + BPF_LEN, 0),
    BPF_STMT(BPF_LD | BPF_MEM, 2)
};

struct bpf_instr ldxinsn[] = {
    BPF_STMT(BPF_LDX | BPF_IMM, 0x1000),
    BPF_STMT(BPF_LDX | BPF_MSH, 12),
    BPF_STMT(BPF_LDX | BPF_LEN, 0),
    BPF_STMT(BPF_LDX | BPF_MEM, 2)
};

struct bpf_instr stinsn[] = {
    BPF_STMT(BPF_ST | BPF_MEM, 0),
    BPF_STMT(BPF_ST | BPF_MEM, 4),
    BPF_STMT(BPF_ST | BPF_MEM, 8),
    BPF_STMT(BPF_ST | BPF_MEM, 128),
    BPF_STMT(BPF_ST | BPF_MEM, 0x80000)
};

struct bpf_instr stxinsn[] = {
    BPF_STMT(BPF_STX | BPF_MEM, 0),
    BPF_STMT(BPF_STX | BPF_MEM, 4),
    BPF_STMT(BPF_STX | BPF_MEM, 8),
    BPF_STMT(BPF_STX | BPF_MEM, 128),
    BPF_STMT(BPF_STX | BPF_MEM, 0x80000)
};

struct bpf_instr aluinsn[] = {
    BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, 8),
    BPF_STMT(BPF_ALU | BPF_ADD | BPF_X, 0),
    BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, 1),
    BPF_STMT(BPF_ALU | BPF_SUB | BPF_K, 8),
    BPF_STMT(BPF_ALU | BPF_SUB | BPF_X, 0),
    BPF_STMT(BPF_ALU | BPF_SUB | BPF_K, 1),
    BPF_STMT(BPF_ALU | BPF_NEG, 0),
    BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf),
    BPF_STMT(BPF_ALU | BPF_AND | BPF_X, 0)
};

struct bpf_instr jmpinsn[] = {
    BPF_STMT(BPF_JMP | BPF_JA, 0),
    BPF_STMT(BPF_ALU | BPF_ADD | BPF_K, 8)
};

void jit_bpf_ld(stream &strm, struct bpf_instr *ins)
{
    auto size = BPF_SIZE(ins->code);
    auto mode = BPF_MODE(ins->code) | size;
    switch (mode)
    {
        case BPF_IMM:
            mov_imm_reg(strm, ins->k, X86_A);
            break;
        case BPF_ABS | BPF_W:
            MOVldl(strm, X86_ARG0, ins->k, X86_A);
            if (strm.should_swap())
            {
                BSWAP32(strm, X86_A);
            }
            break;
        case BPF_ABS | BPF_H:
            if (ins->k < 0x80)
            {
                MOVzw_short(strm, X86_ARG0, ins->k, X86_A);
            }
            else
            {
                MOVzw(strm, X86_ARG0, ins->k, X86_A);
            }

            if (strm.should_swap())
            {
                BSWAP16(strm);
            }
            break;
        case BPF_ABS | BPF_B:
            if (ins->k < 0x80)
            {
                MOVzb_short(strm, X86_ARG0, ins->k, X86_A);
            }
            else
            {
                MOVzb(strm, X86_ARG0, ins->k, X86_A);
            }

            break;
        case BPF_IND | BPF_W:
            LEA(strm, X86_X, ins->k, X86_TMP);
            MOVldla(strm, X86_ARG0, X86_TMP, X86_A);
            if (strm.should_swap())
            {
                BSWAP32(strm, X86_A);
            }
            break;
        case BPF_IND | BPF_H:
            LEA(strm, X86_X, ins->k, X86_TMP);
            MOVzwa(strm, X86_ARG0, X86_TMP, X86_A);
            if (strm.should_swap())
            {
                BSWAP16(strm);
            }
            break;
        case BPF_IND | BPF_B:
            LEA(strm, X86_X, ins->k, X86_TMP);
            MOVzba(strm, X86_ARG0, X86_TMP, X86_A);
            break;
        case BPF_LEN:
            MOVr64(strm, X86_ARG1, X86_A);
            break;
        case BPF_MEM:
            MOVldl(strm, X86_ARG2, ins->k * 4UL, X86_A);
            break;
    }
}

void jit_bpf_ldx(stream &strm, struct bpf_instr *ins)
{
    auto size = BPF_SIZE(ins->code);
    auto mode = BPF_MODE(ins->code) | size;
    switch (mode)
    {
        case BPF_IMM:
            mov_imm_reg(strm, ins->k, X86_X);
            break;
        case BPF_MSH:
            MOVzb(strm, X86_ARG0, ins->k, X86_X);
            ANDB4(strm, X86_X, 0xf);
            SHLi(strm, 2, X86_X);
            break;
        case BPF_LEN:
            MOVr64(strm, X86_ARG1, X86_X);
            break;
        case BPF_MEM:
            MOVldl(strm, X86_ARG2, ins->k * 4UL, X86_X);
            break;
    }
}

void jit_bpf_st(stream &strm, struct bpf_instr *ins)
{
    if (ins->k < 0x80)
    {
        // Smaller mov, but sign extends the offset (so the top bit mustn't be set)
        MOVstli8(strm, X86_A, X86_ARG2, ins->k);
    }
    else
    {
        MOVstli32(strm, X86_A, X86_ARG2, ins->k);
    }
}

void jit_bpf_stx(stream &strm, struct bpf_instr *ins)
{
    if (ins->k < 0x80)
    {
        // Smaller mov, but sign extends the offset (so the top bit mustn't be set)
        MOVstli8(strm, X86_X, X86_ARG2, ins->k);
    }
    else
    {
        MOVstli32(strm, X86_X, X86_ARG2, ins->k);
    }
}

void jit_bpf_alu(stream &strm, struct bpf_instr *ins)
{
    auto src = BPF_SRC(ins->code);
    auto op = BPF_OP(ins->code) | src;

    switch (op)
    {
        case BPF_ADD | BPF_K:
            if (ins->k == 1)
            {
                INC(strm, X86_A);
            }
            else
            {
                add_imm_r32(strm, X86_A, ins->k);
            }
            break;
        case BPF_ADD | BPF_X:
            ADDr32(strm, X86_X, X86_A);
            break;
        case BPF_SUB | BPF_K:
            
            if (ins->k == 1)
            {
                DEC(strm, X86_A);
            }
            else
            {
                sub_imm_r32(strm, X86_A, ins->k);
            }

            break;
    
          case BPF_SUB | BPF_X:
            SUBr32(strm, X86_X, X86_A);
            break;
#if 0
        case BPF_MUL | BPF_K:
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
#endif
        case BPF_AND | BPF_K:
            and_imm_r32(strm, X86_A, ins->k);
            break;
        case BPF_AND | BPF_X:
            ANDr32(strm, X86_X, X86_A);
            break;
#if 0
        case BPF_OR | BPF_K:
            ORi32(strm, ins->k, X6)
#endif
        case BPF_NEG:
            NEGr32(strm, X86_A);
            break;
    }
}

// clang-format on
#define EMIT_COND_JMP(strm, pc, condop, inverse)                                                  \
    do                                                                                            \
    {                                                                                             \
        if (ins->jt == 0 && ins->jf == 0)                                                         \
        {                                                                                         \
        }                                                                                         \
        else if (ins->jt == 0)                                                                    \
        {                                                                                         \
            strm.add_jmp(jmp_reloc::jmp_type::JMP_TYPE_REL_IMM32, strm.size() + 1,                \
                         pc + ins->jf + 1);                                                       \
            inverse(strm, 0);                                                                     \
        }                                                                                         \
        else if (ins->jf == 0)                                                                    \
        {                                                                                         \
            strm.add_jmp(jmp_reloc::jmp_type::JMP_TYPE_REL_IMM32, strm.size() + 1,                \
                         pc + ins->jt + 1);                                                       \
            condop(strm, 0);                                                                      \
        }                                                                                         \
        else                                                                                      \
        {                                                                                         \
            strm.add_jmp(jmp_reloc::jmp_type::JMP_TYPE_REL_IMM32, strm.size() + 1,                \
                         pc + ins->jt + 1);                                                       \
            condop(strm, 0);                                                                      \
            strm.add_jmp(jmp_reloc::jmp_type::JMP_TYPE_REL_IMM32, strm.size(), pc + ins->jf + 1); \
            JMPimm32(strm, 0);                                                                    \
        }                                                                                         \
    } while (0)

// clang-format off
void jit_bpf_jmp(stream &strm, struct bpf_instr *ins, u32 pc)
{
    auto src = BPF_SRC(ins->code);
    auto op = BPF_OP(ins->code) | src;

    switch (op)
    {
        case BPF_JA:
            if (ins->k == 0)
                break;
            strm.add_jmp(jmp_reloc::jmp_type::JMP_TYPE_REL_IMM32, strm.size(), pc + ins->k + 1);
            JMPimm32(strm, 0);
            break;
        case BPF_JEQ | BPF_X:
            CMPr32(strm, X86_X, X86_A);
            EMIT_COND_JMP(strm, pc, JEimm32, emit_jne_imm);
            break;
        case BPF_JEQ | BPF_K:
            // todo cmp can be smaller if the imm8 doesn't sign extend (see 83 f8 0f cmp $0xf, %eax) 
            cmp_imm_r32(strm, ins->k, X86_A);
            EMIT_COND_JMP(strm, pc, JEimm32, emit_jne_imm);
            break;
        case BPF_JGE | BPF_X:
            CMPr32(strm, X86_X, X86_A);
            EMIT_COND_JMP(strm, pc, JAEimm32, JNAEimm32);
            break;
        case BPF_JGE | BPF_K:
            cmp_imm_r32(strm, ins->k, X86_A);
            EMIT_COND_JMP(strm, pc, JAEimm32, JNAEimm32);
            break;
        case BPF_JGT | BPF_X:
            CMPr32(strm, X86_X, X86_A);
            EMIT_COND_JMP(strm, pc, JAimm32, JNAimm32);
            break;
        case BPF_JGT | BPF_K:
            cmp_imm_r32(strm, ins->k, X86_A);
            EMIT_COND_JMP(strm, pc, JAimm32, JNAimm32);
            break;
        case BPF_JSET | BPF_K:
            test_imm_r32(strm, ins->k, X86_A);
            EMIT_COND_JMP(strm, pc, emit_jne_imm, JEimm32);
            break;
        case BPF_JSET | BPF_X:
            TESTr32(strm, X86_X, X86_A);
            EMIT_COND_JMP(strm, pc, emit_jne_imm, JEimm32);
            break;
    }
}

void jit_bpf_ret(stream &strm, struct bpf_instr *ins)
{
    auto rval = BPF_RVAL(ins->code);

    switch (rval)
    {
        case BPF_K:
            mov_imm_reg(strm, ins->k, EAX);
            break;
        case BPF_A:
            // X86_A == EAX, so we're already set
            static_assert(X86_A == EAX, "This snippet depends on EAX = X86_A");
            break;
    }

    POPrq(strm, RBP);
    RET(strm);
}

void jit_bpf_misc(stream &strm, struct bpf_instr *ins)
{
    auto op = BPF_MISCOP(ins->code);

    switch (op)
    {
        case BPF_TAX:
            MOVr32(strm, X86_A, X86_X);
            break;
        case BPF_TXA:
            MOVr32(strm, X86_X, X86_A);
            break;
    }
}

void jit_insn(stream &state, struct bpf_instr *ins, u32 pc)
{
    auto opclass = BPF_CLASS(ins->code);

    switch (opclass)
    {
        case BPF_LD:
            jit_bpf_ld(state, ins);
            break;
        case BPF_LDX:
            jit_bpf_ldx(state, ins);
            break;
        case BPF_ST:
            jit_bpf_st(state, ins);
            break;
        case BPF_STX:
            jit_bpf_stx(state, ins);
            break;
        case BPF_ALU:
            jit_bpf_alu(state, ins);
            break;
        case BPF_JMP:
            jit_bpf_jmp(state, ins, pc);
            break;
        case BPF_RET:
            jit_bpf_ret(state, ins);
            break;
        case BPF_MISC:
            jit_bpf_misc(state, ins);
            break;
    }
}

void x86_jit_bpf(stream &strm, struct bpf_instr *insn, size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        strm.handle_jmp(i, strm.size());
        jit_insn(strm, insn + i, i);
    }
}

int main()
{
    std::ofstream f{"jit.out", std::ios_base::out | std::ios_base::trunc};
    stream s;
    x86_jit_start(s);
    x86_jit_bpf(s, insns, sizeof(insns) / sizeof(insns[0]));

    f.write((const char *) s.data(), s.size());

    return 0;
}
