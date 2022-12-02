/*
 * Copyright (c) 2022 Pedro Falcato
 * This file is  released under the terms of the MIT License
 * check LICENSE at the root directory for more information
 *
 * SPDX-License-Identifier: MIT
 */
#ifndef _BPF_DEFS_H
#define _BPF_DEFS_H

#include <stdint.h>
using u64 = uint64_t;
using u32 = uint32_t;
using u16 = uint16_t;
using u8 = uint8_t;

using i64 = int64_t;
using i32 = int32_t;
using i16 = int16_t;
using i8 = int8_t;

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

#define BPF_MAX_INSN  4096
#define BPF_MEM_WORDS 16
#define BPF_MEM_LEN   64

#endif
