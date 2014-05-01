/* Capstone Disassembly Engine */
/* By Nguyen Anh Quynh <aquynh@gmail.com>, 2013-2014 */

#ifndef CS_SYSZDISASSEMBLER_H
#define CS_SYSZDISASSEMBLER_H

#include <stdint.h>

#include "../../include/capstone.h"
#include "../../MCRegisterInfo.h"
#include "../../MCInst.h"

void SystemZ_init(MCRegisterInfo *MRI);

bool SystemZ_getInstruction(csh ud, const uint8_t *code, uint8_t **modcode, size_t code_len,
		MCInst *instr, uint16_t *size, uint64_t address, void *info);

#endif
