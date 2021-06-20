// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import java.io.PrintStream;
import java.util.Arrays;
import java.util.List;

import static capstone.Capstone.CS_AC_READ;
import static capstone.Capstone.CS_AC_WRITE;
import static capstone.X86_const.*;

// TODO -- THIS IS JNI VERSION
public class X86 {

    public static class OperandMem {
        public int segment;
        public int base;
        public int index;
        public int scale;
        public long disp;

        @Override
        public String toString() {
            return toString(null);
        }

        public String toString(Capstone cs) {
            return "OperandMem{" +
                    "segment=" + segment +
                    ", base=" + (cs == null ? base : cs.cs_reg_name(cs.handle, base)) +
                    ", index=" + (cs == null ? index : cs.cs_reg_name(cs.handle, index)) +
                    ", scale=" + scale +
                    ", disp=" + disp +
                    '}';
        }
    }

    public static class Operand {
        public int type;

        // Union: Only 1 of 3 are valid:
        public int reg;
        public long imm;
        public OperandMem mem;
        //

        public byte size;
        public byte access;
        public int avx_bcast;
        public boolean avx_zero_opmask;

        @Override
        public String toString() {
            return toString(null);
        }

        public String toString(Capstone cs) {

            String stype;
            switch (type) {
                case X86_OP_REG: stype = "reg"; break;
                case X86_OP_IMM: stype = "imm"; break;
                case X86_OP_MEM: stype = "mem"; break;
                case X86_OP_INVALID:
                default:         stype = "invalid"; break;
            }

            return "Operand{" +
                    "type=" + stype +
                    (type == X86_OP_REG ? (", reg=" + reg) : "") +
                    (type == X86_OP_IMM ? (", imm=" + imm) : "") +
                    (type == X86_OP_MEM ? (", mem=" + mem.toString(cs)) : "") +
                    ", size=" + size +
                    ", access=" + accessText(access) +
                    ", avx_bcast=" + avx_bcast +
                    ", avx_zero_opmask=" + avx_zero_opmask +
                    '}';
        }

        private String accessText(int access) {
            switch (access) {
                default:
                    return "invalid";
                case CS_AC_READ: return "READ";
                case CS_AC_WRITE: return "WRITE";
                case CS_AC_READ | CS_AC_WRITE: return "READ | WRITE";
            }
        }
    }

    public static class X86Detail extends Capstone.CsDetail {
        /// Instruction prefix, which can be up to 4 bytes.
        /// A prefix byte gets value 0 when irrelevant.
        /// prefix[0] indicates REP/REPNE/LOCK prefix (See X86_PREFIX_REP/REPNE/LOCK above)
        /// prefix[1] indicates segment override (irrelevant for x86_64):
        /// See X86_PREFIX_CS/SS/DS/ES/FS/GS above.
        /// prefix[2] indicates operand-size override (X86_PREFIX_OPSIZE)
        /// prefix[3] indicates address-size override (X86_PREFIX_ADDRSIZE)
        public byte[] prefix = new byte[4];
        /// Instruction opcode, which can be from 1 to 4 bytes in size.
        /// This contains VEX opcode as well.
        /// An trailing opcode byte gets value 0 when irrelevant.
        public byte[] opcode = new byte[4];
        /// REX prefix: only a non-zero value is relevant for x86_64
        public byte rex;
        /// Address size, which can be overridden with above prefix[5].
        public byte addr_size;
        public byte modrm;
        public byte sib;
        public long disp;
        public int sib_index;
        public byte sib_scale;
        public int sib_base;
        public int xop_cc;
        public int sse_cc;
        public int avx_cc;
        public byte avx_sae;
        public int avx_rm;
        /// EFLAGS updated by this instruction.
        /// This can be formed from OR combination of X86_EFLAGS_* symbols in x86.h
        /// FPU_FLAGS updated by this instruction.
        /// This can be formed from OR combination of X86_FPU_FLAGS_* symbols in x86.h
        public long eflags;

        ///< operands for this instruction.
        public Operand[] op;

        // cs_x86_encoding
        public byte modrmOffset;
        public byte dispOffset;
        public byte dispSize;
        public byte immOffset;
        public byte immSize;

        public X86Detail(Capstone.CsInsn parent) {
            super(parent);
        }

        @Override
        public String toString() {
            Capstone cs = parent.cs;
            StringBuilder ops = new StringBuilder();
            for (int i = 0; i < op.length; i++) {
                ops.append(i).append(": ").append(op[i].toString(cs)).append("\n");
            }
            return "X86Detail{" +
                    super.toString() +
                    " prefix=" + Arrays.toString(prefix) +
                    ", opcode=" + Arrays.toString(opcode) +
                    ", rex=" + rex +
                    ", addr_size=" + addr_size +
                    ", modrm=" + modrm +
                    ", sib=" + sib +
                    ", disp=" + disp +
                    ", sib_index=" + sib_index +
                    ", sib_scale=" + sib_scale +
                    ", sib_base=" + sib_base +
                    ", xop_cc=" + xop_cc +
                    ", sse_cc=" + sse_cc +
                    ", avx_cc=" + avx_cc +
                    ", avx_sae=" + avx_sae +
                    ", avx_rm=" + avx_rm +
                    ", eflags=" + eflags +
                    ", modrmOffset=" + modrmOffset +
                    ", dispOffset=" + dispOffset +
                    ", dispSize=" + dispSize +
                    ", immOffset=" + immOffset +
                    ", immSize=" + immSize +
                    ", ops=\n" + ops +
                    '}';
        }

        boolean printAll = true;
        public void outDetails(PrintStream out) {
            Capstone cs = parent.cs;
            out.println("\tPrefix: " + Capstone.toString(prefix));
            out.println("\tOpcode: " + Capstone.toString(opcode));
            if (rex != 0 || printAll) out.printf("\tRex: 0x%x\n", rex);
            out.printf("\taddr_size: %d\n", addr_size);
            out.printf("\tmodrm: 0x%x offset=%d\n", modrm, modrmOffset);
            out.printf("\tsib: 0x%x\n", sib);
            if (sib != 0 || printAll) out.printf("\t\tsib_base: %s sib_index: %s sib_scale: %d\n",
                    cs.regName(sib_base), cs.regName(sib_index), sib_scale);
            out.printf("\tdisp: 0x%x dispOffset: 0x%x dispSize: 0x%x\n", disp, dispOffset, dispSize);
            if (xop_cc != 0 || printAll) out.printf("\txop_cc=0x%x\n", xop_cc);
            if (sse_cc != 0 || printAll) out.printf("\tsse_cc=0x%x\n", sse_cc);
            if (avx_cc != 0 || printAll) out.printf("\tavx_cc=0x%x\n", avx_cc);
            if (avx_sae != 0 || printAll) out.printf("\tavx_sae=0x%x\n", avx_sae);
            if (avx_rm != 0 || printAll) out.printf("\tavx_rm=0x%x\n", avx_rm);
            eflags;
            immOffset;
            immSize;
        }
    }


    static String get_eflag_name(long flag)
    {
        switch (flag) {
            default:
                return "";
            case X86_EFLAGS_UNDEFINED_OF:
                return "UNDEF_OF";
            case X86_EFLAGS_UNDEFINED_SF:
                return "UNDEF_SF";
            case X86_EFLAGS_UNDEFINED_ZF:
                return "UNDEF_ZF";
            case X86_EFLAGS_MODIFY_AF:
                return "MOD_AF";
            case X86_EFLAGS_UNDEFINED_PF:
                return "UNDEF_PF";
            case X86_EFLAGS_MODIFY_CF:
                return "MOD_CF";
            case X86_EFLAGS_MODIFY_SF:
                return "MOD_SF";
            case X86_EFLAGS_MODIFY_ZF:
                return "MOD_ZF";
            case X86_EFLAGS_UNDEFINED_AF:
                return "UNDEF_AF";
            case X86_EFLAGS_MODIFY_PF:
                return "MOD_PF";
            case X86_EFLAGS_UNDEFINED_CF:
                return "UNDEF_CF";
            case X86_EFLAGS_MODIFY_OF:
                return "MOD_OF";
            case X86_EFLAGS_RESET_OF:
                return "RESET_OF";
            case X86_EFLAGS_RESET_CF:
                return "RESET_CF";
            case X86_EFLAGS_RESET_DF:
                return "RESET_DF";
            case X86_EFLAGS_RESET_IF:
                return "RESET_IF";
            case X86_EFLAGS_TEST_OF:
                return "TEST_OF";
            case X86_EFLAGS_TEST_SF:
                return "TEST_SF";
            case X86_EFLAGS_TEST_ZF:
                return "TEST_ZF";
            case X86_EFLAGS_TEST_PF:
                return "TEST_PF";
            case X86_EFLAGS_TEST_CF:
                return "TEST_CF";
            case X86_EFLAGS_RESET_SF:
                return "RESET_SF";
            case X86_EFLAGS_RESET_AF:
                return "RESET_AF";
            case X86_EFLAGS_RESET_TF:
                return "RESET_TF";
            case X86_EFLAGS_RESET_NT:
                return "RESET_NT";
            case X86_EFLAGS_PRIOR_OF:
                return "PRIOR_OF";
            case X86_EFLAGS_PRIOR_SF:
                return "PRIOR_SF";
            case X86_EFLAGS_PRIOR_ZF:
                return "PRIOR_ZF";
            case X86_EFLAGS_PRIOR_AF:
                return "PRIOR_AF";
            case X86_EFLAGS_PRIOR_PF:
                return "PRIOR_PF";
            case X86_EFLAGS_PRIOR_CF:
                return "PRIOR_CF";
            case X86_EFLAGS_PRIOR_TF:
                return "PRIOR_TF";
            case X86_EFLAGS_PRIOR_IF:
                return "PRIOR_IF";
            case X86_EFLAGS_PRIOR_DF:
                return "PRIOR_DF";
            case X86_EFLAGS_TEST_NT:
                return "TEST_NT";
            case X86_EFLAGS_TEST_DF:
                return "TEST_DF";
            case X86_EFLAGS_RESET_PF:
                return "RESET_PF";
            case X86_EFLAGS_PRIOR_NT:
                return "PRIOR_NT";
            case X86_EFLAGS_MODIFY_TF:
                return "MOD_TF";
            case X86_EFLAGS_MODIFY_IF:
                return "MOD_IF";
            case X86_EFLAGS_MODIFY_DF:
                return "MOD_DF";
            case X86_EFLAGS_MODIFY_NT:
                return "MOD_NT";
            case X86_EFLAGS_MODIFY_RF:
                return "MOD_RF";
            case X86_EFLAGS_SET_CF:
                return "SET_CF";
            case X86_EFLAGS_SET_DF:
                return "SET_DF";
            case X86_EFLAGS_SET_IF:
                return "SET_IF";
        }
    }

    static const char* get_fpu_flag_name(uint64_t flag)
    {
        switch (flag) {
            default:
                return NULL;
            case X86_FPU_FLAGS_MODIFY_C0:
                return "MOD_C0";
            case X86_FPU_FLAGS_MODIFY_C1:
                return "MOD_C1";
            case X86_FPU_FLAGS_MODIFY_C2:
                return "MOD_C2";
            case X86_FPU_FLAGS_MODIFY_C3:
                return "MOD_C3";
            case X86_FPU_FLAGS_RESET_C0:
                return "RESET_C0";
            case X86_FPU_FLAGS_RESET_C1:
                return "RESET_C1";
            case X86_FPU_FLAGS_RESET_C2:
                return "RESET_C2";
            case X86_FPU_FLAGS_RESET_C3:
                return "RESET_C3";
            case X86_FPU_FLAGS_SET_C0:
                return "SET_C0";
            case X86_FPU_FLAGS_SET_C1:
                return "SET_C1";
            case X86_FPU_FLAGS_SET_C2:
                return "SET_C2";
            case X86_FPU_FLAGS_SET_C3:
                return "SET_C3";
            case X86_FPU_FLAGS_UNDEFINED_C0:
                return "UNDEF_C0";
            case X86_FPU_FLAGS_UNDEFINED_C1:
                return "UNDEF_C1";
            case X86_FPU_FLAGS_UNDEFINED_C2:
                return "UNDEF_C2";
            case X86_FPU_FLAGS_UNDEFINED_C3:
                return "UNDEF_C3";
            case X86_FPU_FLAGS_TEST_C0:
                return "TEST_C0";
            case X86_FPU_FLAGS_TEST_C1:
                return "TEST_C1";
            case X86_FPU_FLAGS_TEST_C2:
                return "TEST_C2";
            case X86_FPU_FLAGS_TEST_C3:
                return "TEST_C3";
        }
    }
}
