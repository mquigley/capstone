// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

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
    }
}
