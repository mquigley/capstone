// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import java.io.PrintStream;
import java.util.Arrays;

import static capstone.Capstone.CS_AC_READ;
import static capstone.Capstone.CS_AC_WRITE;
import static capstone.X86_const.*;

// TODO -- THIS IS JNI VERSION
public class X86 {

    /** Whether or not to print non-zero fields with {@link X86Detail#outDetails}. */
    public static boolean printAllDetails = false;

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

        @Override
        public void outDetails(PrintStream out) {
            Capstone cs = parent.cs;
            out.println("\tPrefix: " + Capstone.toString(prefix));
            out.println("\tOpcode: " + Capstone.toString(opcode));
            if (rex != 0 || printAllDetails) out.printf("\tRex: 0x%x\n", rex);
            out.printf("\taddr_size: %d\n", addr_size);
            out.printf("\tmodrm: 0x%x offset=%d\n", modrm, modrmOffset);
            if (immSize != 0 || printAllDetails) out.printf("\timm_offset: %d imm_size: %d\n", immOffset, immSize);
            if (sib != 0 || printAllDetails) {
                out.printf("\tsib: 0x%x\n", sib);
                out.printf("\t\tsib_base: %s sib_index: %s sib_scale: %d\n",
                        cs.regName(sib_base), cs.regName(sib_index), sib_scale);
            }
            if (dispSize > 0 || printAllDetails) out.printf("\tdisp: 0x%x dispOffset: 0x%x dispSize: 0x%x\n", disp, dispOffset, dispSize);
            if (xop_cc != 0 || printAllDetails) out.printf("\txop_cc=0x%x\n", xop_cc);
            if (sse_cc != 0 || printAllDetails) out.printf("\tsse_cc=0x%x\n", sse_cc);
            if (avx_cc != 0 || printAllDetails) out.printf("\tavx_cc=0x%x\n", avx_cc);
            if (avx_sae != 0 || printAllDetails) out.printf("\tavx_sae=0x%x\n", avx_sae);
            if (avx_rm != 0 || printAllDetails) out.printf("\tavx_rm=0x%x\n", avx_rm);

            // Operands
            out.printf("\top_count: %d\n", op.length);
            for (int i = 0; i < op.length; i++) {
                Operand op = this.op[i];

                switch (op.type) {
                    case X86_OP_REG: out.printf("\t\toperand[%d].type: REG = %s\n", i, cs.regName(op.reg)); break;
                    case X86_OP_IMM: out.printf("\t\toperand[%d].type: IMM = 0x%x\n", i, op.imm); break;
                    case X86_OP_MEM:
                        out.printf("\t\toperand[%d].type: MEM\n", i);
                        if (op.mem.segment != X86_REG_INVALID) out.printf("\t\t\tsegment: REG = %s\n", cs.regName(op.mem.segment));
                        if (op.mem.base    != X86_REG_INVALID) out.printf("\t\t\tbase: REG = %s\n",    cs.regName(op.mem.base));
                        if (op.mem.index   != X86_REG_INVALID) out.printf("\t\t\tindex: REG = %s\n",   cs.regName(op.mem.index));
                        if (op.mem.scale   != 1)               out.printf("\t\t\tscale: %d\n",         op.mem.scale);
                        if (op.mem.disp    != 0)               out.printf("\t\t\tdisplacement: 0x%x\n",op.mem.disp);
                        break;
                    default: out.printf("\t\top[%d].type: INVALID\n", i);
                }

                // AVX broadcast type
                if (op.avx_bcast != X86_AVX_BCAST_INVALID)
                    out.printf("\t\toperand[%d].avx_bcast: %d\n", i, op.avx_bcast);

                // AVX zero opmask {z}
                if (op.avx_zero_opmask)
                    out.printf("\t\toperand[%d].avx_zero_opmask: TRUE\n", i);

                out.printf("\t\toperand[%d].size: %d\n", i, op.size);

                switch (op.access) {
                    case 0: break;
                    case CS_AC_READ: out.printf("\t\toperand[%d].access: READ\n", i); break;
                    case CS_AC_WRITE: out.printf("\t\toperand[%d].access: WRITE\n", i); break;
                    case CS_AC_READ | CS_AC_WRITE: out.printf("\t\toperand[%d].access: READ | WRITE\n", i); break;
                    default: out.printf("\t\toperand[%d].access: INVALID %d\n", i, op.access); break;
                }

            }

            if (regs_read.length != 0) {
                out.printf("\tRegisters read:");
                for (int i = 0; i < regs_read.length; i++) {
                    out.printf(" %s", cs.regName(regs_read[i]));
                }
                out.printf("\n");
            }

            if (regs_write.length != 0) {
                out.printf("\tRegisters modified:");
                for (int i = 0; i < regs_write.length; i++) {
                    out.printf(" %s", cs.regName(regs_write[i]));
                }
                out.printf("\n");
            }

            // Groups
            out.printf("\tGroups count: %d\n", groups.length);
            for (int i = 0; i < groups.length; i++) {
                int g = groups[i] & 0xFF;
                out.printf("\t\tGroup %d %s\n", g, cs.groupName(g));
            }

            // Flags
            boolean isFpu = false;
            if (eflags != 0) {
                for (int i = 0; i < groups.length; i++) {
                    if ((groups[i] & 0xFF) == X86_GRP_FPU) {
                        isFpu = true;
                        break;
                    }
                }
                if (isFpu)
                    out.printf("\tfpu_flags:");
                else
                    out.printf("\teflags:");

                for (long flag = 0; flag <= 63; flag++) {
                    long flagValue = (1L << flag);
                    if ((eflags & flagValue) != 0L) {
                        out.printf(" %s", isFpu ? get_fpu_name(flagValue) : get_eflag_name(flagValue));
                    }
                }
                out.println("");
            }
            /*
                if (x86->eflags || x86->fpu_flags) {
	for (i = 0; i < ins->detail->groups_count; i++) {
	    if (ins->detail->groups[i] == X86_GRP_FPU) {
		printf("\tFPU_FLAGS:");
		for (i = 0; i <= 63; i++)
		    if (x86->fpu_flags & ((uint64_t)1 << i)) {
			printf(" %s", get_fpu_flag_name((uint64_t)1 << i));
		    }
		printf("\n");
		break;
	    }
	}

	if (i == ins->detail->groups_count) {
	    printf("\tEFLAGS:");
	    for (i = 0; i <= 63; i++)
		if (x86->eflags & ((uint64_t)1 << i)) {
		    printf(" %s", get_eflag_name((uint64_t)1 << i));
		}
	    printf("\n");
	}
    }
             */
        }
    }


    static String get_eflag_name(long flag)
    {
        if (flag == X86_EFLAGS_MODIFY_AF) return "MODIFY_AF";
        if (flag == X86_EFLAGS_MODIFY_CF) return "MODIFY_CF";
        if (flag == X86_EFLAGS_MODIFY_SF) return "MODIFY_SF";
        if (flag == X86_EFLAGS_MODIFY_ZF) return "MODIFY_ZF";
        if (flag == X86_EFLAGS_MODIFY_PF) return "MODIFY_PF";
        if (flag == X86_EFLAGS_MODIFY_OF) return "MODIFY_OF";
        if (flag == X86_EFLAGS_MODIFY_TF) return "MODIFY_TF";
        if (flag == X86_EFLAGS_MODIFY_IF) return "MODIFY_IF";
        if (flag == X86_EFLAGS_MODIFY_DF) return "MODIFY_DF";
        if (flag == X86_EFLAGS_MODIFY_NT) return "MODIFY_NT";
        if (flag == X86_EFLAGS_MODIFY_RF) return "MODIFY_RF";
        if (flag == X86_EFLAGS_PRIOR_OF) return "PRIOR_OF";
        if (flag == X86_EFLAGS_PRIOR_SF) return "PRIOR_SF";
        if (flag == X86_EFLAGS_PRIOR_ZF) return "PRIOR_ZF";
        if (flag == X86_EFLAGS_PRIOR_AF) return "PRIOR_AF";
        if (flag == X86_EFLAGS_PRIOR_PF) return "PRIOR_PF";
        if (flag == X86_EFLAGS_PRIOR_CF) return "PRIOR_CF";
        if (flag == X86_EFLAGS_PRIOR_TF) return "PRIOR_TF";
        if (flag == X86_EFLAGS_PRIOR_IF) return "PRIOR_IF";
        if (flag == X86_EFLAGS_PRIOR_DF) return "PRIOR_DF";
        if (flag == X86_EFLAGS_PRIOR_NT) return "PRIOR_NT";
        if (flag == X86_EFLAGS_RESET_OF) return "RESET_OF";
        if (flag == X86_EFLAGS_RESET_CF) return "RESET_CF";
        if (flag == X86_EFLAGS_RESET_DF) return "RESET_DF";
        if (flag == X86_EFLAGS_RESET_IF) return "RESET_IF";
        if (flag == X86_EFLAGS_RESET_SF) return "RESET_SF";
        if (flag == X86_EFLAGS_RESET_AF) return "RESET_AF";
        if (flag == X86_EFLAGS_RESET_TF) return "RESET_TF";
        if (flag == X86_EFLAGS_RESET_NT) return "RESET_NT";
        if (flag == X86_EFLAGS_RESET_PF) return "RESET_PF";
        if (flag == X86_EFLAGS_SET_CF) return "SET_CF";
        if (flag == X86_EFLAGS_SET_DF) return "SET_DF";
        if (flag == X86_EFLAGS_SET_IF) return "SET_IF";
        if (flag == X86_EFLAGS_TEST_OF) return "TEST_OF";
        if (flag == X86_EFLAGS_TEST_SF) return "TEST_SF";
        if (flag == X86_EFLAGS_TEST_ZF) return "TEST_ZF";
        if (flag == X86_EFLAGS_TEST_PF) return "TEST_PF";
        if (flag == X86_EFLAGS_TEST_CF) return "TEST_CF";
        if (flag == X86_EFLAGS_TEST_NT) return "TEST_NT";
        if (flag == X86_EFLAGS_TEST_DF) return "TEST_DF";
        if (flag == X86_EFLAGS_UNDEFINED_OF) return "UNDEFINED_OF";
        if (flag == X86_EFLAGS_UNDEFINED_SF) return "UNDEFINED_SF";
        if (flag == X86_EFLAGS_UNDEFINED_ZF) return "UNDEFINED_ZF";
        if (flag == X86_EFLAGS_UNDEFINED_PF) return "UNDEFINED_PF";
        if (flag == X86_EFLAGS_UNDEFINED_AF) return "UNDEFINED_AF";
        if (flag == X86_EFLAGS_UNDEFINED_CF) return "UNDEFINED_CF";
        if (flag == X86_EFLAGS_RESET_RF) return "RESET_RF";
        if (flag == X86_EFLAGS_TEST_RF) return "TEST_RF";
        if (flag == X86_EFLAGS_TEST_IF) return "TEST_IF";
        if (flag == X86_EFLAGS_TEST_TF) return "TEST_TF";
        if (flag == X86_EFLAGS_TEST_AF) return "TEST_AF";
        if (flag == X86_EFLAGS_RESET_ZF) return "RESET_ZF";
        if (flag == X86_EFLAGS_SET_OF) return "SET_OF";
        if (flag == X86_EFLAGS_SET_SF) return "SET_SF";
        if (flag == X86_EFLAGS_SET_ZF) return "SET_ZF";
        if (flag == X86_EFLAGS_SET_AF) return "SET_AF";
        if (flag == X86_EFLAGS_SET_PF) return "SET_PF";
        if (flag == X86_EFLAGS_RESET_0F) return "RESET_0F";
        if (flag == X86_EFLAGS_RESET_AC) return "RESET_AC";

        return "";
    }

    static String get_fpu_name(long flag)
    {
        if (flag == X86_FPU_FLAGS_MODIFY_C0) return "FLAGS_MODIFY_C0";
        if (flag == X86_FPU_FLAGS_MODIFY_C1) return "FLAGS_MODIFY_C1";
        if (flag == X86_FPU_FLAGS_MODIFY_C2) return "FLAGS_MODIFY_C2";
        if (flag == X86_FPU_FLAGS_MODIFY_C3) return "FLAGS_MODIFY_C3";
        if (flag == X86_FPU_FLAGS_RESET_C0) return "FLAGS_RESET_C0";
        if (flag == X86_FPU_FLAGS_RESET_C1) return "FLAGS_RESET_C1";
        if (flag == X86_FPU_FLAGS_RESET_C2) return "FLAGS_RESET_C2";
        if (flag == X86_FPU_FLAGS_RESET_C3) return "FLAGS_RESET_C3";
        if (flag == X86_FPU_FLAGS_SET_C0) return "FLAGS_SET_C0";
        if (flag == X86_FPU_FLAGS_SET_C1) return "FLAGS_SET_C1";
        if (flag == X86_FPU_FLAGS_SET_C2) return "FLAGS_SET_C2";
        if (flag == X86_FPU_FLAGS_SET_C3) return "FLAGS_SET_C3";
        if (flag == X86_FPU_FLAGS_UNDEFINED_C0) return "FLAGS_UNDEFINED_C0";
        if (flag == X86_FPU_FLAGS_UNDEFINED_C1) return "FLAGS_UNDEFINED_C1";
        if (flag == X86_FPU_FLAGS_UNDEFINED_C2) return "FLAGS_UNDEFINED_C2";
        if (flag == X86_FPU_FLAGS_UNDEFINED_C3) return "FLAGS_UNDEFINED_C3";
        if (flag == X86_FPU_FLAGS_TEST_C0) return "FLAGS_TEST_C0";
        if (flag == X86_FPU_FLAGS_TEST_C1) return "FLAGS_TEST_C1";
        if (flag == X86_FPU_FLAGS_TEST_C2) return "FLAGS_TEST_C2";
        if (flag == X86_FPU_FLAGS_TEST_C3) return "FLAGS_TEST_C3";

        return "";
    }
}

