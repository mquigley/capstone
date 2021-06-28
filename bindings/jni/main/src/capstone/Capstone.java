package capstone;

import java.io.PrintStream;
import java.util.ArrayList;

import static capstone.X86_const.X86_GRP_INVALID;

// MLQ - To build header files:
// cd E:\dev\capstone_test\jni\src\capstone
// javac -h . NativeLib.java
// no - won't work
// c:\Program Files\Java\jdk1.8.0_72\bin\javah.exe
// "c:\Program Files\Java\jdk1.8.0_72\bin\javah.exe" Capstone.class
// Note the classpath pointing to the directory parent (cp ..)
// "c:\Program Files\Java\jdk1.8.0_72\bin\javah.exe" -d .-v -cp .. capstone.Capstone

// mac
// https://gist.github.com/DmitrySoshnikov/8b1599a5197b5469c8cc07025f600fdb
// gcc -I"$JAVA_HOME/include" -I"$JAVA_HOME/include/darwin/" -o libcapstonejni.jnilib -Wno-pointer-sign -shared -L../.. -lcapstone  capstone_jni.c
// /usr/libexec/java_home -V

// Next architectures:
/*
x86 is the architecture of choice for general-purpose computers,
PowerPC is the architecture of choice for IBM mainframes,
and ARM is being heavily used for embedded devices.
I think that SPARC and MIPS also deserve a mention at least.
 */


public class Capstone {

    private long handle;

    native public int cs_open(int arch, int mode, LongByReference handle);
    native public long cs_disasm(long handle, byte[] code, int codeLen,
                                 long addr, long count, ArrayList<CsInsn> insn);
    native public CsInsn cs_disasm(long handle, byte[] code, int codeLen, long addr);
    native public int cs_close(long handle);
    native public int cs_option(long handle, int option, long optionValue);

    native public String cs_reg_name(long handle, int id);
    native public String cs_insn_name (long handle, int id);
    native public String cs_group_name(long handle, int id);

    // This method is unnecessary; can be done in java
//    native public int cs_op_count(long csh, PointerToInsn insn, int type);
//    native public int cs_op_index(long csh, PointerToInsn insn, int type, int index);
//    native public byte cs_insn_group(long csh, PointerToInsn insn, int id);

    // These methods we call inside the JNI
//    native public byte cs_reg_read(long csh, PointerToInsn insn, int id);
//    native public byte cs_reg_write(long csh, PointerToInsn insn, int id);

    native public int cs_errno(long handle);
    native public int cs_version(IntByReference major, IntByReference minor);

    // This method should be unnecessary; we support it all
//    native public boolean cs_support(int query);


    // TODO 32-bit E:\dev\disasm\capstone\msvc\Debug
    // TODO 64-bit E:\dev\disasm\capstone\msvc\x64\Debug\
    public static void main(String[] args) {
        Capstone cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_16);
        // byte[] data = { 0x12, 0x2 }; //, 0x3, 0x4, 0x5, 6, 7, 8, 9, 10, 11, 12 };
        byte[] data = { 0x22, 0x2, 0x68, 0x30, 0x50, 0x70 };

        ArrayList<CsInsn> list = new ArrayList<>();
        CsInsn insn = null;
        System.out.println("Reg AX " + cs.cs_reg_name(cs.handle, X86_const.X86_REG_AX));
        System.out.println("Reg Invalid " + cs.cs_reg_name(cs.handle, -50));

        long start = System.currentTimeMillis();

        int TIMES = 5000000;
        for (int i = 0; i < TIMES; i++) {
            insn = cs.disasm(data, 0);
        }
        long end = System.currentTimeMillis();
        long length = end - start;
        System.out.println("Total time took " + length + "ms. Average was " + (length / TIMES) + "ms.");


        System.out.println("main method end. the list is:");
        for (CsInsn insn2 : list) {
            System.out.println(insn2.toString());
            insn2.outDetails();
        }
        System.out.println(insn);

        System.out.println("Instruction name: " + cs.cs_insn_name(cs.handle, X86_const.X86_INS_XLATB));
        System.out.println("Group name: " + cs.cs_group_name(cs.handle, X86_const.X86_GRP_CALL));

        if (true) cs.close();
        System.out.println("Goodbye.\n\n\n");
    }


    public int arch;
    public int mode;
    private int syntax;
    private int detail;
    private boolean diet;

    public Capstone(int arch, int mode) {
        System.loadLibrary("capstonejni");
        IntByReference major = new IntByReference();
        IntByReference minor = new IntByReference();
        int version = cs_version(major, minor);
        if (version != (CS_API_MAJOR << 8) + CS_API_MINOR) {
            throw new RuntimeException("Different API version between core & binding (CS_ERR_VERSION)");
        }
        System.out.println("Version " + version + " major=" + major + " minor=" + minor);

        this.arch = arch;
        this.mode = mode;
        LongByReference handleRef = new LongByReference();
        if (cs_open(arch, mode, handleRef) != CS_ERR_OK) {
            throw new RuntimeException("ERROR: Wrong arch or mode");
        }
        this.handle = handleRef.getValue();
        System.out.println("Handle " + handle + " 0x" + Long.toHexString(handle));
        this.detail = CS_OPT_OFF;
    }

    /**
     * Disassemble up to @count instructions from @code assumed to be located at @address,
     * stop when encountering first broken instruction.
     *
     * @param code The source machine code bytes.
     * @param address The address of the first machine code byte.
     * @param count The maximum number of instructions to disassemble, 0 for no maximum.
     * @return the array of successfully disassembled instructions, empty if no instruction could be disassembled.
     */
    public ArrayList<CsInsn> disasm(byte[] code, long address, long count) {
        ArrayList<CsInsn> list = new ArrayList<>();
        long c = cs_disasm(handle, code, code.length, address, count, list);
        return list;
    }

    public CsInsn disasm(byte[] code, long address) {
        CsInsn insn = cs_disasm(handle, code, code.length, address);
        return insn;
    }

    // E:\dev\disasm\capstone\include\capstone.h #285
    public static class CsInsn {
        // instruction ID.
        public int id;
        // instruction address.
        public long address;
        // instruction size.
        public short size;
        // machine bytes of instruction.
        public byte[] bytes = new byte[24];
        // instruction mnemonic. NOTE: irrelevant for diet engine.
        public String mnemonic = "";
        // instruction operands. NOTE: irrelevant for diet engine.
        public String op_str = "";
        // detail information of instruction.
        public CsDetail cs_detail;
        // handle
        protected Capstone cs;

        public CsInsn(Capstone cs) {
            this.cs = cs;
        }

        /**
         * Check if a disassembled instruction belong to a particular group.
         * @param gid The group, such as {@link X86_const#X86_GRP_3DNOW}
         * @return
         */
        public boolean isInGroup(int gid) {
            return cs_detail.isInGroup(gid);
        }

        @Override
        public String toString() {
            return "_cs_insn{" +
                    "id=" + id +
                    ", mnemonic=" + mnemonic +
                    ", op_str=" + op_str +
                    ", address=" + address +
                    ", size=" + size +
                    ", bytes=" + Capstone.toString(bytes, size) +
                    ", cs_detail=" + (cs_detail != null ? cs_detail.toString() : "(n/a)") +
                    '}';
        }


        public void outDetails() {
            outDetails(System.out);
        }

        public void outDetails(PrintStream out) {
            out.println("ID: " + id + " Mnem: " + mnemonic + " Ops: " + op_str);
            out.printf("\t0x%x size: %d bytes: %s", address, size, Capstone.toString(bytes, size));
            if (cs_detail != null)
                cs_detail.outDetails(out);
        }

        public String getGroupsText() {
            if (cs_detail != null)
                return cs_detail.getGroupsText();
            else
                return "";
        }
    }

    // E:\dev\disasm\capstone\include\capstone.h #246
    public static abstract class CsDetail {
        protected final CsInsn parent;

        public CsDetail(CsInsn parent) {
            this.parent = parent;
        }

        /** list of all implicit registers being read. */
        public short[] regs_read;
        /** list of all implicit registers being written. */
        public short[] regs_write;
        /** list of semantic groups this instruction belongs to. Warning: This is actually an unsigned byte, so one
         * should use {@code groups[i] & 0xFF} to convert to an integer. */
        public byte[] groups;
        public int getGroup(int i) {
            if (i >= 0 && i < groups.length) return groups[i] & 0xFF;
            return X86_GRP_INVALID;
        }

        public X86.X86Detail x86() { return (X86.X86Detail) this; }

        @Override
        public String toString() {
            Capstone cs = parent.cs;
            StringBuilder regsReadText = new StringBuilder("[");
            for (int i = 0; i < regs_read.length; i++) {
                if (i != 0) regsReadText.append(", ");
                regsReadText.append(cs.regName(regs_read[i]));
            }
            regsReadText.append("]");
            StringBuilder regsWriteText = new StringBuilder("[");
            for (int i = 0; i < regs_write.length; i++) {
                if (i != 0) regsWriteText.append(", ");
                regsWriteText.append(cs.regName(regs_write[i]));
            }
            regsWriteText.append("]");
            String groupsText = getGroupsText();

            return "\n_cs_detail{" +
                    "regs_read=" + regsReadText +
                    ", regs_read_count=" + regs_read.length +
                    ", regs_write=" + regsWriteText +
                    ", regs_write_count=" + regs_write.length +
                    ", groups=" + groupsText +
                    ", groups_count=" + groups.length +
                    '}';
        }

        public String getGroupsText() {
            Capstone cs = parent.cs;
            StringBuilder groupsText = new StringBuilder("[");
            for (int i = 0; i < groups.length; i++) {
                if (i != 0) groupsText.append(", ");
                groupsText.append(cs.groupName(groups[i] & 0xFF));
            }
            groupsText.append("]");
            return groupsText.toString();
        }

        public void outDetails(PrintStream out) {
            out.println(this);
        }

        public boolean isInGroup(int gid) {
            for (int i = 0; i < groups.length; i++) {
                if ((groups[i] & 0xFF) == gid) return true;
            }
            return false;
        }
    }












    // Capstone API version
    public static final int CS_API_MAJOR = 5;
    public static final int CS_API_MINOR = 0;

    // architectures
    public static final int CS_ARCH_ARM = 0;
    public static final int CS_ARCH_ARM64 = 1;
    public static final int CS_ARCH_MIPS = 2;
    public static final int CS_ARCH_X86 = 3;
    public static final int CS_ARCH_PPC = 4;
    public static final int CS_ARCH_SPARC = 5;
    public static final int CS_ARCH_SYSZ = 6;
    public static final int CS_ARCH_XCORE = 7;
    public static final int CS_ARCH_M68K = 8;
    public static final int CS_ARCH_TMS320C64X = 9;
    public static final int CS_ARCH_M680X = 10;
    public static final int CS_ARCH_MAX = 11;
    public static final int CS_ARCH_ALL = 0xFFFF; // query id for cs_support()

    // disasm mode
    public static final int CS_MODE_LITTLE_ENDIAN = 0;  // little-endian mode (default mode)
    public static final int CS_MODE_ARM = 0;	          // 32-bit ARM
    public static final int CS_MODE_16 = 1 << 1;		// 16-bit mode for X86
    public static final int CS_MODE_32 = 1 << 2;		// 32-bit mode for X86
    public static final int CS_MODE_64 = 1 << 3;		// 64-bit mode for X86, PPC
    public static final int CS_MODE_THUMB = 1 << 4;	  // ARM's Thumb mode, including Thumb-2
    public static final int CS_MODE_MCLASS = 1 << 5;	  // ARM's Cortex-M series
    public static final int CS_MODE_V8 = 1 << 6;	      // ARMv8 A32 encodings for ARM
    public static final int CS_MODE_MICRO = 1 << 4;	  // MicroMips mode (Mips arch)
    public static final int CS_MODE_MIPS3 = 1 << 5;     // Mips III ISA
    public static final int CS_MODE_MIPS32R6 = 1 << 6;  // Mips32r6 ISA
    public static final int CS_MODE_MIPS2 = 1 << 7;  // Mips II ISA
    public static final int CS_MODE_BIG_ENDIAN = 1 << 31; // big-endian mode
    public static final int CS_MODE_V9 = 1 << 4;	      // SparcV9 mode (Sparc arch)
    public static final int CS_MODE_MIPS32 = CS_MODE_32; // Mips32 ISA
    public static final int CS_MODE_MIPS64 = CS_MODE_64; // Mips64 ISA
    public static final int CS_MODE_QPX = 1 << 4; // Quad Processing eXtensions mode (PPC)
    public static final int CS_MODE_M680X_6301 = 1 << 1; // M680X Hitachi 6301,6303 mode
    public static final int CS_MODE_M680X_6309 = 1 << 2; // M680X Hitachi 6309 mode
    public static final int CS_MODE_M680X_6800 = 1 << 3; // M680X Motorola 6800,6802 mode
    public static final int CS_MODE_M680X_6801 = 1 << 4; // M680X Motorola 6801,6803 mode
    public static final int CS_MODE_M680X_6805 = 1 << 5; // M680X Motorola 6805 mode
    public static final int CS_MODE_M680X_6808 = 1 << 6; // M680X Motorola 6808 mode
    public static final int CS_MODE_M680X_6809 = 1 << 7; // M680X Motorola 6809 mode
    public static final int CS_MODE_M680X_6811 = 1 << 8; // M680X Motorola/Freescale 68HC11 mode
    public static final int CS_MODE_M680X_CPU12 = 1 << 9; // M680X Motorola/Freescale/NXP CPU12 mode
    public static final int CS_MODE_M680X_HCS08 = 1 << 10; // M680X Freescale HCS08 mode

    // Capstone error
    public static final int CS_ERR_OK = 0;
    public static final int CS_ERR_MEM = 1;	    // Out-Of-Memory error
    public static final int CS_ERR_ARCH = 2;	  // Unsupported architecture
    public static final int CS_ERR_HANDLE = 3;	// Invalid handle
    public static final int CS_ERR_CSH = 4;	    // Invalid csh argument
    public static final int CS_ERR_MODE = 5;	  // Invalid/unsupported mode
    public static final int CS_ERR_OPTION = 6;  // Invalid/unsupported option: cs_option()
    public static final int CS_ERR_DETAIL = 7;  // Invalid/unsupported option: cs_option()
    public static final int CS_ERR_MEMSETUP = 8;
    public static final int CS_ERR_VERSION = 9;  //Unsupported version (bindings)
    public static final int CS_ERR_DIET = 10;  //Information irrelevant in diet engine
    public static final int CS_ERR_SKIPDATA = 11;  //Access irrelevant data for "data" instruction in SKIPDATA mode
    public static final int CS_ERR_X86_ATT = 12;  //X86 AT&T syntax is unsupported (opt-out at compile time)
    public static final int CS_ERR_X86_INTEL = 13;  //X86 Intel syntax is unsupported (opt-out at compile time)

    // Capstone option type
    public static final int CS_OPT_SYNTAX = 1;  // Intel X86 asm syntax (CS_ARCH_X86 arch)
    public static final int CS_OPT_DETAIL = 2;  // Break down instruction structure into details
    public static final int CS_OPT_MODE = 3;  // Change engine's mode at run-time

    // Capstone option value
    public static final int CS_OPT_OFF = 0;  // Turn OFF an option - default option of CS_OPT_DETAIL
    public static final int CS_OPT_SYNTAX_INTEL = 1;  // Intel X86 asm syntax - default syntax on X86 (CS_OPT_SYNTAX,  CS_ARCH_X86)
    public static final int CS_OPT_SYNTAX_ATT = 2;    // ATT asm syntax (CS_OPT_SYNTAX, CS_ARCH_X86)
    public static final int CS_OPT_ON = 3;  // Turn ON an option (CS_OPT_DETAIL)
    public static final int CS_OPT_SYNTAX_NOREGNAME = 3; // PPC asm syntax: Prints register name with only number (CS_OPT_SYNTAX)

    // Common instruction operand types - to be consistent across all architectures.
    public static final int CS_OP_INVALID = 0;
    public static final int CS_OP_REG = 1;
    public static final int CS_OP_IMM = 2;
    public static final int CS_OP_MEM = 3;
    public static final int CS_OP_FP  = 4;

    // Common instruction operand access types - to be consistent across all architectures.
    // It is possible to combine access types, for example: CS_AC_READ | CS_AC_WRITE
    public static final int CS_AC_INVALID = 0;
    public static final int CS_AC_READ = 1 << 0;
    public static final int CS_AC_WRITE = 1 << 1;

    // Common instruction groups - to be consistent across all architectures.
    public static final int CS_GRP_INVALID = 0;  // uninitialized/invalid group.
    public static final int CS_GRP_JUMP    = 1;  // all jump instructions (conditional+direct+indirect jumps)
    public static final int CS_GRP_CALL    = 2;  // all call instructions
    public static final int CS_GRP_RET     = 3;  // all return instructions
    public static final int CS_GRP_INT     = 4;  // all interrupt instructions (int+syscall)
    public static final int CS_GRP_IRET    = 5;  // all interrupt return instructions
    public static final int CS_GRP_PRIVILEGE = 6;  // all privileged instructions

    // Query id for cs_support()
    public static final int CS_SUPPORT_DIET = CS_ARCH_ALL+1;	  // diet mode
    public static final int CS_SUPPORT_X86_REDUCE = CS_ARCH_ALL+2;  // X86 reduce mode


    // return combined API version
    public int version() {
        return cs_version(null, null);
    }

    public String regName(int reg_id) {
        return cs_reg_name(handle, reg_id);
    }

    public String insnName(int id) {
        return cs_insn_name(handle, id);
    }

    public String groupName(int id) {
        return cs_group_name(handle, id);
    }

    /**
     * Set assembly syntax; see {@link #CS_OPT_SYNTAX_ATT} {@link #CS_OPT_SYNTAX_INTEL} and
     * {@link #CS_OPT_SYNTAX_NOREGNAME}.
     */
    public void setSyntax(int syntax) {
        if (cs_option(handle, CS_OPT_SYNTAX, syntax) == CS_ERR_OK) {
            this.syntax = syntax;
        } else {
            throw new RuntimeException("ERROR: Failed to set assembly syntax");
        }
    }

    // set detail option at run-time
    public void setDetail(int opt) {
        if (cs_option(handle, CS_OPT_DETAIL, opt) == CS_ERR_OK) {
            this.detail = opt;
        } else {
            throw new RuntimeException("ERROR: Failed to set detail option");
        }
    }

    // set mode option at run-time
    public void setMode(int opt) {
        if (cs_option(handle, CS_OPT_MODE, opt) == CS_ERR_OK) {
            this.mode = opt;
        } else {
            throw new RuntimeException("ERROR: Failed to set mode option");
        }
    }

    // destructor automatically called at destroyed time.
    public int close() {
        int retVal = cs_close(handle);
        handle = 0;
        return retVal;
    }

    public static String toString(byte[] a) {
        return toString(a, a.length);
    }

    public static String toString(byte[] a, int count) {
        if (a == null)
            return "null";
        int iMax = count - 1;
        if (iMax == -1)
            return "[]";

        StringBuilder b = new StringBuilder();
        b.append('[');
        for (int i = 0; ; i++) {
            b.append(a[i]);
            if (i == iMax)
                return b.append(']').toString();
            b.append(", ");
        }
    }

    public static String toString(Object[] a, int count) {
        if (a == null)
            return "null";
        int iMax = count - 1;
        if (iMax == -1)
            return "[]";

        StringBuilder b = new StringBuilder();
        b.append('[');
        for (int i = 0; ; i++) {
            b.append(a[i]);
            if (i == iMax)
                return b.append(']').toString();
            b.append(", ");
        }
    }

}

