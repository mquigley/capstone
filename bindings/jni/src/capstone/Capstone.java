package capstone;

import java.util.ArrayList;

// MLQ - To build header files:
// cd E:\dev\capstone_test\jni\src\capstone
// javac -h . NativeLib.java
// no - won't work
// c:\Program Files\Java\jdk1.8.0_72\bin\javah.exe
// "c:\Program Files\Java\jdk1.8.0_72\bin\javah.exe" Capstone.class
// Note the classpath pointing to the directory parent (cp ..)
// "c:\Program Files\Java\jdk1.8.0_72\bin\javah.exe" -d .-v -cp .. capstone.Capstone

public class Capstone {

    public long handle;

    native public int cs_open(int arch, int mode, LongByReference handle);
    native public long cs_disasm(long handle, byte[] code, long code_len,
                                 long addr, long count, ArrayList<_cs_insn> insn);
    native public int cs_close(long handle);
    native public int cs_option(long handle, int option, long optionValue);

    native public String cs_reg_name(long csh, int id);
    native public String cs_insn_name (long handle, int id);
    native public String cs_group_name(long handle, int id);
    // native public byte   cs_insn_group(long handle, _cs_insn insn, int id);


//    native public int cs_open(int arch, int mode, LongByReference handle);
//    native public long cs_disasm(long handle, byte[] code, long code_len,
//                                 long addr, long count, PointerToInsn insn);
//    native public void cs_free(PointerToInsn p, long count);
//    native public int cs_close(LongByReference handle);
//    native public int cs_option(long handle, int option, long optionValue);
//
//    native public String cs_reg_name(long csh, int id);
//    native public int cs_op_count(long csh, PointerToInsn insn, int type);
//    native public int cs_op_index(long csh, PointerToInsn insn, int type, int index);
//
//    native public String cs_insn_name(long csh, int id);
//    native public String cs_group_name(long csh, int id);
//    native public byte cs_insn_group(long csh, PointerToInsn insn, int id);
//    native public byte cs_reg_read(long csh, PointerToInsn insn, int id);
//    native public byte cs_reg_write(long csh, PointerToInsn insn, int id);
//    native public int cs_errno(long csh);
//    native public int cs_version(IntByReference major, IntByReference minor);
//    native public boolean cs_support(int query);


    // TODO 32-bit E:\dev\disasm\capstone\msvc\Debug
    // TODO 64-bit E:\dev\disasm\capstone\msvc\x64\Debug\
    public static void main(String[] args) {
        Capstone cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_16);
        byte[] data = { 0x12, 0x2 }; //, 0x3, 0x4, 0x5, 6, 7, 8, 9, 10, 11, 12 };


        ArrayList<_cs_insn> list = new ArrayList<>();

        long start = System.currentTimeMillis();

        int TIMES = 1;
        for (int i = 0; i < TIMES; i++) {
            list = cs.disasm(data, 0);
        }
        long end = System.currentTimeMillis();
        long length = end - start;
        System.out.println("Total time took " + length + "ms. Average was " + (length / TIMES) + "ms.");

        System.out.println("main method end. the list is:");
        for (_cs_insn insn : list) {
            System.out.println(insn.toString(cs));
        }
        System.out.println("Goodbye.\n\n\n");
    }


    private Capstone cs;
    public int arch;
    public int mode;
    private int syntax;
    private int detail;
    private boolean diet;

    public Capstone(int arch, int mode) {
        System.loadLibrary("jni");
//        int version = cs.cs_version(null, null);
//        if (version != (CS_API_MAJOR << 8) + CS_API_MINOR) {
//            throw new RuntimeException("Different API version between core & binding (CS_ERR_VERSION)");
//        }

        this.arch = arch;
        this.mode = mode;
        cs = this;
        LongByReference handleRef = new LongByReference();
        if (cs.cs_open(arch, mode, handleRef) != CS_ERR_OK) {
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
    public ArrayList<_cs_insn> disasm(byte[] code, long address, long count) {
        ArrayList<_cs_insn> list = new ArrayList<>();
        long c = cs.cs_disasm(handle, code, code.length, address, count, list);
//
//        System.out.println("Disassembled " + c + " instructions");
//        for (int i = 0; i < list.size(); i++) {
//            System.out.println("Idx " + i + " is " + list.get(i));
//        }

//        if (0 == c) {
//            return EMPTY_INSN;
//        }
//
//        Pointer p = insnRef.getValue();
//        _cs_insn byref = new _cs_insn(p);
//
//        CsInsn[] allInsn = fromArrayRaw((_cs_insn[]) byref.toArray(c.intValue()));
//
//        // free allocated memory
//        // cs.cs_free(p, c);
//        // FIXME(danghvu): Can't free because memory is still inside CsInsn

        return list;
    }

    protected static abstract class OpInfo {};
    protected static abstract class ArchDetail {
        public String toString(Capstone cs) {
            return toString();
        }
    };

    public static abstract class UnionArchDetail {
//        public Arm.UnionOpInfo arm;
//        public Arm64.UnionOpInfo arm64;
//        public X86.X86Detail x86;
//        public Mips.UnionOpInfo mips;
//        public Ppc.UnionOpInfo ppc;
//        public Sparc.UnionOpInfo sparc;
//        public Systemz.UnionOpInfo sysz;
//        public Xcore.UnionOpInfo xcore;
    }

    // E:\dev\disasm\capstone\include\capstone.h #285
    public static class _cs_insn {
        // instruction ID.
        public int id;
        // instruction address.
        public long address;
        // instruction size.
        public short size;
        // machine bytes of instruction.
        public byte[] bytes = new byte[16];
        // instruction mnemonic. NOTE: irrelevant for diet engine.
        public String mnemonic = "";
        // instruction operands. NOTE: irrelevant for diet engine.
        public String op_str = "";
        // detail information of instruction.
        public _cs_detail cs_detail;

        @Override
        public String toString() {
            return "_cs_insn{" +
                    "id=" + id +
                    ", mnemonic=" + mnemonic +
                    ", op_str=" +op_str +
                    ", address=" + address +
                    ", size=" + size +
                    ", bytes=" + Capstone.toString(bytes, size) +
                    ", cs_detail=" + cs_detail +
                    '}';
        }

        public String toString(Capstone cs) {
            return "_cs_insn{" +
                    "id=" + id +
                    ", mnemonic=" + mnemonic +
                    ", op_str=" +op_str +
                    ", address=" + address +
                    ", size=" + size +
                    ", bytes=" + Capstone.toString(bytes, size) +
                    ", cs_detail=" + cs_detail.toString(cs) +
                    '}';
        }
    }

    // E:\dev\disasm\capstone\include\capstone.h #246
    public static class _cs_detail {

        // list of all implicit registers being read.
        public byte[] regs_read = new byte[12];
        public byte regs_read_count;
        // list of all implicit registers being written.
        public byte[] regs_write = new byte[20];
        public byte regs_write_count;
        // list of semantic groups this instruction belongs to.
        public byte[] groups = new byte[8];
        public byte groups_count;

        public ArchDetail arch;

        public X86.X86Detail x86() { return (X86.X86Detail) arch; }

        @Override
        public String toString() {
            return "_cs_detail{\n" +
                    "regs_read=" + Capstone.toString(regs_read, regs_read_count) +
                    ", regs_read_count=" + regs_read_count +
                    ", regs_write=" + Capstone.toString(regs_write, regs_write_count) +
                    ", regs_write_count=" + regs_write_count +
                    ", groups=" + Capstone.toString(groups, groups_count) +
                    ", groups_count=" + groups_count +
                    ",\n arch=" + arch +
                    '}';
        }

        public String toString(Capstone cs) {
            String regsReadText = "[!!!!";
            for (int i = 0; i < regs_read_count; i++) {
                if (i != 0) regsReadText += ", ";
                regsReadText += cs.cs_reg_name(cs.handle, regs_read[i]);
            }
            regsReadText += "]";
            String regsWriteText = "[!!!!";
            for (int i = 0; i < regs_write_count; i++) {
                if (i != 0) regsWriteText += ", ";
                regsWriteText += cs.cs_reg_name(cs.handle, regs_write[i]);
            }
            regsWriteText += "]";
            return "_cs_detail{\n" +
                    "regs_read=" + regsReadText +
                    ", regs_read_count=" + regs_read_count +
                    ", regs_write=" + regsWriteText +
                    ", regs_write_count=" + regs_write_count +
                    ", groups=" + Capstone.toString(groups, groups_count) +
                    ", groups_count=" + groups_count +
                    ",\n arch=" + arch.toString(cs) +
                    '}';
        }
    }
















    public static class CsInsn {
        private long csh;
        private Capstone cs;
        private _cs_insn raw;
        private int arch;

        // instruction ID.
        public int id;
        // instruction address.
        public long address;
        // instruction size.
        public short size;
        // instruction mnemonic. NOTE: irrelevant for diet engine.
        public String mnemonic;
        // instruction operands. NOTE: irrelevant for diet engine.
        public String opStr;
        // list of all implicit registers being read.
        public byte[] regsRead;
        // list of all implicit registers being written.
        public byte[] regsWrite;
        // list of semantic groups this instruction belongs to.
        public byte[] groups;
        public OpInfo operands;

        public CsInsn (_cs_insn insn, int _arch, long _csh, Capstone _cs, boolean diet) {
            id = insn.id;
            address = insn.address;
            size = insn.size;

            mnemonic = insn.mnemonic;
            opStr = insn.op_str;

            cs = _cs;
            arch = _arch;
            raw = insn;
            csh = _csh;

            if (insn.cs_detail != null) {
                if (!diet) {
                    regsRead = new byte[insn.cs_detail.regs_read_count];
                    for (int i=0; i<regsRead.length; i++)
                        regsRead[i] = insn.cs_detail.regs_read[i];
                    regsWrite = new byte[insn.cs_detail.regs_write_count];
                    for (int i=0; i<regsWrite.length; i++)
                        regsWrite[i] = insn.cs_detail.regs_write[i];
                    groups = new byte[insn.cs_detail.groups_count];
                    for (int i=0; i<groups.length; i++)
                        groups[i] = insn.cs_detail.groups[i];
                }

                operands = getOptInfo(insn.cs_detail);
            }
        }

        private OpInfo getOptInfo(_cs_detail detail) {
            OpInfo op_info = null;

            switch (this.arch) {
//                case CS_ARCH_ARM:
//                    detail.arch.setType(Arm.UnionOpInfo.class);
//                    detail.arch.read();
//                    op_info = new Arm.OpInfo((Arm.UnionOpInfo) detail.arch.arm);
//                    break;
//                case CS_ARCH_ARM64:
//                    detail.arch.setType(Arm64.UnionOpInfo.class);
//                    detail.arch.read();
//                    op_info = new Arm64.OpInfo((Arm64.UnionOpInfo) detail.arch.arm64);
//                    break;
//                case CS_ARCH_MIPS:
//                    detail.arch.setType(Mips.UnionOpInfo.class);
//                    detail.arch.read();
//                    op_info = new Mips.OpInfo((Mips.UnionOpInfo) detail.arch.mips);
//                    break;
//                case CS_ARCH_X86:
//                    detail.arch.setType(X86.UnionOpInfo.class);
//                    detail.arch.read();
//                    op_info = new X86.OpInfo((X86.UnionOpInfo) detail.arch.x86);
//                    break;
//                case CS_ARCH_SPARC:
//                    detail.arch.setType(Sparc.UnionOpInfo.class);
//                    detail.arch.read();
//                    op_info = new Sparc.OpInfo((Sparc.UnionOpInfo) detail.arch.sparc);
//                    break;
//                case CS_ARCH_SYSZ:
//                    detail.arch.setType(Systemz.UnionOpInfo.class);
//                    detail.arch.read();
//                    op_info = new Systemz.OpInfo((Systemz.UnionOpInfo) detail.arch.sysz);
//                    break;
//                case CS_ARCH_PPC:
//                    detail.arch.setType(Ppc.UnionOpInfo.class);
//                    detail.arch.read();
//                    op_info = new Ppc.OpInfo((Ppc.UnionOpInfo) detail.arch.ppc);
//                    break;
//                case CS_ARCH_XCORE:
//                    detail.arch.setType(Xcore.UnionOpInfo.class);
//                    detail.arch.read();
//                    op_info = new Xcore.OpInfo((Xcore.UnionOpInfo) detail.arch.xcore);
//                    break;
                default:
            }

            return op_info;
        }

//        public int opCount(int type) {
//            return cs.cs_op_count(csh, raw.getPointer(), type);
//        }
//
//        public int opIndex(int type, int index) {
//            return cs.cs_op_index(csh, raw.getPointer(), type, index);
//        }
//
//        public boolean regRead(int reg_id) {
//            return cs.cs_reg_read(csh, raw.getPointer(), reg_id) != 0;
//        }
//
//        public boolean regWrite(int reg_id) {
//            return cs.cs_reg_write(csh, raw.getPointer(), reg_id) != 0;
//        }
//
//        public int errno() {
//            return cs.cs_errno(csh);
//        }
//
//        public String regName(int reg_id) {
//            return cs.cs_reg_name(csh, reg_id);
//        }
//
//        public String insnName() {
//            return cs.cs_insn_name(csh, id);
//        }
//
//        public String groupName(int id) {
//            return cs.cs_group_name(csh, id);
//        }
//
//        public boolean group(int gid) {
//            return cs.cs_insn_group(csh, raw.getPointer(), gid) != 0;
//        }

    }

//    private CsInsn[] fromArrayRaw(_cs_insn[] arr_raw) {
//        CsInsn[] arr = new CsInsn[arr_raw.length];
//
//        for (int i = 0; i < arr_raw.length; i++) {
//            arr[i] = new CsInsn(arr_raw[i], this.arch, ns.csh, cs, this.diet);
//        }
//
//        return arr;
//    }

    // Capstone API version
    public static final int CS_API_MAJOR = 3;
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
    public static final int CS_ARCH_MAX = 8;
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
    public static final int CS_MODE_MIPSGP64 = 1 << 7;  // General Purpose Registers are 64-bit wide (MIPS arch)
    public static final int CS_MODE_BIG_ENDIAN = 1 << 31; // big-endian mode
    public static final int CS_MODE_V9 = 1 << 4;	      // SparcV9 mode (Sparc arch)
    public static final int CS_MODE_MIPS32 = CS_MODE_32; // Mips32 ISA
    public static final int CS_MODE_MIPS64 = CS_MODE_64; // Mips64 ISA

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

    // Common instruction groups - to be consistent across all architectures.
    public static final int CS_GRP_INVALID = 0;  // uninitialized/invalid group.
    public static final int CS_GRP_JUMP    = 1;  // all jump instructions (conditional+direct+indirect jumps)
    public static final int CS_GRP_CALL    = 2;  // all call instructions
    public static final int CS_GRP_RET     = 3;  // all return instructions
    public static final int CS_GRP_INT     = 4;  // all interrupt instructions (int+syscall)
    public static final int CS_GRP_IRET    = 5;  // all interrupt return instructions

    // Query id for cs_support()
    public static final int CS_SUPPORT_DIET = CS_ARCH_ALL+1;	  // diet mode
    public static final int CS_SUPPORT_X86_REDUCE = CS_ARCH_ALL+2;  // X86 reduce mode

    private static final CsInsn[] EMPTY_INSN = new CsInsn[0];


//    // return combined API version
//    public int version() {
//        return cs.cs_version(null, null);
//    }
//
//    // set Assembly syntax
//    public void setSyntax(int syntax) {
//        if (true) return;
//        if (cs.cs_option(ns.csh, CS_OPT_SYNTAX, new NativeLong(syntax)) == CS_ERR_OK) {
//            this.syntax = syntax;
//        } else {
//            throw new RuntimeException("ERROR: Failed to set assembly syntax");
//        }
//    }
//
//    // set detail option at run-time
//    public void setDetail(int opt) {
//        if (cs.cs_option(ns.csh, CS_OPT_DETAIL, new NativeLong(opt)) == CS_ERR_OK) {
//            this.detail = opt;
//        } else {
//            throw new RuntimeException("ERROR: Failed to set detail option");
//        }
//    }
//
//    // set mode option at run-time
//    public void setMode(int opt) {
//        if (cs.cs_option(ns.csh, CS_OPT_MODE, new NativeLong(opt)) == CS_ERR_OK) {
//            this.mode = opt;
//        } else {
//            throw new RuntimeException("ERROR: Failed to set mode option");
//        }
//    }

    // destructor automatically called at destroyed time.
    protected void finalize() {
        // FIXME: crashed on Ubuntu 14.04 64bit, OpenJDK java 1.6.0_33
        // cs.cs_close(ns.handleRef);
    }

    // destructor automatically called at destroyed time.
    public int close() {
        return cs.cs_close(handle);
    }

    /**
     * Disassemble instructions from @code assumed to be located at @address,
     * stop when encountering first broken instruction.
     *
     * @param code The source machine code bytes.
     * @param address The address of the first machine code byte.
     * @return the array of successfully disassembled instructions, empty if no instruction could be disassembled.
     */
    public ArrayList<_cs_insn> disasm(byte[] code, long address) {
        return disasm(code, address, 0);
    }



    static class PointerToInsn {
        public ArrayList<_cs_insn> insn = new ArrayList<>();
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

