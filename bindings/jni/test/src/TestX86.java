import java.util.ArrayList;
import capstone.*;
import capstone.Capstone.*;

public class TestX86 {


    // TODO 32-bit E:\dev\disasm\capstone\msvc\Debug
    // TODO 64-bit E:\dev\disasm\capstone\msvc\x64\Debug\
    public static void main(String[] args) {
        Capstone cs = new Capstone(Capstone.CS_ARCH_X86, Capstone.CS_MODE_16);
        // byte[] data = { 0x12, 0x2 }; //, 0x3, 0x4, 0x5, 6, 7, 8, 9, 10, 11, 12 };
        byte[] data = { 0x22, 0x2, 0x68, 0x30, 0x50, 0x70 };

        ArrayList<CsInsn> list = new ArrayList<>();
        System.out.println("Reg AX " + cs.regName(X86_const.X86_REG_AX));
        System.out.println("Reg Invalid " + cs.regName(-50));

        long start = System.currentTimeMillis();

        int TIMES = 1;
        for (int i = 0; i < TIMES; i++) {
            list = cs.disasm(data, 0);
        }
        long end = System.currentTimeMillis();
        long length = end - start;
        System.out.println("Total time took " + length + "ms. Average was " + (length / TIMES) + "ms.");

        System.out.println("main method end. the list is:");
        for (CsInsn insn : list) {
            System.out.println(insn.toString());
            insn.outDetails();
        }

        System.out.println("Instruction name: " + cs.insnName(X86_const.X86_INS_XLATB));
        System.out.println("Group name: " + cs.groupName(X86_const.X86_GRP_CALL));

        if (true) cs.close();
        System.out.println("Goodbye.\n\n\n");
    }

}
