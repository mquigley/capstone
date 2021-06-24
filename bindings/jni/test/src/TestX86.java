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

        // With full disassembly, getting methods inline
        // 50000: 1758ms. Average was 0.03516ms.
        // Total time for 50000 took 1725ms. Average was 0.0345ms.

        // With cs_disasm and cs_regs_access, but skipping conversion to Java
        // 50000: 179ms. Average was 0.00358ms.
        // Obviously, the conversion to Java is a problem.

        // With conversion to Java but skipping detail and add to array list
        // Total time for 50000 took 505ms. Average was 0.0101ms.
        // Total time for 50000 took 626ms. Average was 0.01252ms.

        // With conversion to Java with global fields, skipping detail and array list add:
        // Total time for 50000 took 375ms. Average was 0.0075ms.
        // This means just allocation doubles it
        // If we skip detail but add to array list, it adds a whole 100ms
        // Total time for 50000 took 472ms. Average was 0.00944ms.
        // If we remove finding array class and method, really good results!
        // Total time for 50000 took 380ms. Average was 0.0076ms.

        // With single disasm and global
        // Total time for 50000 took 119ms. Average was 0.00238ms.
        // Total time for 50000 took 134ms. Average was 0.00268ms.

        int TIMES = 50000 ; //50000;
        CsInsn ins = null;
        for (int i = 0; i < TIMES; i++) {
            ins = cs.disasm(data, 0);
            // System.out.println(list);
        }
        long end = System.currentTimeMillis();
        long length = end - start;
        System.out.println("Total time for " + TIMES + " took " + length + "ms. Average was " + (length / (float)TIMES) + "ms.");

        System.out.println("main method end. the list is:");
        for (CsInsn listInsn : list) {
            System.out.println(listInsn.toString());
            listInsn.outDetails();
        }
        System.out.println("Instruction is " + ins);

        System.out.println("Instruction name: " + cs.insnName(X86_const.X86_INS_XLATB));
        System.out.println("Group name: " + cs.groupName(X86_const.X86_GRP_CALL));

        if (true) cs.close();
        System.out.println("Goodbye.\n\n\n");
    }

}
