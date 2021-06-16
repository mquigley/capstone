package capstone;

import java.util.ArrayList;

public class TestNative {


        public long handle;

        native public int cs_open(int arch, int mode, int handle);
        native public long cs_disasm(long handle, byte[] code, long code_len,
                                     long addr, long count, ArrayList<capstone.Capstone._cs_insn> insn);
        native public int cs_close(long handle);
        native public int cs_option(long handle, int option, long optionValue);

        native public String cs_reg_name(long csh, int id);
        native public String cs_insn_name (long handle, int id);
        native public String cs_group_name(long handle, int id);

    }
