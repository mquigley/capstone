// Capstone Java binding
// By Nguyen Anh Quynh & Dang Hoang Vu,  2013

package capstone;

import java.util.Arrays;
import static capstone.X86_const.*;
public class X86 {

  public static class OperandMem {
    public int segment;
    public int base;
    public int index;
    public int scale;
    public long disp;

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

    // Following is a union
    // {
    public int reg;
    public long imm;
    public double fp;
    public OperandMem mem;
    // }

    public byte size;
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
        case X86_OP_FP: stype = "fp"; break;
        case X86_OP_INVALID:
        default:
          stype = "invalid";
          break;
      }

      return "Operand{" +
              "type=" + stype +
              ", reg=" + (cs == null ? reg : cs.cs_reg_name(cs.handle, reg)) +
              ", imm=" + imm +
              ", fp=" + fp +
              ", mem=" + (mem == null ? "null" : mem.toString(cs)) +
              ", size=" + size +
              ", avx_bcast=" + avx_bcast +
              ", avx_zero_opmask=" + avx_zero_opmask +
              '}';
    }
  }

  public static class X86Detail extends Capstone.ArchDetail {
    public byte [] prefix = new byte[4];
    public byte [] opcode  = new byte[4];
    public byte rex;
    public byte addr_size;
    public byte modrm;
    public byte sib;
    public int disp;
    public int sib_index;
    public byte sib_scale;
    public int sib_base;
    public int sse_cc;
    public int avx_cc;
    public byte avx_sae;
    public int avx_rm;

    public byte op_count;

    public Operand[] op = new Operand[8];

    @Override
    public String toString() {
      String ops = "";
      for (int i = 0; i < op_count; i++) {
        ops += i + ": " + op[i] + "\n";
      }
      return "X86Detail{" +
              "prefix=" + Arrays.toString(prefix) +
              ", opcode=" + Arrays.toString(opcode) +
              ", rex=" + rex +
              ", addr_size=" + addr_size +
              ", modrm=" + modrm +
              ", sib=" + sib +
              ", disp=" + disp +
              ", sib_index=" + sib_index +
              ", sib_scale=" + sib_scale +
              ", sib_base=" + sib_base +
              ", sse_cc=" + sse_cc +
              ", avx_cc=" + avx_cc +
              ", avx_sae=" + avx_sae +
              ", avx_rm=" + avx_rm +
              ", op_count=" + op_count +
              ", ops=\n" + ops +
              //", op=" + Capstone.toString(op, op_count) +
              '}';
    }


    @Override
    public String toString(Capstone cs) {
      String ops = "";
      for (int i = 0; i < op_count; i++) {
        ops += i + ": " + op[i].toString(cs) + "\n";
      }
      return "X86Detail{" +
              "prefix=" + Arrays.toString(prefix) +
              ", opcode=" + Arrays.toString(opcode) +
              ", rex=" + rex +
              ", addr_size=" + addr_size +
              ", modrm=" + modrm +
              ", sib=" + sib +
              ", disp=" + disp +
              ", sib_index=" + sib_index +
              ", sib_scale=" + sib_scale +
              ", sib_base=" + sib_base +
              ", sse_cc=" + sse_cc +
              ", avx_cc=" + avx_cc +
              ", avx_sae=" + avx_sae +
              ", avx_rm=" + avx_rm +
              ", op_count=" + op_count +
              ", ops=\n" + ops +
              //", op=" + Capstone.toString(op, op_count) +
              '}';
    }
  }

//  public static class OpInfo extends Capstone.OpInfo {
//    public byte [] prefix;
//    public byte [] opcode;
//    public byte opSize;
//    public byte rex;
//    public byte addrSize;
//    public byte dispSize;
//    public byte immSize;
//    public byte modrm;
//    public byte sib;
//    public int disp;
//    public int sibIndex;
//    public byte sibScale;
//    public int sibBase;
//    public int sseCC;
//    public int avxCC;
//    public boolean avxSae;
//    public int avxRm;
//
//    public Operand[] op;
//
//    public OpInfo(UnionOpInfo e) {
//      prefix = e.prefix;
//      opcode = e.opcode;
//      rex = e.rex;
//      addrSize = e.addr_size;
//      modrm = e.modrm;
//      sib = e.sib;
//      disp = e.disp;
//      sibIndex = e.sib_index;
//      sibScale = e.sib_scale;
//      sibBase = e.sib_base;
//      sseCC = e.sse_cc;
//      avxCC = e.avx_cc;
//      avxSae = e.avx_sae > 0;
//      avxRm = e.avx_rm;
//      op = new Operand[e.op_count];
//      for (int i=0; i<e.op_count; i++)
//        op[i] = e.op[i];
//    }
//  }
}
