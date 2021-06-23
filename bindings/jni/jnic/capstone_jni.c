
#include "capstone_Capstone.h"


#include "../../../include/capstone/capstone.h"
#include "../../../include/capstone/platform.h"

// e:\dev\disasm\capstone\cs_priv.h
#include "../../../cs_priv.h" 

// #include <capstone.h>
#include <stdlib.h>
#include <string.h>

#ifdef DEBUG
#define PRINTF(...) printf(__VA_ARGS__);
#else
#define PRINTF(...) 
#endif

// MLQ Use x64 mode for 64-bit JVMs
// 32-bit include directory: E:\dev\disasm\capstone\msvc\Debug 
// 64-bit: jni project > properties > VC++ directories > library directories: E:\dev\disasm\capstone\msvc\x64\Debug;$(LibraryPath)

// MLQ - IntelliJ project is at E:\dev\capstone_test

// jclass_cs_insn = (*env)->FindClass(env, "capstone/Capstone$_cs_insn");
#define FINDCLASS(variable, classname) jclass variable = (*env)->FindClass(env, classname); \
    if (!variable) { printf("Failed to load " #classname); goto ERROR; }
// constructor = (*env)->GetMethodID(env, jclass_cs_insn, "<init>", "()V");        
#define GETMETHOD(variable, jclass, name, signature) jmethodID variable = (*env)->GetMethodID(env, jclass, name, signature); \
    if (!variable) { printf("Failed to find method " #name #signature); goto ERROR; }
// javaObject = (*env)->NewObject(env, jclass_cs_insn, constructor);
#define NEWOBJECT(variable, jclass, constructor, ...) jobject variable = (*env)->NewObject(env, jclass, constructor, __VA_ARGS__); \
    if (!variable) { printf("Failed to allocate object jclass" ); goto ERROR; }

// jfieldID field_d_regs_read = (*env)->GetFieldID(env, jclass_cs_detail, "regs_read", "[S");
#define GETFIELD(variable, jclass, name, signature)  jfieldID variable = (*env)->GetFieldID(env, jclass, name, signature); \
    if (!variable) { printf("Failed to find field " #name #signature); goto ERROR; }




struct platform {
    cs_arch arch;
    cs_mode mode;
    unsigned char *code;
    size_t size;
    char *comment;
    cs_opt_type opt_type;
    cs_opt_value opt_value;
};

static void print_string_hex(char *comment, unsigned char *str, size_t len)
{
    unsigned char *c;

    printf("%s", comment);
    for (c = str; c < str + len; c++) {
        printf("0x%02x ", *c & 0xff);
    }

    printf("\n");
}


static const char* get_eflag_name(uint64_t flag)
{
    switch (flag) {
    default:
        return NULL;
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

static void print_insn_detail(csh ud, cs_mode mode, cs_insn* ins)
{
    int count, i;
    cs_x86* x86;
    cs_regs regs_read, regs_write;
    uint8_t regs_read_count, regs_write_count;

    // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
    if (ins->detail == NULL)
        return;

    csh handle = ud;

    x86 = &(ins->detail->x86);

    print_string_hex("\tPrefix:", x86->prefix, 4);

    print_string_hex("\tOpcode:", x86->opcode, 4);

    printf("\trex: 0x%x\n", x86->rex);

    printf("\taddr_size: %u\n", x86->addr_size);
    printf("\tmodrm: 0x%x\n", x86->modrm);
    if (x86->encoding.modrm_offset != 0) {
        printf("\tmodrm_offset: 0x%x\n", x86->encoding.modrm_offset);
    }

    printf("\tdisp: 0x%" PRIx64 "\n", x86->disp);
    if (x86->encoding.disp_offset != 0) {
        printf("\tdisp_offset: 0x%x\n", x86->encoding.disp_offset);
    }

    if (x86->encoding.disp_size != 0) {
        printf("\tdisp_size: 0x%x\n", x86->encoding.disp_size);
    }

    // SIB is not available in 16-bit mode
    if ((mode & CS_MODE_16) == 0) {
        printf("\tsib: 0x%x\n", x86->sib);
        if (x86->sib_base != X86_REG_INVALID)
            printf("\t\tsib_base: %s\n", cs_reg_name(handle, x86->sib_base));
        if (x86->sib_index != X86_REG_INVALID)
            printf("\t\tsib_index: %s\n", cs_reg_name(handle, x86->sib_index));
        if (x86->sib_scale != 0)
            printf("\t\tsib_scale: %d\n", x86->sib_scale);
    }

    // XOP code condition
    if (x86->xop_cc != X86_XOP_CC_INVALID) {
        printf("\txop_cc: %u\n", x86->xop_cc);
    }

    // SSE code condition
    if (x86->sse_cc != X86_SSE_CC_INVALID) {
        printf("\tsse_cc: %u\n", x86->sse_cc);
    }

    // AVX code condition
    if (x86->avx_cc != X86_AVX_CC_INVALID) {
        printf("\tavx_cc: %u\n", x86->avx_cc);
    }

    // AVX Suppress All Exception
    if (x86->avx_sae) {
        printf("\tavx_sae: %u\n", x86->avx_sae);
    }

    // AVX Rounding Mode
    if (x86->avx_rm != X86_AVX_RM_INVALID) {
        printf("\tavx_rm: %u\n", x86->avx_rm);
    }

    // Print out all immediate operands
    count = cs_op_count(ud, ins, X86_OP_IMM);
    if (count) {
        printf("\timm_count: %u\n", count);
        for (i = 1; i < count + 1; i++) {
            int index = cs_op_index(ud, ins, X86_OP_IMM, i);
            printf("\t\timms[%u]: 0x%" PRIx64 "\n", i, x86->operands[index].imm);
            if (x86->encoding.imm_offset != 0) {
                printf("\timm_offset: 0x%x\n", x86->encoding.imm_offset);
            }

            if (x86->encoding.imm_size != 0) {
                printf("\timm_size: 0x%x\n", x86->encoding.imm_size);
            }
        }
    }

    if (x86->op_count)
        printf("\top_count: %u\n", x86->op_count);

    // Print out all operands
    for (i = 0; i < x86->op_count; i++) {
        cs_x86_op* op = &(x86->operands[i]);

        switch ((int)op->type) {
        case X86_OP_REG:
            printf("\t\toperands[%u].type: REG = %s\n", i, cs_reg_name(handle, op->reg));
            break;
        case X86_OP_IMM:
            printf("\t\toperands[%u].type: IMM = 0x%" PRIx64 "\n", i, op->imm);
            break;
        case X86_OP_MEM:
            printf("\t\toperands[%u].type: MEM\n", i);
            if (op->mem.segment != X86_REG_INVALID)
                printf("\t\t\toperands[%u].mem.segment: REG = %s\n", i, cs_reg_name(handle, op->mem.segment));
            if (op->mem.base != X86_REG_INVALID)
                printf("\t\t\toperands[%u].mem.base: REG = %s\n", i, cs_reg_name(handle, op->mem.base));
            if (op->mem.index != X86_REG_INVALID)
                printf("\t\t\toperands[%u].mem.index: REG = %s\n", i, cs_reg_name(handle, op->mem.index));
            if (op->mem.scale != 1)
                printf("\t\t\toperands[%u].mem.scale: %u\n", i, op->mem.scale);
            if (op->mem.disp != 0)
                printf("\t\t\toperands[%u].mem.disp: 0x%" PRIx64 "\n", i, op->mem.disp);
            break;
        default:
            break;
        }

        // AVX broadcast type
        if (op->avx_bcast != X86_AVX_BCAST_INVALID)
            printf("\t\toperands[%u].avx_bcast: %u\n", i, op->avx_bcast);

        // AVX zero opmask {z}
        if (op->avx_zero_opmask != false)
            printf("\t\toperands[%u].avx_zero_opmask: TRUE\n", i);

        printf("\t\toperands[%u].size: %u\n", i, op->size);

        switch (op->access) {
        default:
            break;
        case CS_AC_READ:
            printf("\t\toperands[%u].access: READ\n", i);
            break;
        case CS_AC_WRITE:
            printf("\t\toperands[%u].access: WRITE\n", i);
            break;
        case CS_AC_READ | CS_AC_WRITE:
            printf("\t\toperands[%u].access: READ | WRITE\n", i);
            break;
        }
    }

    // Print out all registers accessed by this instruction (either implicit or explicit)
    if (!cs_regs_access(ud, ins,
        regs_read, &regs_read_count,
        regs_write, &regs_write_count)) {
        if (regs_read_count) {
            printf("\tRegisters read:");
            for (i = 0; i < regs_read_count; i++) {
                printf(" %s", cs_reg_name(handle, regs_read[i]));
            }
            printf("\n");
        }

        if (regs_write_count) {
            printf("\tRegisters modified:");
            for (i = 0; i < regs_write_count; i++) {
                printf(" %s", cs_reg_name(handle, regs_write[i]));
            }
            printf("\n");
        }
    }

    printf("\tGroups count: %d\n", ins->detail->groups_count);
    for (i = 0; i < ins->detail->groups_count; i++) {
        uint8_t g = ins->detail->groups[i];
        printf("\t\tGroup %d %s", g, cs_group_name(handle, g));
    }

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

    printf("\n");
}
static void test()
{
    //#define X86_CODE32 "\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x78\x56\x00\x00"
    //#define X86_CODE32 "\x05\x78\x56\x00\x00"
    //#define X86_CODE32 "\x01\xd8"
    //#define X86_CODE32 "\x05\x23\x01\x00\x00"
    //#define X86_CODE32 "\x8d\x87\x89\x67\x00\x00"
    //#define X86_CODE32 "\xa1\x13\x48\x6d\x3a\x8b\x81\x23\x01\x00\x00\x8b\x84\x39\x23\x01\x00\x00"
    //#define X86_CODE32 "\xb4\xc6"        // mov        ah, 0x6c
    //#define X86_CODE32 "\x77\x04"        // ja +6
#define X86_CODE64 "\x55\x48\x8b\x05\xb8\x13\x00\x00"
    //#define X86_CODE64 "\xe9\x79\xff\xff\xff"        // jmp 0xf7e

#define X86_CODE16 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
    //#define X86_CODE16 "\x67\x00\x18"
#define X86_CODE32 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
    //#define X86_CODE32 "\x0f\xa7\xc0"        // xstorerng
    //#define X86_CODE32 "\x64\xa1\x18\x00\x00\x00"        // mov eax, dword ptr fs:[18]
    //#define X86_CODE32 "\x64\xa3\x00\x00\x00\x00"        // mov [fs:0x0], eax
    //#define X86_CODE32 "\xd1\xe1"        // shl ecx, 1
    //#define X86_CODE32 "\xd1\xc8"        // ror eax, 1
    //#define X86_CODE32 "\x83\xC0\x80"        // add        eax, -x80
    //#define X86_CODE32 "\xe8\x26\xfe\xff\xff"                // call        0xe2b
    //#define X86_CODE32 "\xcd\x80"                // int 0x80
    //#define X86_CODE32 "\x24\xb8"                // and    $0xb8,%al
    //#define X86_CODE32 "\xf0\x01\xd8"   // lock add eax,ebx
    //#define X86_CODE32 "\xf3\xaa"                // rep stosb

    struct platform platforms[] = {
        {
            CS_ARCH_X86,
            CS_MODE_16,
        (unsigned char *)X86_CODE16,
        sizeof(X86_CODE16) - 1,
        "X86 16bit (Intel syntax)"
        },
        {
            CS_ARCH_X86,
            CS_MODE_32,
        (unsigned char *)X86_CODE32,
        sizeof(X86_CODE32) - 1,
        "X86 32 (AT&T syntax)",
        CS_OPT_SYNTAX,
        CS_OPT_SYNTAX_ATT,
        },
        {
            CS_ARCH_X86,
            CS_MODE_32,
        (unsigned char *)X86_CODE32,
        sizeof(X86_CODE32) - 1,
        "X86 32 (Intel syntax)"
        },
        {
            CS_ARCH_X86,
            CS_MODE_64,
        (unsigned char *)X86_CODE64,
        sizeof(X86_CODE64) - 1,
        "X86 64 (Intel syntax)"
        },
    };

    uint64_t address = 0x1000;
    cs_insn *insn;
    int i;
    size_t count;
    csh handle;


    for (i = 0; i < sizeof(platforms) / sizeof(platforms[0]); i++) {
        cs_err err = cs_open(platforms[i].arch, platforms[i].mode, &handle);
        if (err) {
            printf("Failed on cs_open() with error returned: %u\n", err);
            continue;
        }

        if (platforms[i].opt_type)
            cs_option(handle, platforms[i].opt_type, platforms[i].opt_value);

        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        count = cs_disasm(handle, platforms[i].code, platforms[i].size, address, 0, &insn);
        if (count) {
            size_t j;

            printf("****************\n");
            printf("Platform: %s\n", platforms[i].comment);
            print_string_hex("Code:", platforms[i].code, platforms[i].size);
            printf("Disasm:\n");

            for (j = 0; j < count; j++) {
                printf("0x%" PRIx64 ":\t%s\t%s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
                print_insn_detail(handle, platforms[i].mode, &insn[j]);
            }
            printf("0x%" PRIx64 ":\n", insn[j - 1].address + insn[j - 1].size);

            // free memory allocated by cs_disasm()
            cs_free(insn, count);
        }
        else {
            printf("****************\n");
            printf("Platform: %s\n", platforms[i].comment);
            print_string_hex("Code:", platforms[i].code, platforms[i].size);
            printf("ERROR: Failed to disasm given code!\n");
        }

        printf("\n");
    }
}







/*
* Class:     capstone_Capstone
* Method:    cs_open
* Signature: (IILcapstone/LongByReference;)I
*/
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1open
(JNIEnv *env, jobject thisObj, jint arch, jint mode, jobject handleRef)
{
    PRINTF("Called open with thisObj=%p arch=%d mode=%d handle=%p\n", thisObj, arch, mode, handleRef);

    csh handle = 0;
    cs_err err = cs_open(arch, mode, &handle);

    PRINTF("Open returned err=%d handle=0x%zx\n", err, handle);

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    jclass handleClass = (*env)->GetObjectClass(env, handleRef);
    jmethodID setValueMethodId = (*env)->GetMethodID(env, handleClass, "setValue", "(J)V");
    if (NULL == setValueMethodId) {
        printf("Could not find method\n");
        return CS_ERR_CSH;
    }

    PRINTF("Handle class %p methodID %p\n", handleClass, setValueMethodId);
    (*env)->CallVoidMethod(env, handleRef, setValueMethodId, (jlong)handle);

    return err;
}

// native public String cs_reg_name(long csh, int id);

/*
 * Class:     capstone_Capstone
 * Method:    cs_reg_name
 * Signature: (JI)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_capstone_Capstone_cs_1reg_1name
(JNIEnv* env, jobject thisObj, jlong handle, jint id)
{
    const char* name = cs_reg_name(handle, id);
    jstring result = (*env)->NewStringUTF(env, name);
    return result;
}


// 
/*
 * Class:     capstone_Capstone
 * Method:    cs_insn_name
 * Signature: (JI)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_capstone_Capstone_cs_1insn_1name
(JNIEnv* env, jobject thisObj, jlong handle, jint id)
{
    const char* name = cs_insn_name(handle, id);
    jstring result = (*env)->NewStringUTF(env, name);
    return result;
}

// 
/*
 * Class:     capstone_Capstone
 * Method:    cs_group_name
 * Signature: (JI)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_capstone_Capstone_cs_1group_1name
(JNIEnv* env, jobject thisObj, jlong handle, jint id)
{
    const char* name = cs_group_name(handle, id);
    jstring result = (*env)->NewStringUTF(env, name);
    return result;
}

/*
* Class:     capstone_Capstone
* Method:    cs_version
* Signature: (ILcapstone/IntByReference;,Lcapstone/IntByReference;)I
*/
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1version
(JNIEnv* env, jobject thisObj, jobject majorObj, jobject minorObj)
{
    int major = 0, minor = 0;
    int version = cs_version(&major, &minor);

    if (majorObj || minorObj) {
        FINDCLASS(jclassIntByRef, "capstone/IntByReference");
        GETMETHOD(method, jclassIntByRef, "setValue", "(I)V");

        if (majorObj) {
            (*env)->CallVoidMethod(env, majorObj, method, (jint)major);
        }
        if (minorObj) {
            (*env)->CallVoidMethod(env, minorObj, method, (jint)minor);
        }
    }

 ERROR:
    return version;
}
















static jbyteArray allocateJByteArray(JNIEnv* env, const uint8_t* src, const int size) {
    jbyteArray retVal = (*env)->NewByteArray(env, size);
    (*env)->SetByteArrayRegion(env, retVal, 0, size, (const jbyte *)src);
    return retVal;
}


/// <summary>
///  Sets fields common to all detail objects.
/// </summary>
/// <param name="env"></param>
/// <param name="cs"></param>
/// <param name="ci"></param>
/// <param name="jclass_cs_detail"></param>
/// <param name="detailObject"></param>
void disasmDetails(JNIEnv* env, struct cs_struct* cs, cs_insn* ci, jclass jclass_cs_detail, jobject detailObject) {

    GETFIELD(field_d_regs_read, jclass_cs_detail, "regs_read", "[S");
    GETFIELD(field_d_regs_write, jclass_cs_detail, "regs_write", "[S");
    GETFIELD(field_d_groups, jclass_cs_detail, "groups", "[B");

    // Allocate the arrays
    jshortArray regsReadArray = (*env)->NewShortArray(env, ci->detail->regs_read_count);
    (*env)->SetObjectField(env, detailObject, field_d_regs_read, regsReadArray);
    jshortArray regsWriteArray = (*env)->NewShortArray(env, ci->detail->regs_write_count);
    (*env)->SetObjectField(env, detailObject, field_d_regs_write, regsWriteArray);
    jbyteArray groupsArray = (*env)->NewByteArray(env, ci->detail->groups_count);
    (*env)->SetObjectField(env, detailObject, field_d_groups, groupsArray);

    // Set the values inside the arrays
    (*env)->SetShortArrayRegion(env, regsReadArray, 0, ci->detail->regs_read_count, ci->detail->regs_read);
    (*env)->SetShortArrayRegion(env, regsWriteArray, 0, ci->detail->regs_write_count, ci->detail->regs_write);
    (*env)->SetByteArrayRegion(env, groupsArray, 0, ci->detail->groups_count, ci->detail->groups);

ERROR:
    ;
}

void disasmX86Details(JNIEnv* env, struct cs_struct* cs, cs_insn* ci, jobject csInsnObject, jfieldID field_insnObject_detail) {

    FINDCLASS(jclass_x86, "capstone/X86$X86Detail");
    GETMETHOD(constructor, jclass_x86, "<init>", "(Lcapstone/Capstone$CsInsn;)V");
    NEWOBJECT(x86InsnObject, jclass_x86, constructor, csInsnObject);
    (*env)->SetObjectField(env, csInsnObject, field_insnObject_detail, x86InsnObject);

    disasmDetails(env, cs, ci, jclass_x86, x86InsnObject);

    /*
        public static class X86Detail extends Capstone.CsDetail {
        public byte[] prefix;
        public byte[] opcode;
        public byte rex;
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
        public long eflags;
        public byte op_count;
        public Operand[] op;
        public byte modrmOffset;
        public byte dispOffset;
        public byte dispSize;
        public byte immOffset;
        public byte immSize;

    */

    GETFIELD(field_prefix, jclass_x86, "prefix", "[B");
    GETFIELD(field_opcode, jclass_x86, "opcode", "[B");
    GETFIELD(field_rex, jclass_x86, "rex", "B");
    GETFIELD(field_addr_size, jclass_x86, "addr_size", "B");
    GETFIELD(field_modrm, jclass_x86, "modrm", "B");
    GETFIELD(field_sib, jclass_x86, "sib", "B");
    GETFIELD(field_disp, jclass_x86, "disp", "J");
    GETFIELD(field_sib_index, jclass_x86, "sib_index", "I");
    GETFIELD(field_sib_scale, jclass_x86, "sib_scale", "B");
    GETFIELD(field_sib_base, jclass_x86, "sib_base", "I");
    GETFIELD(field_xop_cc, jclass_x86, "xop_cc", "I");
    GETFIELD(field_sse_cc, jclass_x86, "sse_cc", "I");
    GETFIELD(field_avx_cc, jclass_x86, "avx_cc", "I");
    GETFIELD(field_avx_sae, jclass_x86, "avx_sae", "B");
    GETFIELD(field_avx_rm, jclass_x86, "avx_rm", "I");
    GETFIELD(field_eflags, jclass_x86, "eflags", "J");
    // GETFIELD(field_op_count, jclass_x86, "op_count", "B");
    GETFIELD(field_op, jclass_x86, "op", "[Lcapstone/X86$Operand;");
    GETFIELD(field_modrmOffset, jclass_x86, "modrmOffset", "B");
    GETFIELD(field_dispOffset, jclass_x86, "dispOffset", "B");
    GETFIELD(field_dispSize, jclass_x86, "dispSize", "B");
    GETFIELD(field_immOffset, jclass_x86, "immOffset", "B");
    GETFIELD(field_immSize, jclass_x86, "immSize", "B");

    cs_x86* x86 = &ci->detail->x86;

    jbyteArray jary = (jbyteArray)(*env)->GetObjectField(env, x86InsnObject, field_prefix);
    (*env)->SetByteArrayRegion(env, jary, 0, sizeof(x86->prefix), x86->prefix);

    jary = (jbyteArray)(*env)->GetObjectField(env, x86InsnObject, field_opcode);
    (*env)->SetByteArrayRegion(env, jary, 0, sizeof(x86->opcode), x86->opcode);

    (*env)->SetByteField(env, x86InsnObject, field_rex, x86->rex);
    (*env)->SetByteField(env, x86InsnObject, field_addr_size, x86->addr_size);
    (*env)->SetByteField(env, x86InsnObject, field_modrm, x86->modrm);
    (*env)->SetByteField(env, x86InsnObject, field_sib, x86->sib);
    (*env)->SetLongField(env, x86InsnObject, field_disp, x86->disp);
    (*env)->SetIntField(env, x86InsnObject, field_sib_index, x86->sib_index);
    (*env)->SetByteField(env, x86InsnObject, field_sib, x86->sib_scale);
    (*env)->SetIntField(env, x86InsnObject, field_sib_base, x86->sib_base);
    (*env)->SetIntField(env, x86InsnObject, field_xop_cc, x86->xop_cc);
    (*env)->SetIntField(env, x86InsnObject, field_sse_cc, x86->sse_cc);
    (*env)->SetIntField(env, x86InsnObject, field_avx_cc, x86->avx_cc);
    (*env)->SetByteField(env, x86InsnObject, field_avx_sae, x86->avx_sae);
    (*env)->SetIntField(env, x86InsnObject, field_avx_rm, x86->avx_rm);
    (*env)->SetLongField(env, x86InsnObject, field_eflags, x86->eflags);
    // (*env)->SetByteField(env, x86InsnObject, field_op_count, x86->op_count);
    (*env)->SetByteField(env, x86InsnObject, field_modrmOffset, x86->encoding.modrm_offset);
    (*env)->SetByteField(env, x86InsnObject, field_dispOffset, x86->encoding.disp_offset);
    (*env)->SetByteField(env, x86InsnObject, field_dispSize, x86->encoding.disp_size);
    (*env)->SetByteField(env, x86InsnObject, field_immOffset, x86->encoding.imm_offset);
    (*env)->SetByteField(env, x86InsnObject, field_immSize, x86->encoding.imm_size);

    /*
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
        */
    FINDCLASS(jclass_operand, "capstone/X86$Operand");
    GETMETHOD(operandConstructor, jclass_operand, "<init>", "()V");

    GETFIELD(field_type, jclass_operand, "type", "I");
    GETFIELD(field_reg, jclass_operand, "reg", "I");
    GETFIELD(field_imm, jclass_operand, "imm", "J");
    GETFIELD(field_mem, jclass_operand, "mem", "Lcapstone/X86$OperandMem;");
    GETFIELD(field_size, jclass_operand, "size", "B");
    GETFIELD(field_access, jclass_operand, "access", "B");
    GETFIELD(field_avx_bcast, jclass_operand, "avx_bcast", "I");
    GETFIELD(field_avx_zero_opmask, jclass_operand, "avx_zero_opmask", "Z");

    // Allocate the operands array
    jobjectArray operandArray = (*env)->NewObjectArray(env, x86->op_count, jclass_operand, NULL);
    (*env)->SetObjectField(env, x86InsnObject, field_op, operandArray);

    for (int i = 0; i < x86->op_count; i++) {
                cs_x86_op* op = &x86->operands[i];
                jobject operand = (*env)->NewObject(env, jclass_operand, operandConstructor);
                (*env)->SetObjectArrayElement(env, operandArray, i, operand);

                (*env)->SetIntField(env, operand, field_type, op->type);
                (*env)->SetByteField(env, operand, field_size, op->size);
                (*env)->SetByteField(env, operand, field_access, op->access);
                (*env)->SetIntField(env, operand, field_avx_bcast, op->avx_bcast);
                (*env)->SetBooleanField(env, operand, field_avx_zero_opmask, op->avx_zero_opmask);

                switch (op->type) {
                        case X86_OP_REG:
                        (*env)->SetIntField(env, operand, field_reg, op->reg); break;
                        case X86_OP_IMM:
                        (*env)->SetLongField(env, operand, field_imm, op->imm); break;
                        case X86_OP_MEM: {
                        /*
                        public static class OperandMem {
                                public int segment;
                                public int base;
                                public int index;
                                public int scale;
                                public long disp;
                        */
                        FINDCLASS(jclass_operand_mem, "capstone/X86$OperandMem");
                        GETMETHOD(opMemconstructor, jclass_operand_mem, "<init>", "()V");

                        jobject opmem = (*env)->NewObject(env, jclass_operand_mem, opMemconstructor);
                        // NEWOBJECT(opmem, jclass_operand_mem, opMemconstructor);
                        // 
                        (*env)->SetObjectField(env, operand, field_mem, opmem);

                        GETFIELD(field_segment, jclass_operand_mem, "segment", "I");
                        GETFIELD(field_base, jclass_operand_mem, "base", "I");
                        GETFIELD(field_index, jclass_operand_mem, "index", "I");
                        GETFIELD(field_scale, jclass_operand_mem, "scale", "I");
                        GETFIELD(field_disp, jclass_operand_mem, "disp", "J");

                        (*env)->SetIntField(env, opmem, field_segment, op->mem.segment);
                        (*env)->SetIntField(env, opmem, field_base, op->mem.base);
                        (*env)->SetIntField(env, opmem, field_index, op->mem.index);
                        (*env)->SetIntField(env, opmem, field_scale, op->mem.scale);
                        (*env)->SetLongField(env, opmem, field_disp, op->mem.disp);

                        break;
                        default: break;
                        }
                }
    }

ERROR:
    ;
}


/*
* Class:     capstone_Capstone
* Method:    cs_disasm
* Signature: (J[BJJJLjava/util/ArrayList;)J
*/
JNIEXPORT jlong JNICALL Java_capstone_Capstone_cs_1disasm
(JNIEnv *env, jobject thisObj, jlong handle, jbyteArray code, jlong code_len, jlong addr, jlong count, jobject insnArray)
{
    // native public long cs_disasm(long handle, byte[] code, long code_len, long addr, long count, ArrayList<_cs_insn> insn);

    if (code_len < 0 || count < 0)
        return 0;

    struct cs_struct* ud = (cs_struct*)handle;
    csh chandle = (csh)handle;

    PRINTF("Called disasm... handle %lx ud->mode %d\n", handle, ud->mode);

    // printf("Size cs_err %zd csh %zd cs_opt_type %zd size_t %zd sizeof(cs_insn) %zd\n", 
    //     sizeof(cs_err), sizeof(csh), sizeof(cs_opt_type), sizeof(size_t), sizeof(cs_insn));

    jbyte* codeBytes = (*env)->GetByteArrayElements(env, code, NULL);

    cs_insn *insn = NULL; 
    
    // size_t CAPSTONE_API cs_disasm(csh ud, const uint8_t *buffer, size_t size, uint64_t offset, size_t count, cs_insn **insn)
    size_t actualCount = cs_disasm(handle, codeBytes, code_len, addr, 0, &insn);
    // struct cs_struct *cs = (struct cs_struct *)(uintptr_t)handle;

    if (!actualCount) {
        PRINTF("ERROR: Failed to disasm given code!\n");
        goto ERROR;
    }
	goto ERROR;

    long j;

    // printf("Disasm (count %zd):\n", actualCount);

    for (j = 0; j < actualCount; j++) {
        cs_insn* ci = &insn[j];
        PRINTF("%ld 0x%" PRIx64 ":\t%s\t%s\n", j, insn[j].address, insn[j].mnemonic, insn[j].op_str);
		#if DEBUG
        print_insn_detail(handle, CS_MODE_16, &insn[j]);
		#endif

        // The registers read and modified are not filled in by default. ci->detail->regs_read is only set by the 
        // instruction ID, not the operands
        cs_regs regs_read, regs_write;
        uint8_t regs_read_count, regs_write_count;

        // Print out all registers accessed by this instruction (either implicit or explicit)
        if (!cs_regs_access(chandle, ci, regs_read, &regs_read_count, regs_write, &regs_write_count)) {
            if (regs_read_count) {
                ci->detail->regs_read_count = regs_read_count;
                memcpy(ci->detail->regs_read, regs_read, regs_read_count * sizeof(*regs_read));
            }

            if (regs_write_count) {
                ci->detail->regs_write_count = regs_write_count;
                memcpy(ci->detail->regs_write, regs_write, regs_write_count * sizeof(*regs_write));
            }
        }
            

        //   Type Signature
            //Java Type
            //Z                boolean
            //B                byte
            //C                char
            //S                short
            //I                int
            //J                long
            //F                float
            //D                double
            //L fully - qualified - class;            fully - qualified - class
            //[type                type[]
            //(arg - types) ret - type                method type
            //V is void return type, so you could have()V

        // Convert instruction
        jstring    filename = NULL;
        jboolean  returnValue = JNI_FALSE;
        jobject    detailObject = NULL;

        // jclass_cs_insn = (*env)->FindClass(env, "capstone/Capstone$_cs_insn");
        FINDCLASS(jclass_cs_insn, "capstone/Capstone$CsInsn")
        GETMETHOD(constructor, jclass_cs_insn, "<init>", "(Lcapstone/Capstone;)V");
        NEWOBJECT(csInsnObject, jclass_cs_insn, constructor, thisObj)

        //public int id;
        //public long address;
        //public short size;
        //public byte[] bytes;
        //public String mnemonic;
        //public String op_str;
        //public _cs_detail cs_detail;

        GETFIELD(field_id, jclass_cs_insn, "id", "I")
        GETFIELD(field_address, jclass_cs_insn, "address", "J")
        GETFIELD(field_size, jclass_cs_insn, "size", "S")
        GETFIELD(field_bytes, jclass_cs_insn, "bytes", "[B")
        GETFIELD(field_mnemonic, jclass_cs_insn, "mnemonic", "Ljava/lang/String;")
        GETFIELD(field_op_str, jclass_cs_insn, "op_str", "Ljava/lang/String;")
        GETFIELD(field_detail, jclass_cs_insn, "cs_detail", "Lcapstone/Capstone$CsDetail;")

        (*env)->SetIntField(env, csInsnObject, field_id, ci->id);
        (*env)->SetLongField(env, csInsnObject, field_address, ci->address);
        (*env)->SetShortField(env, csInsnObject, field_size, ci->size);

        jbyteArray bytesArray = allocateJByteArray(env, ci->bytes, ci->size);
        (*env)->SetObjectField(env, csInsnObject, field_bytes, bytesArray);

        jstring mnem = (*env)->NewStringUTF(env, ci->mnemonic);
        (*env)->SetObjectField(env, csInsnObject, field_mnemonic, mnem);

        jstring ops = (*env)->NewStringUTF(env, ci->op_str);
        (*env)->SetObjectField(env, csInsnObject, field_op_str, ops);

        if (ci->detail) {
            // Detail
            // 
            //public static  abstract class CsDetail {
            //
            // list of all implicit registers being read.
            //public short[] regs_read = new short[16];
            //public byte regs_read_count;
            //// list of all implicit registers being written.
            //public short[] regs_write = new short[20];
            //public byte regs_write_count;
            //// list of semantic groups this instruction belongs to.
            //public byte[] groups = new byte[8];
            //public byte groups_count;
            //}

            // public UnionArch arch;
            switch (ud->arch) {
            case CS_ARCH_X86: {
                disasmX86Details(env, ud, ci, csInsnObject, field_detail);
                break;
            }
            default:
                printf("Architecture %d is unsupported", ud->arch);
                ;
                // Unsupported
            }
        }

        // Add to ArrayList
        jclass arrayList = (*env)->FindClass(env, "Ljava/util/ArrayList;");
        jmethodID array_add = (*env)->GetMethodID(env, arrayList, "add", "(Ljava/lang/Object;)Z");
        (*env)->CallBooleanMethod(env, insnArray, array_add, csInsnObject);




    }

ERROR:
    // free memory allocated by cs_disasm()
    if (insn) cs_free(insn, count);

 //   printf("\n");
    return actualCount;
}

/*
* Class:     capstone_Capstone
* Method:    cs_close
* Signature: (J)I
*/
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1close
(JNIEnv *env, jobject thisObj, jlong handle)
{
    PRINTF("Called close with handle 0x%lx...\n", handle);
    return cs_close(&handle);
}

/*
* Class:     capstone_Capstone
* Method:    cs_option
* Signature: (JIJ)I
*/
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1option
(JNIEnv * env, jobject thisObj, jlong handle, jint option, jlong optionValue)
{
    csh chandle = (csh)handle;
	return cs_option(chandle, option, optionValue);
}
