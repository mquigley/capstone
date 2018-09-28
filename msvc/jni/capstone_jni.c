
#include "capstone_Capstone.h"

#include <platform.h>
#include <capstone.h>
#include <stdlib.h>


// MLQ Use x64 mode for 64-bit JVMs
// 32-bit include directory: E:\dev\disasm\capstone\msvc\Debug 
// 64-bit: jni project > properties > VC++ directories > library directories: E:\dev\disasm\capstone\msvc\x64\Debug;$(LibraryPath)







static csh handle;

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

static void print_insn_detail(csh ud, cs_mode mode, cs_insn *ins)
{
    int count, i;
    cs_x86 *x86;

    // detail can be NULL on "data" instruction if SKIPDATA option is turned ON
    if (ins->detail == NULL)
	return;

    x86 = &(ins->detail->x86);

    print_string_hex("\tPrefix:", x86->prefix, 4);

    print_string_hex("\tOpcode:", x86->opcode, 4);

    printf("\trex: 0x%x\n", x86->rex);

    printf("\taddr_size: %u\n", x86->addr_size);
    printf("\tmodrm: 0x%x\n", x86->modrm);
    printf("\tdisp: 0x%x\n", x86->disp);

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

    count = cs_op_count(ud, ins, X86_OP_IMM);
    if (count) {
	printf("\timm_count: %u\n", count);
	for (i = 1; i < count + 1; i++) {
	    int index = cs_op_index(ud, ins, X86_OP_IMM, i);
	    printf("\t\timms[%u]: 0x%" PRIx64 "\n", i, x86->operands[index].imm);
	}
    }

    if (x86->op_count)
	printf("\top_count: %u\n", x86->op_count);
    for (i = 0; i < x86->op_count; i++) {
	cs_x86_op *op = &(x86->operands[i]);

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
    //#define X86_CODE32 "\xb4\xc6"	// mov	ah, 0x6c
    //#define X86_CODE32 "\x77\x04"	// ja +6
#define X86_CODE64 "\x55\x48\x8b\x05\xb8\x13\x00\x00"
    //#define X86_CODE64 "\xe9\x79\xff\xff\xff"	// jmp 0xf7e

#define X86_CODE16 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
    //#define X86_CODE16 "\x67\x00\x18"
#define X86_CODE32 "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6"
    //#define X86_CODE32 "\x0f\xa7\xc0"	// xstorerng
    //#define X86_CODE32 "\x64\xa1\x18\x00\x00\x00"	// mov eax, dword ptr fs:[18]
    //#define X86_CODE32 "\x64\xa3\x00\x00\x00\x00"	// mov [fs:0x0], eax
    //#define X86_CODE32 "\xd1\xe1"	// shl ecx, 1
    //#define X86_CODE32 "\xd1\xc8"	// ror eax, 1
    //#define X86_CODE32 "\x83\xC0\x80"	// add	eax, -x80
    //#define X86_CODE32 "\xe8\x26\xfe\xff\xff"		// call	0xe2b
    //#define X86_CODE32 "\xcd\x80"		// int 0x80
    //#define X86_CODE32 "\x24\xb8"		// and    $0xb8,%al
    //#define X86_CODE32 "\xf0\x01\xd8"   // lock add eax,ebx
    //#define X86_CODE32 "\xf3\xaa"		// rep stosb

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

	cs_close(&handle);
    }
}









//
///*
//* Class:     com_lookout_NativeCodeImpl
//* Method:    FLX_AD_Integrity
//* Signature: ()Z
//*/
//JNIEXPORT jboolean JNICALL Java_com_lookout_NativeCodeImpl_FLX_1AD_1Integrity(JNIEnv *env, jobject obj)
//{
//    int eRet;
//    jstring    filename = NULL;
//    jclass    fileclass = NULL;
//    jboolean  returnValue = JNI_FALSE;
//    jmethodID  constructor = NULL;
//    jmethodID  existsMethod = NULL;
//    jobject    fileobject = NULL;
//    int        i;
//    char      szFilename[sizeof(szIntegrityPattern)] = { 0 };
//    struct stat st;
//
//    // Original Java code used to generate obfuscated data
//    //    String original = "/dev/socket/qemud";
//    //    String obfuscated = "";
//    //    int xor = 0x80;
//    //    for (int i = 0; i < original.length(); i++) {
//    //        int xored = original.charAt(i) ^ xor;
//    //        if (++xor > 0x8F) {
//    //            xor = 0x80;
//    //        }
//    //        if (obfuscated.length() > 0) {
//    //            obfuscated += ", ";
//    //        }
//    //        obfuscated += "0x" + Integer.toHexString(xored & 0xff);
//    //    }
//
//    int len = strlen(szIntegrityPattern);
//    int xor = 0x80;
//    for (i = 0; i < len; i++) {
//	szFilename[i] = szIntegrityPattern[i] ^ xor;
//	if (++xor > 0x8F) {
//	    xor = 0x80;
//	}
//    }
//    return stat(szFilename, &st) == 0;
//
//    filename = (*env)->NewStringUTF(env, szFilename);
//    GOTO_ERROR_IF_TRUE(!filename, FLX_RET_ERROR);
//
//    fileclass = (*env)->FindClass(env, "java/io/File");
//    GOTO_ERROR_IF_TRUE(!fileclass, FLX_RET_ERROR);
//
//    constructor = (*env)->GetMethodID(env, fileclass, "<init>", "(Ljava/lang/String;)V");
//    GOTO_ERROR_IF_TRUE(!constructor, FLX_RET_ERROR);
//
//    existsMethod = (*env)->GetMethodID(env, fileclass, "exists", "()Z");
//    GOTO_ERROR_IF_TRUE(!existsMethod, FLX_RET_ERROR);
//
//    fileobject = (*env)->NewObject(env, fileclass, constructor, filename);
//    GOTO_ERROR_IF_TRUE(!fileobject, FLX_RET_ERROR);
//
//    // return new File("/dev/socket/qemud").exists();
//    returnValue = (*env)->CallBooleanMethod(env, fileobject, existsMethod);
//
//Error:
//
//    return returnValue;
//}




/*
* Class:     capstone_Capstone
* Method:    cs_open
* Signature: (IILcapstone/LongByReference;)I
*/
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1open
(JNIEnv *env, jobject thisObj, jint arch, jint mode, jobject handleRef)
{
    printf("Called open with thisObj=%p arch=%d mode=%d handle=%p\n", thisObj, arch, mode, handleRef);

    csh handle = 0;
    cs_err err = cs_open(arch, mode, &handle);

    printf("Open returned err=%d handle=0x%zx\n", err, handle);

    cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

    // Get a reference to this object's class
    jclass handleClass = (*env)->GetObjectClass(env, handleRef);
    // Get the Method ID for method "callback", which takes a long and return void
    jmethodID setValueMethodId = (*env)->GetMethodID(env, handleClass, "setValue", "(J)V");
    if (NULL == setValueMethodId) {
	printf("Could not find method\n");
	return CS_ERR_CSH;
    }

    printf("Handle class %p methodID %p\n", handleClass, setValueMethodId);

    printf("About to call method...\n");
    (*env)->CallVoidMethod(env, handleRef, setValueMethodId, (jlong)handle);
    printf("Called method!\n");

    //mConstructor = (*env)->GetMethodID(env, gFLXS_AD_RegistrationResultClass, "<init>", "(IILjava/lang/String;Ljava/lang/String;)V");
    //GOTO_ERROR_IF_TRUE(!mConstructor, FLX_RET_ERROR);

    return err;
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

    printf("Called disasm... handle %llx\n", handle);
    // test();

    jbyte* codeBytes = (*env)->GetByteArrayElements(env, code, NULL);
    printf("here\n");

    for (int i = 0; i < code_len; i++) {
	printf("0x%x ", codeBytes[i]);
    }
    printf("\n");

    cs_insn *insn = NULL; 
    
    // size_t CAPSTONE_API cs_disasm(csh ud, const uint8_t *buffer, size_t size, uint64_t offset, size_t count, cs_insn **insn)
    size_t actualCount = cs_disasm(handle, codeBytes, code_len, addr, 0, &insn);

    printf("Disasm was count=%zd\n", actualCount);


    if (actualCount) {
	long j;

	printf("****************\n");
	printf("Disasm (count %zd):\n", actualCount);

	for (j = 0; j < actualCount; j++) {
	    cs_insn* ci = &insn[j];
	    printf("%d 0x%" PRIx64 ":\t%s\t%s\n", j, insn[j].address, insn[j].mnemonic, insn[j].op_str);
	    print_insn_detail(handle, CS_MODE_16, &insn[j]);


	    

	 //   Type Signature
		//Java Type
		//Z		boolean
		//B		byte
		//C		char
		//S		short
		//I		int
		//J		long
		//F		float
		//D		double
		//L fully - qualified - class;	    fully - qualified - class
		//[type		type[]
		//(arg - types) ret - type		method type
		//V is void return type, so you could have()V

	    // Convert instruction
	    {
		jstring    filename = NULL;
		jclass    jclass_cs_insn = NULL;
		jboolean  returnValue = JNI_FALSE;
		jmethodID  constructor = NULL;
		jmethodID  existsMethod = NULL;
		jobject    javaObject = NULL;

		jclass_cs_insn = (*env)->FindClass(env, "capstone/Capstone$_cs_insn");
		printf("Found class %x\n", (long)jclass_cs_insn);

		constructor = (*env)->GetMethodID(env, jclass_cs_insn, "<init>", "()V");
		printf("Found constructor %x\n", (long)constructor);
		
		javaObject = (*env)->NewObject(env, jclass_cs_insn, constructor);


		//public int id;
		//public long address;
		//public short size;
		//public byte[] bytes;
		//public String mnemonic;
		//public String op_str;
		//public _cs_detail cs_detail;

		jfieldID field_id = (*env)->GetFieldID(env, jclass_cs_insn, "id", "I");
		jfieldID field_address = (*env)->GetFieldID(env, jclass_cs_insn, "address", "J");
		jfieldID field_size = (*env)->GetFieldID(env, jclass_cs_insn, "size", "S");
		jfieldID field_bytes = (*env)->GetFieldID(env, jclass_cs_insn, "bytes", "[B");
		jfieldID field_mnemonic = (*env)->GetFieldID(env, jclass_cs_insn, "mnemonic", "Ljava/lang/String;");
		jfieldID field_op_str = (*env)->GetFieldID(env, jclass_cs_insn, "op_str", "Ljava/lang/String;");
		jfieldID field_detail = (*env)->GetFieldID(env, jclass_cs_insn, "cs_detail", "Lcapstone/Capstone$_cs_detail;");

		(*env)->SetIntField(env, javaObject, field_id, ci->id);
		(*env)->SetLongField(env, javaObject, field_address, ci->address);
		(*env)->SetShortField(env, javaObject, field_size, ci->size);

		jbyteArray jary = (jintArray)(*env)->GetObjectField(env, javaObject, field_bytes);
		(*env)->SetByteArrayRegion(env, jary, 0, ci->size, ci->bytes);

		jstring mnem = (*env)->NewStringUTF(env, ci->mnemonic);
		(*env)->SetObjectField(env, javaObject, field_mnemonic, mnem);

		jstring ops = (*env)->NewStringUTF(env, ci->op_str);
		(*env)->SetObjectField(env, javaObject, field_op_str, ops);



		// Add to ArrayList
		{
		    jclass arrayList = (*env)->FindClass(env, "Ljava/util/ArrayList;");
		    jmethodID array_add = (*env)->GetMethodID(env, arrayList, "add", "(Ljava/lang/Object;)Z");
		    printf("Arraylist class %x add method %x\n", arrayList, array_add);
		    (*env)->CallBooleanMethod(env, insnArray, array_add, javaObject);
		}

	    }









	}
	printf("0x%" PRIx64 ":\n", insn[j - 1].address + insn[j - 1].size);

	// free memory allocated by cs_disasm()
	cs_free(insn, count);
    }
    else {
	printf("****************\n");
	printf("ERROR: Failed to disasm given code!\n");
    }

 //   printf("\n");

    return 0;
}

/*
* Class:     capstone_Capstone
* Method:    cs_close
* Signature: (J)I
*/
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1close
(JNIEnv *env, jobject thisObj, jlong handle)
{
    printf("Called close with handle 0x%llx...\n", handle);
    csh* h = (csh*)handle;
    cs_close(h);
    return 0;
}

/*
* Class:     capstone_Capstone
* Method:    cs_option
* Signature: (JIJ)I
*/
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1option
(JNIEnv * env, jobject thisObj, jlong handle, jint option, jlong optionValue)
{
    printf("Called options...");
    return 0;
}
