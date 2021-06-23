/* DO NOT EDIT THIS FILE - it is machine generated */
#include <jni.h>
/* Header for class capstone_Capstone */

#ifndef _Included_capstone_Capstone
#define _Included_capstone_Capstone
#ifdef __cplusplus
extern "C" {
#endif
#undef capstone_Capstone_CS_API_MAJOR
#define capstone_Capstone_CS_API_MAJOR 5L
#undef capstone_Capstone_CS_API_MINOR
#define capstone_Capstone_CS_API_MINOR 0L
#undef capstone_Capstone_CS_ARCH_ARM
#define capstone_Capstone_CS_ARCH_ARM 0L
#undef capstone_Capstone_CS_ARCH_ARM64
#define capstone_Capstone_CS_ARCH_ARM64 1L
#undef capstone_Capstone_CS_ARCH_MIPS
#define capstone_Capstone_CS_ARCH_MIPS 2L
#undef capstone_Capstone_CS_ARCH_X86
#define capstone_Capstone_CS_ARCH_X86 3L
#undef capstone_Capstone_CS_ARCH_PPC
#define capstone_Capstone_CS_ARCH_PPC 4L
#undef capstone_Capstone_CS_ARCH_SPARC
#define capstone_Capstone_CS_ARCH_SPARC 5L
#undef capstone_Capstone_CS_ARCH_SYSZ
#define capstone_Capstone_CS_ARCH_SYSZ 6L
#undef capstone_Capstone_CS_ARCH_XCORE
#define capstone_Capstone_CS_ARCH_XCORE 7L
#undef capstone_Capstone_CS_ARCH_M68K
#define capstone_Capstone_CS_ARCH_M68K 8L
#undef capstone_Capstone_CS_ARCH_TMS320C64X
#define capstone_Capstone_CS_ARCH_TMS320C64X 9L
#undef capstone_Capstone_CS_ARCH_M680X
#define capstone_Capstone_CS_ARCH_M680X 10L
#undef capstone_Capstone_CS_ARCH_MAX
#define capstone_Capstone_CS_ARCH_MAX 11L
#undef capstone_Capstone_CS_ARCH_ALL
#define capstone_Capstone_CS_ARCH_ALL 65535L
#undef capstone_Capstone_CS_MODE_LITTLE_ENDIAN
#define capstone_Capstone_CS_MODE_LITTLE_ENDIAN 0L
#undef capstone_Capstone_CS_MODE_ARM
#define capstone_Capstone_CS_MODE_ARM 0L
#undef capstone_Capstone_CS_MODE_16
#define capstone_Capstone_CS_MODE_16 2L
#undef capstone_Capstone_CS_MODE_32
#define capstone_Capstone_CS_MODE_32 4L
#undef capstone_Capstone_CS_MODE_64
#define capstone_Capstone_CS_MODE_64 8L
#undef capstone_Capstone_CS_MODE_THUMB
#define capstone_Capstone_CS_MODE_THUMB 16L
#undef capstone_Capstone_CS_MODE_MCLASS
#define capstone_Capstone_CS_MODE_MCLASS 32L
#undef capstone_Capstone_CS_MODE_V8
#define capstone_Capstone_CS_MODE_V8 64L
#undef capstone_Capstone_CS_MODE_MICRO
#define capstone_Capstone_CS_MODE_MICRO 16L
#undef capstone_Capstone_CS_MODE_MIPS3
#define capstone_Capstone_CS_MODE_MIPS3 32L
#undef capstone_Capstone_CS_MODE_MIPS32R6
#define capstone_Capstone_CS_MODE_MIPS32R6 64L
#undef capstone_Capstone_CS_MODE_MIPS2
#define capstone_Capstone_CS_MODE_MIPS2 128L
#undef capstone_Capstone_CS_MODE_BIG_ENDIAN
#define capstone_Capstone_CS_MODE_BIG_ENDIAN -2147483648L
#undef capstone_Capstone_CS_MODE_V9
#define capstone_Capstone_CS_MODE_V9 16L
#undef capstone_Capstone_CS_MODE_MIPS32
#define capstone_Capstone_CS_MODE_MIPS32 4L
#undef capstone_Capstone_CS_MODE_MIPS64
#define capstone_Capstone_CS_MODE_MIPS64 8L
#undef capstone_Capstone_CS_MODE_QPX
#define capstone_Capstone_CS_MODE_QPX 16L
#undef capstone_Capstone_CS_MODE_M680X_6301
#define capstone_Capstone_CS_MODE_M680X_6301 2L
#undef capstone_Capstone_CS_MODE_M680X_6309
#define capstone_Capstone_CS_MODE_M680X_6309 4L
#undef capstone_Capstone_CS_MODE_M680X_6800
#define capstone_Capstone_CS_MODE_M680X_6800 8L
#undef capstone_Capstone_CS_MODE_M680X_6801
#define capstone_Capstone_CS_MODE_M680X_6801 16L
#undef capstone_Capstone_CS_MODE_M680X_6805
#define capstone_Capstone_CS_MODE_M680X_6805 32L
#undef capstone_Capstone_CS_MODE_M680X_6808
#define capstone_Capstone_CS_MODE_M680X_6808 64L
#undef capstone_Capstone_CS_MODE_M680X_6809
#define capstone_Capstone_CS_MODE_M680X_6809 128L
#undef capstone_Capstone_CS_MODE_M680X_6811
#define capstone_Capstone_CS_MODE_M680X_6811 256L
#undef capstone_Capstone_CS_MODE_M680X_CPU12
#define capstone_Capstone_CS_MODE_M680X_CPU12 512L
#undef capstone_Capstone_CS_MODE_M680X_HCS08
#define capstone_Capstone_CS_MODE_M680X_HCS08 1024L
#undef capstone_Capstone_CS_ERR_OK
#define capstone_Capstone_CS_ERR_OK 0L
#undef capstone_Capstone_CS_ERR_MEM
#define capstone_Capstone_CS_ERR_MEM 1L
#undef capstone_Capstone_CS_ERR_ARCH
#define capstone_Capstone_CS_ERR_ARCH 2L
#undef capstone_Capstone_CS_ERR_HANDLE
#define capstone_Capstone_CS_ERR_HANDLE 3L
#undef capstone_Capstone_CS_ERR_CSH
#define capstone_Capstone_CS_ERR_CSH 4L
#undef capstone_Capstone_CS_ERR_MODE
#define capstone_Capstone_CS_ERR_MODE 5L
#undef capstone_Capstone_CS_ERR_OPTION
#define capstone_Capstone_CS_ERR_OPTION 6L
#undef capstone_Capstone_CS_ERR_DETAIL
#define capstone_Capstone_CS_ERR_DETAIL 7L
#undef capstone_Capstone_CS_ERR_MEMSETUP
#define capstone_Capstone_CS_ERR_MEMSETUP 8L
#undef capstone_Capstone_CS_ERR_VERSION
#define capstone_Capstone_CS_ERR_VERSION 9L
#undef capstone_Capstone_CS_ERR_DIET
#define capstone_Capstone_CS_ERR_DIET 10L
#undef capstone_Capstone_CS_ERR_SKIPDATA
#define capstone_Capstone_CS_ERR_SKIPDATA 11L
#undef capstone_Capstone_CS_ERR_X86_ATT
#define capstone_Capstone_CS_ERR_X86_ATT 12L
#undef capstone_Capstone_CS_ERR_X86_INTEL
#define capstone_Capstone_CS_ERR_X86_INTEL 13L
#undef capstone_Capstone_CS_OPT_SYNTAX
#define capstone_Capstone_CS_OPT_SYNTAX 1L
#undef capstone_Capstone_CS_OPT_DETAIL
#define capstone_Capstone_CS_OPT_DETAIL 2L
#undef capstone_Capstone_CS_OPT_MODE
#define capstone_Capstone_CS_OPT_MODE 3L
#undef capstone_Capstone_CS_OPT_OFF
#define capstone_Capstone_CS_OPT_OFF 0L
#undef capstone_Capstone_CS_OPT_SYNTAX_INTEL
#define capstone_Capstone_CS_OPT_SYNTAX_INTEL 1L
#undef capstone_Capstone_CS_OPT_SYNTAX_ATT
#define capstone_Capstone_CS_OPT_SYNTAX_ATT 2L
#undef capstone_Capstone_CS_OPT_ON
#define capstone_Capstone_CS_OPT_ON 3L
#undef capstone_Capstone_CS_OPT_SYNTAX_NOREGNAME
#define capstone_Capstone_CS_OPT_SYNTAX_NOREGNAME 3L
#undef capstone_Capstone_CS_OP_INVALID
#define capstone_Capstone_CS_OP_INVALID 0L
#undef capstone_Capstone_CS_OP_REG
#define capstone_Capstone_CS_OP_REG 1L
#undef capstone_Capstone_CS_OP_IMM
#define capstone_Capstone_CS_OP_IMM 2L
#undef capstone_Capstone_CS_OP_MEM
#define capstone_Capstone_CS_OP_MEM 3L
#undef capstone_Capstone_CS_OP_FP
#define capstone_Capstone_CS_OP_FP 4L
#undef capstone_Capstone_CS_AC_INVALID
#define capstone_Capstone_CS_AC_INVALID 0L
#undef capstone_Capstone_CS_AC_READ
#define capstone_Capstone_CS_AC_READ 1L
#undef capstone_Capstone_CS_AC_WRITE
#define capstone_Capstone_CS_AC_WRITE 2L
#undef capstone_Capstone_CS_GRP_INVALID
#define capstone_Capstone_CS_GRP_INVALID 0L
#undef capstone_Capstone_CS_GRP_JUMP
#define capstone_Capstone_CS_GRP_JUMP 1L
#undef capstone_Capstone_CS_GRP_CALL
#define capstone_Capstone_CS_GRP_CALL 2L
#undef capstone_Capstone_CS_GRP_RET
#define capstone_Capstone_CS_GRP_RET 3L
#undef capstone_Capstone_CS_GRP_INT
#define capstone_Capstone_CS_GRP_INT 4L
#undef capstone_Capstone_CS_GRP_IRET
#define capstone_Capstone_CS_GRP_IRET 5L
#undef capstone_Capstone_CS_GRP_PRIVILEGE
#define capstone_Capstone_CS_GRP_PRIVILEGE 6L
#undef capstone_Capstone_CS_SUPPORT_DIET
#define capstone_Capstone_CS_SUPPORT_DIET 65536L
#undef capstone_Capstone_CS_SUPPORT_X86_REDUCE
#define capstone_Capstone_CS_SUPPORT_X86_REDUCE 65537L
/*
 * Class:     capstone_Capstone
 * Method:    cs_open
 * Signature: (IILcapstone/LongByReference;)I
 */
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1open
  (JNIEnv *, jobject, jint, jint, jobject);

/*
 * Class:     capstone_Capstone
 * Method:    cs_disasm
 * Signature: (J[BJJJLjava/util/ArrayList;)J
 */
JNIEXPORT jlong JNICALL Java_capstone_Capstone_cs_1disasm
  (JNIEnv *, jobject, jlong, jbyteArray, jlong, jlong, jlong, jobject);

/*
 * Class:     capstone_Capstone
 * Method:    cs_close
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1close
  (JNIEnv *, jobject, jlong);

/*
 * Class:     capstone_Capstone
 * Method:    cs_option
 * Signature: (JIJ)I
 */
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1option
  (JNIEnv *, jobject, jlong, jint, jlong);

/*
 * Class:     capstone_Capstone
 * Method:    cs_reg_name
 * Signature: (JI)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_capstone_Capstone_cs_1reg_1name
  (JNIEnv *, jobject, jlong, jint);

/*
 * Class:     capstone_Capstone
 * Method:    cs_insn_name
 * Signature: (JI)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_capstone_Capstone_cs_1insn_1name
  (JNIEnv *, jobject, jlong, jint);

/*
 * Class:     capstone_Capstone
 * Method:    cs_group_name
 * Signature: (JI)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_capstone_Capstone_cs_1group_1name
  (JNIEnv *, jobject, jlong, jint);

/*
 * Class:     capstone_Capstone
 * Method:    cs_errno
 * Signature: (J)I
 */
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1errno
  (JNIEnv *, jobject, jlong);

/*
 * Class:     capstone_Capstone
 * Method:    cs_version
 * Signature: (Lcapstone/IntByReference;Lcapstone/IntByReference;)I
 */
JNIEXPORT jint JNICALL Java_capstone_Capstone_cs_1version
  (JNIEnv *, jobject, jobject, jobject);

#ifdef __cplusplus
}
#endif
#endif
