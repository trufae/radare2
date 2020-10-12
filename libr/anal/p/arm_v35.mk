N=anal_arm_v35
OBJ_ARM_V35=anal_arm_v35.o

STATIC_OBJ+=${OBJ_ARM_V35}

TARGET_ARM_V35=$(N).${EXT_SO}

ALL_TARGETS+=${TARGET_ARM_V35}

${TARGET_ARM_V35}: ${OBJ_ARM_V35}
	${CC} ${CFLAGS} $(call libname,$(N)) $(V35_CFLAGS) \
		-o $(TARGET_ARM_V35) ${OBJ_ARM_V35} $(V35_LDFLAGS)
