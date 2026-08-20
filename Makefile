# Standalone command-line build for the Hello_World (app) project,
# independent of the S32DS IDE. Mirrors the compiler/linker flags S32DS
# itself uses (taken from .cproject's Debug_FLASH configuration), so the
# output matches what "Build Project" in S32DS produces.
#
# Output goes to Debug_FLASH/ - the same directory and filenames (Hello_World.elf/.bin)
# that the S32DS IDE build produces - because the sibling s32k_easy_boot project's
# linker script embeds ../../s32k_demo/Debug_FLASH/Hello_World.bin by that exact path.
# Building here with either the IDE or this Makefile is interchangeable; just
# run a clean (IDE "Clean" or `make clean`) before switching between the two,
# since IDE-generated and Makefile-generated objects aren't tracked the same way.
#
# Usage:
#   make                 # build Debug_FLASH/Hello_World.elf and .bin
#   make clean
#   make GCC_PATH=... RTD_BASE_PATH=...   # override toolchain/RTD location

GCC_PATH      ?= C:/NXP/S32DS.3.5/S32DS/build_tools/gcc_v10.2/gcc-10.2-arm32-eabi/bin
RTD_BASE_PATH ?= C:/NXP/S32DS.3.5/S32DS/software/PlatformSDK_S32K3/RTD

SRC_DIRS     = src RTD/src board generate/src Project_Settings/Startup_Code \
		  mbedtls_hse/library \
		  mbedtls_hse/3rdparty_nxp_hse/library/alt_layer \
		  mbedtls_hse/3rdparty_nxp_hse/library/custom_layer \
		  mbedtls_hse/nxp_hse_al_hse_dal/src \
		  mbedtls_hse/nxp_hse_al_keystore_mgmt/src \
		  mbedtls_hse/nxp_common/src
PATH_BUILD   = Debug_FLASH
PATH_OBJS    = Debug_FLASH/objects

CC      = $(GCC_PATH)/arm-none-eabi-gcc
AS      = $(GCC_PATH)/arm-none-eabi-gcc -x assembler-with-cpp -g3
LD      = $(GCC_PATH)/arm-none-eabi-gcc
OBJCOPY = $(GCC_PATH)/arm-none-eabi-objcopy
SIZE    = $(GCC_PATH)/arm-none-eabi-size

CFLAGS  = -std=c99 \
		  -DD_CACHE_ENABLE -DI_CACHE_ENABLE -DENABLE_FPU -DMPU_ENABLE -DGCC \
		  -DS32K3XX -DS32K312 -DCPU_S32K312 -DCPU_CORTEX_M7 \
		  -DMBEDTLS_CONFIG_FILE='<nxp_hse_config.h>' \
		  -IRTD/include \
		  -Igenerate/include \
		  -Igenerate/src \
		  -Iboard \
		  -Iinclude \
		  -Imbedtls_hse/include \
		  -Imbedtls_hse/3rdparty_nxp_hse/include/config \
		  -Imbedtls_hse/3rdparty_nxp_hse/include/alt_layer \
		  -Imbedtls_hse/3rdparty_nxp_hse/include/custom_layer \
		  -Imbedtls_hse/nxp_hse_al_hse_dal/include \
		  -Imbedtls_hse/nxp_hse_al_keystore_mgmt/include \
		  -Imbedtls_hse/nxp_common/inc \
		  -Imbedtls_hse/nxp_common/hse_interface \
		  -I"$(RTD_BASE_PATH)/BaseNXP_TS_T40D34M50I0R0/header" \
		  -I"$(RTD_BASE_PATH)/BaseNXP_TS_T40D34M50I0R0/include" \
		  -I"$(RTD_BASE_PATH)/Platform_TS_T40D34M50I0R0/include" \
		  -I"$(RTD_BASE_PATH)/Platform_TS_T40D34M50I0R0/startup/include" \
		  -Os -funsigned-char -fomit-frame-pointer -ggdb3 -Wall -Wextra -c \
		  -fno-short-enums -funsigned-bitfields -fno-common -Wunused \
		  -Wsign-compare -Werror=implicit-function-declaration \
		  -mcpu=cortex-m7 -mthumb -mlittle-endian -mfloat-abi=hard -mfpu=fpv5-sp-d16 \
		  -specs=nano.specs -specs=nosys.specs \
		  --sysroot="$(GCC_PATH)/../arm-none-eabi/lib"

LDFLAGS = -nostartfiles --entry=Reset_Handler -ggdb3 \
		  -T Project_Settings/Linker_Files/linker_flash_s32k312.ld \
		  -Wl,-Map,"$(PATH_BUILD)/Hello_World.map" \
		  -mcpu=cortex-m7 -mthumb -mlittle-endian -mfloat-abi=hard -mfpu=fpv5-sp-d16 \
		  -specs=nano.specs -specs=nosys.specs \
		  --sysroot="$(GCC_PATH)/../arm-none-eabi/lib" \
		  -lc -lm -lgcc

# dhm_alt.c (classic/finite-field DH) unconditionally references
# key_import_param_t union members that only exist when HSE_SPT_CLASSIC_DH
# is defined - and that flag reflects actual HSE firmware capability
# (hse_b_config.h), not a convenience toggle. Not enabling it without
# confirming this firmware build supports classic DH, so this file is
# excluded from the active build (still present in the tree).
EXCLUDE_SRCS = mbedtls_hse/3rdparty_nxp_hse/library/alt_layer/dhm_alt.c \
		  mbedtls_hse/3rdparty_nxp_hse/library/alt_layer/nxp_hse_dhm.c \
		  mbedtls_hse/nxp_common/src/global_variables.c \
		  mbedtls_hse/nxp_common/src/device.c

SRCS    = $(filter-out $(EXCLUDE_SRCS),$(foreach d,$(SRC_DIRS),$(wildcard $(d)/*.c)))
SRCS_AS = $(foreach d,$(SRC_DIRS),$(wildcard $(d)/*.s))
OBJS    = $(patsubst %.c,$(PATH_OBJS)/%.o,$(notdir $(SRCS))) $(patsubst %.s,$(PATH_OBJS)/%.o,$(notdir $(SRCS_AS)))

vpath %.c $(SRC_DIRS)
vpath %.s $(SRC_DIRS)

MKDIR = mkdir -p

.PHONY: all clean printsize build_magic

all: build_magic $(PATH_BUILD)/Hello_World.bin printsize

build_magic:
	python tools/gen_build_magic.py

$(PATH_BUILD) $(PATH_OBJS):
	$(MKDIR) $@

$(PATH_BUILD)/Hello_World.elf: $(OBJS) Project_Settings/Linker_Files/linker_flash_s32k312.ld | $(PATH_BUILD)
	$(LD) -o $@ $(OBJS) $(LDFLAGS)

$(PATH_BUILD)/Hello_World.bin: $(PATH_BUILD)/Hello_World.elf
	$(OBJCOPY) -O binary $< $@

$(PATH_OBJS)/%.o: %.c include/build_magic.h | $(PATH_OBJS)
	$(CC) $(CFLAGS) $< -o $@

$(PATH_OBJS)/%.o: %.s | $(PATH_OBJS)
	$(AS) $(CFLAGS) $< -o $@

# Not using -MMD -MP / auto dependency re-include here: on this toolchain,
# generated .d files escape Windows drive-letter colons as "C\:" which
# mingw32-make chokes on when re-including them on a second invocation
# (same root cause AGENTS.md documents for s32k312_provision's CLI make).
# Practical effect: this Makefile always does a fresh per-file compile check
# on header changes via `make clean && make`, not true incremental rebuilds.

printsize: $(PATH_BUILD)/Hello_World.elf
	$(SIZE) --format=berkeley $<

clean:
	rm -rf $(PATH_BUILD)
