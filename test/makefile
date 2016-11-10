
#BINPATH=~/sat/bin

CC=arm-none-eabi-gcc
AR=arm-none-eabi-ar
OBJCOPY=arm-none-eabi-objcopy
SIZE=arm-none-eabi-size

###################################################

# Check for valid float argument
ifneq ($(FLOAT_TYPE), hard)
ifneq ($(FLOAT_TYPE), soft)
#override FLOAT_TYPE = hard
override FLOAT_TYPE = soft
endif
endif

###################################################

LINK_DIRS =  -L.. -L../misc/libs/stm32f4 
LINK_LIBS = -lflea_stm32f4 
#-lstm32f4 -lm

INCLUDES = -Iinclude -Iinclude/api -I../misc/libs/stm32f4/inc -I../misc/libs/stm32f4/inc/core -I../misc/libs/stm32f4/inc/peripherals -I../include/api -I../include -I../include/api -I../test/include

vpath %.c src/common src/stm32f4

CFLAGS  = -g -O3 -Wall -std=gnu99 -Tsrc/stm32f4/stm32_flash.ld
#-g 

CFLAGS += $(INCLUDES) -DFLEA_PLTF_ARM_32BIT

CFLAGS += -mlittle-endian -mthumb -mthumb-interwork -mcpu=cortex-m4 -nostartfiles

ifeq ($(FLOAT_TYPE), hard)
CFLAGS += -fsingle-precision-constant -Wdouble-promotion
CFLAGS += -mfpu=fpv4-sp-d16 -mfloat-abi=hard
# discard unused code during linking:
CFLAGS += -fdata-sections -ffunction-sections -Wl,--gc-sections
#CFLAGS += -mfpu=fpv4-sp-d16 -mfloat-abi=softfp
else
CFLAGS += -msoft-float
endif

CFLAGS += -ffreestanding 
#-nostdlib
CFLAGS += -Iinc -Iinc/core -Iinc/peripherals



SRC_DIRS = src/common src/stm32f4

SRCS := $(foreach dir,$(SRC_DIRS),$(wildcard $(dir)/*.c))
#SRCS += src/stm32f4/startup_stm32f4xx.s #src/test.s # add startup file to build

$(info $$SRCS is [${SRCS}])

OBJDIR = ../build/stm32f4/test
OBJS_RAW = $(SRCS:.c=.o)

OBJS = $(addprefix $(OBJDIR)/, $(OBJS_RAW))

DEPS_RAW = $(SRCS:.c=.d)

DEPS = $(addprefix $(OBJDIR)/, $(DEPS_RAW))


#.PHONY: flea_test_stm32f4

all: flea_test_stm32f4.elf
	$(SIZE) flea_test_stm32f4.elf

test: flea_test_stm32f4.elf

$(OBJDIR)/%.o : %.c
	$(CC) -MMD $(CFLAGS) -c $< -o $@ 

flea_test_stm32f4.elf: $(OBJS)
	$(CC) $(CFLAGS) $^ src/stm32f4/startup_stm32f4xx.s -o $@ $(LINK_LIBS) $(LINK_DIRS) -Xlinker -Map=stm32f4.map

clean: 
	rm -f $(OBJS) flea_test_stm32f4.elf

-include $(DEPS)

