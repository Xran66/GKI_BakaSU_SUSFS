# SPDX-License-Identifier: GPL-2.0
#
# 全部用 obj-y 编进内核镜像，不做成模块（.ko 才会进 /proc/modules、taint O 位）
#
obj-$(CONFIG_KAIROS)		+= kairos_core.o
obj-$(CONFIG_KAIROS)		+= kairos_mem.o
obj-$(CONFIG_KAIROS)		+= kairos_ioctl.o
obj-$(CONFIG_KAIROS)		+= kairos_auth.o

obj-$(CONFIG_KAIROS_GYRO_HOOK)	+= kairos_gyro.o

# 日志开关：CONFIG_KAIROS_DEBUG 关掉时 kairos_log.h 里的宏会被编译成空
ccflags-$(CONFIG_KAIROS_DEBUG)	+= -DKAIROS_VERBOSE
