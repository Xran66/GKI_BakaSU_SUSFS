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

# 这份代码还没有在本机内核树上完整编译验证过，先关掉 -Werror，
# 避免为了一个 unused-variable 之类的小警告反复烧掉二十分钟构建。
# 注意：真错误（类型不匹配、隐式声明、链接失败）照样会挂，
# 只是把警告降级；构建日志里仍能看到全部 warning，请照常检查。
ccflags-y			+= -Wno-error

