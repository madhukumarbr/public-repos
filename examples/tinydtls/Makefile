########################################################################
# platform-specific options

ifeq ($(TARGET), econotag)
CFLAGS += -DUIP_CONF_TCP=0
endif

ifeq ($(TARGET), minimal-net)
UIP_CONF_IPV6_RPL=0
CFLAGS += -DUIP_CONF_IPV6_RPL=0 -DRPL_BORDER_ROUTER=0
endif

# usually, you should not need changing anything beyond this line
########################################################################

# the library's version
VERSION:=0.8.2

CONTIKI_PROJECT = dtls-server dtls-client
all:	$(CONTIKI_PROJECT)
	$(MAKE) $(MAKEFLAGS) ROLE=server dtls-server
#	$(MAKE) $(MAKEFLAGS) clean
#	$(MAKE) $(MAKEFLAGS) ROLE=client dtls-client

CONTIKI=../..

WITH_UIP6=1
UIP_CONF_IPV6=1

ifneq ($(ROLE),client)
	CFLAGS+= -DHARD_CODED_ADDRESS=\"aaaa::02:232\"
else
	CFLAGS+= -DUDP_CONNECTION_ADDR="fe80::ff:fe02:232" \
		 -DHARD_CODED_ADDRESS=\"aaaa::02:230\"
endif

CFLAGS += -ffunction-sections
ifeq ($(TARGET), cooja)
LDFLAGS += --gc-sections --undefined=_reset_vector__ --undefined=InterruptVectors --undefined=_copy_data_init__ --undefined=_clear_bss_init__ --undefined=_end_of_init__
else
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__
endif

CFLAGS += -DSHA2_USE_INTTYPES_H

APPS += tinydtls/aes tinydtls/sha2 tinydtls/ecc tinydtls

ifeq ("1", "1")
include $(CONTIKI)/Makefile.include
endif
