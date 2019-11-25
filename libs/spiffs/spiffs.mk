
SPIFFS_DIR=./libs/spiffs/spiffs/src/
_SRCS=aes.c asn1parse.c asn1write.c \
_SRCS  = spiffs_nucleus.c
_SRCS += spiffs_gc.c
_SRCS += spiffs_hydrogen.c
_SRCS += spiffs_cache.c
_SRCS += spiffs_check.c

SPIFFS_SRCS := $(foreach var, $(_SRCS), $(SPIFFS_DIR)$(var))

SPIFFS_INCLUDE= -I. -Ilibs/spiffs -Ilibs/spiffs/spiffs/src/ -Ilibs/spiffs/

SPIFFS_OBJ = $(MBEDTLS_SRCS:.c=.o)

$(MBEDTLS_DIR)%.o:  $(SPIFFS_DIR)%.c
	gcc  $^ -o $@ $(SPIFFS_INCLUDE) -c -Os -fdata-sections -ffunction-sections


$(SPIFFS_DIR):
	@echo "Error: need to download spiffs."
