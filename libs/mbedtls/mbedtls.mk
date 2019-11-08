
MBEDTLS_A=./libs/mbedtls/mbedtls.a
MBEDTLS_DIR=./libs/mbedtls/mbedtls/crypto/library/
_SRCS=aes.c asn1parse.c asn1write.c \
            bignum.c timing.c \
            ccm.c cipher.c cipher_wrap.c ctr_drbg.c \
            rsa_internal.c platform_util.c \
            sha1.c rsa.c sha256.c sha512.c \
            havege.c dhm.c entropy.c entropy_poll.c \
            ecp.c ecp_curves.c ecdsa.c ecdh.c \
            md.c md2.c md4.c md5.c oid.c

# MBEDTLS_SRCS := $(patsubst %.cpp, $(OBJ_DIR)/%.cpp, $(notdir $(_SRCS)))
MBEDTLS_SRCS := $(foreach var, $(_SRCS), $(MBEDTLS_DIR)$(var))

MBEDTLS_INCLUDE= -I. -Ilibs/mbedtls -Ilibs/mbedtls/mbedtls/include/ -Ilibs/mbedtls/mbedtls/crypto/include/
MBEDTLS_CONFIG= -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"

MBEDTLS_OBJ = $(MBEDTLS_SRCS:.c=.o)

$(MBEDTLS_DIR)%.o:  $(MBEDTLS_DIR)%.c
	gcc  $^ -o $@ $(MBEDTLS_INCLUDE) $(MBEDTLS_CONFIG) -c -Os -fdata-sections -ffunction-sections


libs/mbedtls/mbedtls.a: $(MBEDTLS_DIR) $(MBEDTLS_OBJ)
	ar -rc $(MBEDTLS_A) $(MBEDTLS_OBJ)  
	ar -s $(MBEDTLS_A)

$(MBEDTLS_DIR):
	@echo "Error: need to download mbedtls."
