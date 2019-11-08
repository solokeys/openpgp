
MBEDTLS_DIR=./mbedtls/
_SRCS=aes.c asn1parse.c asn1write.c \
            bignum.c \
            ccm.c cipher.c cipher_wrap.c ctr_drbg.c \
            dhm.c ecdh.c ecdsa.c ecp.c \
            ecp_curves.c entropy.c entropy_poll.c \
            havege.c md.c md2.c md4.c md5.c \
            md_wrap.c oid.c \
            rsa_internal.c platform_util.c \
            sha1.c rsa.c sha256.c sha512.c

# MBEDTLS_SRCS := $(patsubst %.cpp, $(OBJ_DIR)/%.cpp, $(notdir $(_SRCS)))
MBEDTLS_SRCS := $(foreach var, $(_SRCS), $(MBEDTLS_DIR)$(var))

MBEDTLS_INCLUDE= -Imbedtls/include/   -Imbedtls/include/mbedtls
MBEDTLS_CONFIG= -I. -DMBEDTLS_CONFIG_FILE=\"mbedtls_config.h\"

MBEDTLS_OBJ = $(MBEDTLS_SRCS:.c=.o)

$(MBEDTLS_DIR)%.o:  $(MBEDTLS_DIR)%.c
	gcc  $^ -o $@ $(MBEDTLS_INCLUDE) $(MBEDTLS_CONFIG) -c -Os -fdata-sections -ffunction-sections


mbedtls.a: $(MBEDTLS_DIR) $(MBEDTLS_OBJ)
	ar -rc  mbedtls.a $(MBEDTLS_OBJ)  
	ar -s mbedtls.a

$(MBEDTLS_DIR):
	echo "Error: need to download mbedtls."
