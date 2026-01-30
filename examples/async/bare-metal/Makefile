CC ?= gcc
AR ?= ar
RM ?= rm -f

WOLFSSL_TOP ?= $(abspath ../../..)
OBJDIR ?= build

CFLAGS ?= -O0 -g
CFLAGS += -I.
CFLAGS += -I$(WOLFSSL_TOP)
CFLAGS += -I$(WOLFSSL_TOP)/wolfssl
CFLAGS += -I$(WOLFSSL_TOP)/wolfssl/wolfcrypt
CFLAGS += -DWOLFSSL_USER_SETTINGS

LDFLAGS ?=
LDLIBS ?=

TARGET = tls13_client

WOLFSSL_SRC := $(wildcard $(WOLFSSL_TOP)/src/*.c)
WOLFCRYPT_SRC := $(wildcard $(WOLFSSL_TOP)/wolfcrypt/src/*.c)
LOCAL_SRC := tls13_client.c

WOLFSSL_OBJS := $(patsubst $(WOLFSSL_TOP)/%, $(OBJDIR)/%, $(WOLFSSL_SRC:.c=.o))
WOLFCRYPT_OBJS := $(patsubst $(WOLFSSL_TOP)/%, $(OBJDIR)/%, $(WOLFCRYPT_SRC:.c=.o))
LOCAL_OBJS := $(patsubst %.c, $(OBJDIR)/%.o, $(LOCAL_SRC))

OBJS := $(LOCAL_OBJS) $(WOLFSSL_OBJS) $(WOLFCRYPT_OBJS)

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $(OBJS) $(LDLIBS)

$(OBJDIR)/%.o: %.c user_settings.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: $(WOLFSSL_TOP)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	$(RM) -r $(OBJDIR) $(TARGET)
