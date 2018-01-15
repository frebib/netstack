SRCDIR = lib
OBJDIR = obj
INCDIR = include

override CFLAGS  += -Wall -Werror -Wno-unused-variable -Wno-unused-function -Wno-missing-braces -fstack-protector -O3 -g
override INCLUD  += -I$(INCDIR) -I$(RBUF_DIR)/src
override LDFLAGS += -shared -L$(RBUF_DIR) -Wl,--as-needed -Wl,-enable-new-dtags,-rpath,"$(RBUF_DIR)"
override LDLIBS  += -lpthread -lrt -lrbuf

# Source and header files
SRC = $(shell find $(SRCDIR) -type f -name '*.c')
INC = $(shell find $(INCDIR) -type f -name '*.h')
OBJ = $(patsubst $(SRCDIR)%,$(OBJDIR)%,$(patsubst %.c, %.o, $(SRC)))

# Target declarations
TARGET_LIB = libnetstack.so

TEST_DIR = tests

NETD_DIR = tools/netd
NETD = $(NETD_DIR)/netd

RBUF_DIR = ext/ring_buffer
RBUF = $(RBUF_DIR)/librbuf.so

PREFIX  = /usr/local
DESTDIR =

export PREFIX DESTDIR

.PHONY: default all build ext tools
default: all
all: build doc
build: $(TARGET_LIB) tools
ext: $(RBUF)
tools: netd

# Compilation
$(TARGET_LIB): $(RBUF) $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) $(LDLIBS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INC)
	@mkdir -p $(@D)
	$(CC) -fPIC $(INCLUD) $(CFLAGS) -c $< -o $@

# Tools
netd: $(NETD)
$(NETD):
	@make -C $(NETD_DIR)
	@ln -sfv $(NETD) netd

$(RBUF):
	@make -C $(@D) dynamic

# Misc
.PHONY: test doc install uninstall clean
test: $(TARGET_LIB)
	@make -C $(TEST_DIR) all
	@make -C $(RBUF_DIR) test
	@make -C $(NETD_DIR) test

doc:
	@echo 'No documentation to build yet'

install: $(TARGET_LIB) tools
	install -Dm644 $(TARGET_LIB) $(DESTDIR)$(PREFIX)/lib/$(TARGET_LIB)
	install -m644  $(RBUF)       $(DESTDIR)$(PREFIX)/lib/$(notdir $(RBUF))
	@make -C $(NETD_DIR) install

uninstall:
	$(RM) $(DESTDIR)/$(PREFIX)/lib/$(TARGET_LIB)
	$(RM) $(DESTDIR)$(PREFIX)/lib/$(notdir $(RBUF))
	@make -C $(NETD_DIR) uninstall

clean:
	$(RM) -r $(OBJDIR) $(TARGET_LIB)
	$(RM) ./netd
	@make -C $(RBUF_DIR) clean
	@make -C $(TEST_DIR) clean
	@make -C $(NETD_DIR) clean
