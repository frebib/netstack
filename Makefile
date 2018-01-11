SRCDIR = lib
OBJDIR = obj
INCDIR = include

override CFLAGS  += -I$(INCDIR) -Wall -Werror -Wno-unused-variable -Wno-missing-braces -fstack-protector -O3
override LDFLAGS += -shared -Wl,--as-needed
override LDLIBS  += -lpthread -lrt

# Source and header files
SRC = $(shell find $(SRCDIR) -type f -name '*.c')
INC = $(shell find $(INCDIR) -type f -name '*.h')
OBJ = $(patsubst $(SRCDIR)%,$(OBJDIR)%,$(patsubst %.c, %.o, $(SRC)))

# Target declarations
TARGET_LIB = libnetstack.so

TEST_DIR = tests

NETD_DIR = tools/netd
NETD = $(NETD_DIR)/netd

PREFIX  = /usr/local
DESTDIR =

export PREFIX DESTDIR

.PHONY: default all build
default: all
all: build doc
build: $(TARGET_LIB) tools
tools: netd

# Compilation
$(TARGET_LIB): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) $(LDLIBS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INC)
	@mkdir -p $(@D)
	$(CC) -fPIC $(CFLAGS) -c $< -o $@

# Tools
netd: $(NETD)
$(NETD):
	@make -C $(NETD_DIR)
	@ln -sfv $(NETD) .

# Misc
.PHONY: test doc install uninstall clean
test: $(TARGET_LIB)
	@make -C $(TEST_DIR) all
	@make -C $(NETD_DIR) test

doc:
	@echo 'No documentation to build yet'

install: $(TARGET_LIB) tools
	install -Dm644 $(TARGET_LIB) $(DESTDIR)$(PREFIX)/lib/$(TARGET_LIB)
	@make -C $(NETD_DIR) install

uninstall:
	$(RM) $(DESTDIR)/$(PREFIX)/lib/$(TARGET_LIB)
	@make -C $(NETD_DIR) uninstall

clean:
	$(RM) -r $(OBJDIR) $(TARGET_LIB)
	$(RM) ./netd
	@make -C $(TEST_DIR) clean
	@make -C $(NETD_DIR) clean
