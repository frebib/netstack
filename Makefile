SRCDIR = lib
OBJDIR = obj
INCDIR = include

override CFLAGS  += -Wall -Werror -Wno-unused-variable -Wno-unused-function -Wno-unused-parameter -Wno-missing-braces -fstack-protector -O3 -g
override INCLUD  += -I$(INCDIR)
override LDFLAGS += -shared -Wl,--as-needed
override LDLIBS  += -pthread -lrt

# Source and header files
SRC = $(shell find $(SRCDIR) -type f -name '*.c')
INC = $(shell find $(INCDIR) -type f -name '*.h')
OBJ = $(patsubst $(SRCDIR)%,$(OBJDIR)%,$(patsubst %.c, %.o, $(SRC)))

# Target declarations
TARGET_LIB = libnetstack.so

TEST_DIR = tests

NETD_DIR = tools/netd
NETD = $(NETD_DIR)/netd
LIBNSHOOK_DIR = tools/nshook
LIBNSHOOK = $(LIBNSHOOK_DIR)/libnshook.so

PREFIX  = /usr/local
DESTDIR =

export PREFIX DESTDIR

.PHONY: default all build ext tools
default: all
all: build doc
build: $(TARGET_LIB) tools
tools: $(notdir $(NETD)) $(notdir $(LIBNSHOOK))

# Compilation
$(TARGET_LIB): $(OBJ)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INC)
	@mkdir -p $(@D)
	$(CC) -fPIC $(INCLUD) $(CFLAGS) -c $< -o $@

# Tools
$(notdir $(NETD)): $(NETD)
	@ln -sfv $(NETD) $(notdir $(NETD))
$(NETD): $(TARGET_LIB)
	@$(MAKE) -C $(NETD_DIR)

$(notdir $(LIBNSHOOK)): $(LIBNSHOOK)
	@ln -sfv $(LIBNSHOOK) $(notdir $(LIBNSHOOK))
$(LIBNSHOOK): $(TARGET_LIB)
	@$(MAKE) -C $(LIBNSHOOK_DIR)

# Misc
.PHONY: test doc install uninstall clean
test: $(TARGET_LIB)
	@$(MAKE) -C $(TEST_DIR) all
	@$(MAKE) -C $(NETD_DIR) test

doc:
	@echo 'No documentation to build yet'

install: $(TARGET_LIB) tools
	install -Dm644 $(TARGET_LIB) $(DESTDIR)$(PREFIX)/lib/$(TARGET_LIB)
	@$(MAKE) -C $(NETD_DIR) install
	@$(MAKE) -C $(LIBNSHOOK_DIR) install

uninstall:
	$(RM) $(DESTDIR)/$(PREFIX)/lib/$(TARGET_LIB)
	@$(MAKE) -C $(NETD_DIR) uninstall
	@$(MAKE) -C $(LIBNSHOOK_DIR) uninstall

clean:
	$(RM) -r $(OBJDIR) $(TARGET_LIB)
	$(RM) $(notdir $(NETD))
	$(RM) $(notdir $(LIBNSHOOK))
	@$(MAKE) -C $(TEST_DIR) clean
	@$(MAKE) -C $(NETD_DIR) clean
	@$(MAKE) -C $(LIBNSHOOK_DIR) clean
