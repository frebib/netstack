SRCDIR = src
OBJDIR = obj
LIBDIR = ../..
INCDIR = $(LIBDIR)/include

CFLAGS  ?= -Wall -Werror -Wno-unused-variable -Wno-unused-function -Wno-unused-parameter -Wno-missing-braces -fstack-protector -O3 -g
CFLAGS  += -I$(INCDIR)
LDFLAGS += -shared -Wl,--as-needed,-enable-new-dtags,-rpath,"$(LIBDIR)",-rpath,. -L$(LIBDIR)
LDLIBS  += -lnetstack -lcap -ldl

# Source and header files
SRC = $(shell find $(SRCDIR) -type f -name '*.c')
INC = $(shell find $(SRCDIR) -type f -name '*.h')
OBJ = $(patsubst $(SRCDIR)%,$(OBJDIR)%,$(patsubst %.c, %.o, $(SRC)))

# Target declarations
TARGET_LIB = libnshook.so
HOOK_SCRIPT = ../netstack-run

PREFIX  = /usr/local
DESTDIR =

export PREFIX DESTDIR

.PHONY: default all build
default: all
all: build
build: $(TARGET_LIB)

# Compilation
$(TARGET_LIB): $(OBJ)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INC)
	@mkdir -p $(@D)
	$(CC) -fPIC $(CFLAGS) $(INCLUD) -c $< -o $@

# Misc
.PHONY: install uninstall clean
install: $(TARGET_LIB) $(HOOK_SCRIPT)
	install -Dm644 $(TARGET_LIB) $(DESTDIR)$(PREFIX)/lib/$(TARGET_LIB)
	install -Dm755 $(HOOK_SCRIPT) $(DESTDIR)$(PREFIX)/bin/$(notdir $(HOOK_SCRIPT))

uninstall:
	$(RM) $(DESTDIR)$(PREFIX)/lib/$(TARGET_LIB)
	$(RM) $(DESTDIR)$(PREFIX)/bin/$(notdir $(HOOK_SCRIPT))

clean:
	$(RM) -r $(OBJDIR) $(TARGET_LIB)
