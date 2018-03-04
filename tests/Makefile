SRCDIR = src
BINDIR = bin
LIBDIR = ..
INCDIR = $(LIBDIR)/include

LIB_TARGET = libnetstack.so

override CFLAGS  += -I$(INCDIR) -Wall -Werror -Wpedantic -Wno-variadic-macros
override LDFLAGS += -L$(LIBDIR) -Wl,-enable-new-dtags,-rpath,"$(LIBDIR)"
override LDLIBS  += -lnetstack -lcheck

# Source and header files
SRC = $(shell find $(SRCDIR) -type f -name '*.c')
INC = $(shell find $(INCDIR) -type f -name '*.h')
BIN = $(patsubst $(SRCDIR)%, $(BINDIR)%, $(patsubst %.c, %, $(SRC)))

.PHONY: default all build lib run
default: all
all: build run

lib:
	@$(MAKE) -C $(LIBDIR) $(LIB_TARGET) >/dev/null

build: lib $(BIN)
$(BINDIR)/%: $(SRCDIR)/%.c $(INC)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(LDFLAGS) $(LDLIBS) $< -o $@

run: $(BIN)
	@$(foreach f,$^,./$(f);)

clean:
	$(RM) -r $(BINDIR)
