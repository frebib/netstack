SRCDIR = src
OBJDIR = obj

CFLAGS  ?= -Wall -Werror -Wno-unused-variable -Wno-unused-function -Wno-unused-parameter -Wno-missing-braces -O3 -g
LDFLAGS += -Wl,--as-needed

# Source and header files
SRC = $(shell find $(SRCDIR) -type f -name '*.c')
INC = $(shell find $(SRCDIR) -type f -name '*.h')
OBJ = $(patsubst $(SRCDIR)%,$(OBJDIR)%,$(patsubst %.c, %.o, $(SRC)))

# Target Declarations
HTTPGET_BIN = httpget

PREFIX  = /usr/local
DESTDIR =

export PREFIX DESTDIR

.PHONY: default all build
default: all
all: build
build: $(HTTPGET_BIN)

# Compilation
$(HTTPGET_BIN): $(OBJ)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INC)
	@mkdir -p $(@D)
	$(CC) -fPIC $(CFLAGS) -c $< -o $@

# Misc
.PHONY: clean
clean:
	$(RM) -r $(OBJDIR) $(HTTPGET_BIN)
