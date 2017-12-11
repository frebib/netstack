SRCDIR = src
OBJDIR = obj
INCDIR = include

override CFLAGS  += -fPIC -I$(INCDIR) -Wall -Werror -Wpedantic -Wno-unused-variable
override LDFLAGS += -shared -Wl,--as-needed
override LDLIBS  += -lpthread

# Source and header files
SRC = $(shell find $(SRCDIR) -type f -name '*.c')
INC = $(shell find $(INCDIR) -type f -name '*.h')
OBJ = $(patsubst $(SRCDIR)%,$(OBJDIR)%,$(patsubst %.c, %.o, $(SRC)))

# Target declarations
TARGET_LIB = libnetstack.so

PREFIX  = /usr/local
DESTDIR =

export PREFIX DESTDIR

.PHONY: default all build
default: all
all: build doc
build: $(TARGET_LIB)

# Compilation
$(TARGET_LIB): $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) $(LDLIBS) -o $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INC)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@ $(LDLIBS)

# Misc
.PHONY: test doc install uninstall clean
test: $(TARGET_LIB)
	make -C tests all

doc:
	@echo 'No documentation to build yet'

install: $(TARGET_LIB)
	install -Dm644 $(TARGET_LIB) $(DESTDIR)$(PREFIX)/lib/$(TARGET_LIB)

uninstall:
	$(RM) $(DESTDIR)/$(PREFIX)/lib/$(TARGET_LIB)

clean:
	$(RM) -r $(OBJDIR) $(TARGET_LIB)
