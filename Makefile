SRCDIR = src
OBJDIR = obj
LIBDIR = lib/netstack
INCDIR = $(LIBDIR)/include

override CFLAGS  += -fPIC -I$(INCDIR) -Wall -Werror -Wpedantic -Wno-unused-variable -g
override LDFLAGS += -L$(LIBDIR) -Wl,--as-needed -Wl,-enable-new-dtags,-rpath,"$(LIBDIR)"
override LDLIBS  += -lnetstack -lcap -ldl -lpthread

# Source and header files
SRC = $(shell find $(SRCDIR) -type f -name '*.c')
LIB = $(shell find $(LIBDIR) -type f -name '*.c')
INC = $(shell find $(INCDIR) -type f -name '*.h')
OBJ = $(patsubst $(SRCDIR)%, $(OBJDIR)%, $(patsubst %.c, %.o, $(SRC)))

# Target declarations
TARGET_BIN = netd
TARGET_LIB = libnetstack.so
TARGET_LIB_PATH = $(LIBDIR)/libnetstack.so

PREFIX  = /usr/local
DESTDIR =

export PREFIX DESTDIR


.PHONY: default all build
default: all
all: build doc
build: $(TARGET_BIN)

# Compilation
$(TARGET_BIN): $(TARGET_LIB_PATH) $(OBJ)
	$(CC) $(LDFLAGS) $(OBJ) $(LDLIBS) -o $@

$(TARGET_LIB_PATH):
	make -C $(LIBDIR) $(TARGET_LIB)

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INC)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) -c $< -o $@

# Misc
.PHONY: test doc install uninstall clean

test:
	make -C $(LIBDIR) test

doc:
	@echo 'No documentation to build yet'

install: $(TARGET_BIN) $(TARGET_LIB_PATH)
	make -C $(LIBDIR) install
	install -Dm755 $(TARGET_BIN) $(DESTDIR)$(PREFIX)/bin/$(TARGET_BIN)

uninstall:
	make -C $(LIBDIR) uninstall
	$(RM) $(DESTDIR)/$(PREFIX)/bin/$(TARGET_BIN)

clean:
	make -C $(LIBDIR) clean
	$(RM) -r $(OBJDIR) $(TARGET_BIN)
