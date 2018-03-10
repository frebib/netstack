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
.PHONY: clean
clean:
	$(RM) -r $(OBJDIR) $(TARGET_LIB)
