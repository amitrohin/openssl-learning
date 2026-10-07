.SUFFIXES:

PROGS := encrypt decrypt digest hmac kdf rsa-encrypt rsa-decrypt
SRCS += foo.c

CFLAGS ?= -g -O0 -pipe
CXXFLAGS ?= $(CFLAGS)
CPPFLAGS ?= -I/usr/local/include
LDFLAGS ?= -L/usr/local/lib
LDLIBS ?= -lcrypto

OBJDIR ?= obj

# -MT $@
#    Set the name of the target in the generated dependency file.
#
# -MMD
#    Generate dependency information as a side-effect of compilation, not
#    instead of compilation. This version omits system headers from the
#    generated dependencies: if you prefer to preserve system headers as
#    prerequisites, use -MD.
#
# -MP
#    Adds a target for each prerequisite in the list, to avoid errors when
#    deleting files.
#
# -MF $(DEPDIR)/$*.d
#    Write the generated dependency file $(DEPDIR)/$*.d.
#
DEPSUFFIX := .deps
DEPFLAGS = -MT $@ -MMD -MP -MF $(basename $@)$(DEPSUFFIX)

DESTDIR ?= /usr/local
BINDIR ?= $(DESTDIR)/bin

INSTALL ?= install

define make =
$(strip
	$(eval .PHONY: all)
	$(eval all: $(PROGS))

	$(foreach p,$(PROGS),
		$(if $(SRCS.$p),,$(eval SRCS.$p := $(wildcard $p.c $p.cc)))
		$(eval SRCS.$p += $(SRCS))
		$(#info SRCS.$p = $(value SRCS.$p))

		$(eval OBJS.$p += $(addprefix $(OBJDIR)/$p.,$(addsuffix .o,$(SRCS.$p))))
		$(#info OBJS.$p = $(value OBJS.$p))
		$(eval OBJS += $(OBJS.$p))

		$(eval DEPS.$p += $(OBJS.$p:%.o=%$(DEPSUFFIX)))
		$(#info DEPS.$p = $(value DEPS.$p))
		$(eval DEPS += $(DEPS.$p))

		$(if $(CFLAGS.$p),,$(eval CFLAGS.$p = $$(CFLAGS)))
		$(if $(CXXFLAGS.$p),,$(eval CXXFLAGS.$p = $$(CXXFLAGS)))
		$(if $(CPPFLAGS.$p),,$(eval CPPFLAGS.$p = $$(CPPFLAGS)))
		$(if $(LDFLAGS.$p),,$(eval LDFLAGS.$p = $$(LDFLAGS)))
		$(if $(LDLIBS.$p),,$(eval LDLIBS.$p = $$(LDLIBS)))

		$(if $(CC.$p),,$(eval CC.$p = $(CC)))
		$(#info CC.$p = $(CC.$p))

		$(if $(CXX.$p),,$(eval CXX.$p = $(CXX)))
		$(#info CXX.$p = $(CXX.$p))

		$(if $(LD.$p),,
			$(if $(filter %.cc,$(SRCS.$p)),
				$(eval LD.$p = $$(CXX.$p))
			,
				$(eval LD.$p = $$(CC.$p))
			)
		)
		$(#info LD.$p = $(LD.$p))

		$(foreach s,$(SRCS.$p),
			$(if $(CFLAGS.$p.$s),,$(eval CFLAGS.$p.$s = $$(CFLAGS.$p)))
			$(if $(CXXFLAGS.$p.$s),,$(eval CXXFLAGS.$p.$s = $$(CXXFLAGS.$p)))
			$(if $(CPPFLAGS.$p.$s),,$(eval CPPFLAGS.$p.$s = $$(CPPFLAGS.$p)))
			$(if $(filter %.c,$s),
				$(if $(CC.$p.$s),,$(eval CC.$p.$s = $(CC.$p)))
				$(eval COMPILE.$p.$s = $$(CC.$p.$s) -c $$(CFLAGS.$p.$s))
			,
				$(if $(CXX.$p.$s),,$(eval CXX.$p.$s = $(CXX.$p)))
				$(eval COMPILE.$p.$s = $$(CXX.$p.$s) -c $$(CXXFLAGS.$p.$s))
			)
			$(eval COMPILE.$p.$s += $$(CPPFLAGS.$p.$s) $$(DEPFLAGS))
			$(#info COMPILE.$p.$s = $(value COMPILE.$p.$s))
			$(eval $(OBJDIR)/$p.$s.o: $s | $(OBJDIR); $$(COMPILE.$p.$s) $$< -o $$@)
		)
		$(eval $p: $(OBJS.$p); $$(LD.$p) $$(LDFLAGS.$p) $$^ $$(LDLIBS.$p) -o $$@)

		$(eval OBJS := $(sort $(OBJS)))
		$(eval DEPS := $(sort $(DEPS)))
		$(#Include the dependency files that exist. Use wildcard to avoid failing on non-existent files.)
		$(eval include $(wildcard $(DEPS)))

	)
	$(eval $(OBJDIR):; mkdir -p $$@)

	$(eval .PHONY: clean)
	$(eval clean:; @-for f in $$(OBJS) $$(DEPS) $$(PROGS); do unlink $$$$f 2>/dev/null && echo "unlink $$$$f"; done)
)
endef
$(call make)

.PHONY: install
#install: $(PROG); $(INSTALL) -m 755 $(PROG) $(BINDIR)/
