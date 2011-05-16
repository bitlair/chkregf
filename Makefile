CC := gcc

# Enable for debug
CFLAGS := -g -ggdb -Wall -Wshadow -Wpointer-arith -Wcast-align -Wwrite-strings -Wdeclaration-after-statement -Werror-implicit-function-declaration -Werror -Wstrict-prototypes

INCLUDES := -I.

chkregf_LIB := -ltalloc
chkregf_OBJ := chkregf.o blockcheck.o treecheck.o

OBJ := $(chkregf_OBJ)

binaries := chkregf

all:	$(binaries)

clean:
	rm -f $(binaries)
	rm -f $(OBJ)
	rm -f $(OBJ:.o=.d)

distclean: clean
	rm -f tags

%.o: %.c
	@echo Compiling $*.c
	@$(CC) -c $(CFLAGS) $(INCLUDES) -o $*.o $<
	@$(CC) -MM $(CFLAGS) -MT $*.o $(INCLUDES) -o $*.d $<

chkregf: $(chkregf_OBJ)
	@echo Linking chkregf
	@$(CC) $(chkregf_OBJ) $(chkregf_LIB) -o chkregf

ctags:
	ctags `find -name \*.[ch]`

-include $(OBJ:.o=.d)
