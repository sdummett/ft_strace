# **************************************************************************** #
#       TITLE                                                                  #
# **************************************************************************** #
NAME = ft_strace

# **************************************************************************** #
#       COMMANDS                                                               #
# **************************************************************************** #
CC = cc

# **************************************************************************** #
#       FLAGS                                                                  #
# **************************************************************************** #

CFLAGS = -Wall -Wextra -Werror

# **************************************************************************** #
#       SOURCES                                                                #
# **************************************************************************** #
SRCS = srcs/main.c \

SYS_TAB_H = syscall_table.h

# **************************************************************************** #
#       RULES                                                                  #
# **************************************************************************** #
OBJS = $(addprefix objs/,$(SRCS:.c=.o))
OBJ_DIRS = $(sort $(dir $(OBJS)))

objs/%.o : %.c | $(OBJ_DIRS)
	$(CC) -I. -c $(CFLAGS) $< -o $@


$(NAME) : ${SYS_TAB_H} $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME)

$(OBJ_DIRS):
	mkdir -p $@

all: $(NAME)

# Generate a fresh systable if a new syscall is added to the kernel
# generate_syscall_table: syscall_table.h
generate_syscall_table: $(SYS_TAB_H)
$(SYS_TAB_H):
	@echo "[+] Generating syscall_table.h"
	@echo -e "#ifndef SYSCALL_TABLE_H" > $(SYS_TAB_H)
	@echo -e "#define SYSCALL_TABLE_H\n" >> $(SYS_TAB_H)
	@echo -e "const char *syscall_names[] = {\n" >> $(SYS_TAB_H)
	@ausyscall --dump | awk 'NR > 1 { printf "\t[%s] = \"%s\",\n", toupper($$1), $$2 }' >> $(SYS_TAB_H)
	@echo -e "};\n" >> $(SYS_TAB_H)
	@echo "#endif //SYSCALL_TABLE_H" >> $(SYS_TAB_H)

test:
	./unit-tests.sh

# debug: CFLAGS += -g3 -DDEBUG
# debug: $(NAME)

clean:
	rm -rf objs

fclean: clean
	rm -f $(SYS_TAB_H)
	rm -f $(NAME)

re: fclean all

# **************************************************************************** #
#       PHONY                                                                  #
# **************************************************************************** #
.PHONY: all clean fclean re test debug
