# ******************* #
#       TITLE         #
# ******************* #
NAME = ft_strace

# ******************* #
#       COMMANDS      #
# ******************* #
CC = cc

# ******************* #
#       FLAGS         #
# ******************* #

CFLAGS = -Wall -Wextra -Werror -Iincs

# ******************* #
#       SOURCES       #
# ******************* #
SRCS = srcs/main.c \
		srcs/signals.c \
		srcs/syscalls.c \
		srcs/utils.c \

SYS_TAB_H = syscall_table.h

# ******************* #
#       RULES         #
# ******************* #
OBJS = $(addprefix objs/,$(SRCS:.c=.o))
OBJ_DIRS = $(sort $(dir $(OBJS)))

objs/%.o : %.c | $(OBJ_DIRS)
	$(CC) -I. -c $(CFLAGS) $< -o $@


$(NAME) : $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $(NAME)

$(OBJ_DIRS):
	mkdir -p $@

all: $(NAME)

debug: CFLAGS += -g3
debug: $(NAME)

clean:
	rm -rf objs

fclean: clean
	rm -f $(NAME)

re: fclean all

# **************************************************************************** #
#       PHONY                                                                  #
# **************************************************************************** #
.PHONY: all clean fclean re test debug
