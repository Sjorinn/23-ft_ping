NAME 	= ft_ping
SRCS 	= main.c
OBJ 	= $(SRCS:.c=.o)
FLAGS 	= -Wall -Wextra -Werror
LIBS	= -lm

all: $(NAME)

$(NAME):
	@gcc -o $(NAME) $(SRCS) $(FLAGS) $(LIBS)

clean: 
	@rm -f $(OBJ)

fclean: clean
	@rm -f $(NAME)

re: fclean $(NAME)

.PHONY: all clean fclean re