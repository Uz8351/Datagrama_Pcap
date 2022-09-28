CC          = gcc
CFLAGS		= -c -Wall -Werror
LDFLAGS		= -lpcap
SOURCES		= datagrama.c
INCLUDES	= -I.
OBJECTS		= $(SOURCES:.c=.o)
TARGET		= datagrama

all: $(SOURCES) $(TARGET)

$(TARGET): $(OBJECTS) 
	$(CC) $(OBJECTS) $(LDFLAGS) -o $@  

.c.o:
	$(CC) $(CFLAGS) $(INCLUDES) $< -o $@

clean:
	rm -rf $(OBJECTS) $(TARGET)
