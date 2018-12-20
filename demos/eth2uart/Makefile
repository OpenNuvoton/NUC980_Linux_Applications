.SUFFIXES : .x .o .c .s

DD = 1
CC := arm-linux-gcc
STRIP := arm-linux-strip

TARGET = eth2uart
SRCS := eth2uart.c
LIBS = -lpthread -lc -lgcc

all:
ifeq ($(DD),1)
	$(CC) -static $(SRCS) -o $(TARGET) $(LIBS)
	$(STRIP) $(TARGET)
else
	@echo ' ROOTFS COPY PATH = $(DD) '
	$(CC) -static $(SRCS) -o $(TARGET) $(LIBS)
	$(STRIP) $(TARGET)
	cp eth2uart.c $(DD)

endif
clean:
	rm -f *.o
	rm -f *.x
	rm -f *.flat
	rm -f *.map
	rm -f temp
	rm -f *.img
	rm -f $(TARGET)
	rm -f *.gdb
