.SUFFIXES : .x .o .c .s

CC := arm-linux-gcc
STRIP := arm-linux-strip

TARGET = cap2bmp
SRCS := cap2bmp.c
LIBS= -lc -lgcc -lc -lpthread

all: 
	$(CC) -static $(SRCS) -o $(TARGET)
	$(STRIP) $(TARGET) 
	cp cap2bmp ../../../rootfs/
clean:
	rm -f *.o 
	rm -f *.x 
	rm -f *.flat
	rm -f *.map
	rm -f temp
	rm -f *.img
	rm -f $(TARGET)	
	rm -f *.gdb
	rm -f *.bak
