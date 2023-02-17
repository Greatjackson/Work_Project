APP = axidma-net

# Add any other object files to this list below
APP_OBJS = axidma-net.o libaxidma.o util.o version.o crc.o file_trans_and_rcv.o md5sum.o pthread_own.o tcp_udp_lib.o 

all: build

build: $(APP)

$(APP): $(APP_OBJS)
	$(CC) -o $@ $(APP_OBJS) $(LDFLAGS) $(LDLIBS) -lpthread
clean:
	rm -f $(APP) *.o

