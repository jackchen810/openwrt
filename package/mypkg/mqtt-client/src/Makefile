# build mqtt-client executable when user executes "make"
LIBS += -lmosquitto
LIBS += -ljson-c
LIBS += -lpthread
LIBS += -luci
LIBS += -lcurl
# LIBS += -lutils

objects := $(patsubst %.c,%.o,$(wildcard *.c))
mqtt-client: $(objects)
	echo $(CC)
	echo $(LDFLAGs)
	$(CC) -g $(LDFLAGS) $(LIBS) $^ -o $@

# remove object files and executable when user executes "make clean"
clean:
	rm *.o mqtt-client
