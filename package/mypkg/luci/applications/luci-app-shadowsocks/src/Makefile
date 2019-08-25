%.o: %.c
		$(CC) $(CPPFLAGS) $(CFLAGS) $(FPIC) -c -o $@ $<

clean:
		rm -f luci-base64 *.o

luci-base64: luci-base64.o
		$(CC) $(LDFLAGS) -o $@ $^ -ldl

compile: luci-base64

install: compile
		mkdir -p $(DESTDIR)/usr/bin
		cp luci-base64 $(DESTDIR)/usr/bin/luci-base64

