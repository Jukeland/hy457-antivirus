build:
	gcc -w -g -o antivirus antivirus.c list.c -lcrypto -lcurl -lrt -lm

run:
	./antivirus scan Target
	./antivirus inspect Target
	./antivirus monitor test
	./antivirus slice 156
	./antivirus unlock "(1, 313)" "(4, 2524)" "(9, 12009)"

slice:
	./antivirus slice 156
	./antivirus unlock "(1, 313)" "(4, 2524)" "(9, 12009)"

clean:
	rm -f antivirus