NAME=zpscan
BUILDPATH=main.go
BINDIR=bin
VERSION=$(shell git describe --tags || echo "unknown version")
GOBUILD=CGO_ENABLED=1 CGO_LDFLAGS="-Wl,-static -L/usr/lib/x86_64-linux-gnu/libpcap.a -lpcap -Wl,-Bdynamic" go build -trimpath -ldflags '-w -s'

docker:
	$(GOBUILD) -o $(BINDIR)/$(NAME)-$@ $(BUILDPATH)

sha256sum:
	cd $(BINDIR); for file in *; do sha256sum $$file > $$file.sha256; done

clean:
	rm $(BINDIR)/*