CWD = $(shell pwd)
YARADIR = ${CWD}/vendor/yara-master
BUILDDIR = ${CWD}/out
OBJ = ${BUILDDIR}/lib/libyara.a
CGOFLAGS = -ldflags='-extldflags "-static"'

export PKG_CONFIG_PATH = ${BUILDDIR}/lib/pkgconfig

.PHONY: all install test clean

all: ${OBJ}

${OBJ}:
	mkdir -p ${BUILDDIR}
	cd ${YARADIR} && ./bootstrap.sh
	cd ${YARADIR} && ./configure --disable-cuckoo --disable-magic --without-crypto --prefix=${BUILDDIR}
	make -C ${YARADIR}
	make -C ${YARADIR} install

install: ${OBJ}
	go install -a

test: ${OBJ}
	go test

clean:
	-make -C ${YARADIR} clean
	-rm -r ${BUILDDIR}
