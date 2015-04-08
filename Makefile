CWD = $(shell pwd)
YARADIR = ${CWD}/vendor/yara-3.3.0
BUILDDIR = ${CWD}/out
OBJ = ${BUILDDIR}/lib/libyara.a

export PKG_CONFIG_PATH = ${BUILDDIR}/lib/pkgconfig

.PHONY: all install clean

all: ${OBJ}

${OBJ}:
	mkdir -p ${BUILDDIR}
	cd ${YARADIR} && ./bootstrap.sh
	cd ${YARADIR} && ./configure --without-crypto --prefix=${BUILDDIR}
	make -C ${YARADIR}
	make -C ${YARADIR} install

install: ${OBJ}
	go install

clean:
	-make -C ${YARADIR} clean
	-rm -r ${BUILDDIR}
