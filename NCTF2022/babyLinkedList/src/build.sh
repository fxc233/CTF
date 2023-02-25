#!/bin/bash

set -ex

if ! hash patchelf 2>/dev/null;
then
    echo "Exception: patchelf not installed"
    exit 1
fi

OLD_PWD="${PWD}"
MUSL_DIR="${OLD_PWD}/musl-1.2.2"
RELEASE_DIR="${OLD_PWD}/Release"
DEBUG_DIR="${OLD_PWD}/Debug"

mkdir -p ${RELEASE_DIR} ${DEBUG_DIR}

tar -xvf musl-1.2.2.tar.gz

cd ${MUSL_DIR}
mkdir -p build
./configure --enable-debug --prefix="${MUSL_DIR}/build" --syslibdir="${MUSL_DIR}/build/lib"
make -j$(nproc)
make install

cd ${DEBUG_DIR}
cp "${MUSL_DIR}/build/lib/libc.so" .
${MUSL_DIR}/build/bin/musl-gcc "${OLD_PWD}/babyLinkedList.c" -o babyLinkedList
patchelf --set-interpreter libc.so babyLinkedList

cd ${RELEASE_DIR}
strip "${DEBUG_DIR}/babyLinkedList" -o babyLinkedList
strip "${DEBUG_DIR}/libc.so" -o libc.so

echo "Done."
