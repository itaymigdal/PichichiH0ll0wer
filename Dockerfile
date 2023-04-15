FROM nimlang/nim:1.6.12-alpine

RUN apk add --no-cache mingw-w64-gcc upx \
&& nimble install -y argparse winim ptr_math rc4 nimprotect
