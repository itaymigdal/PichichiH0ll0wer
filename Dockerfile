FROM nimlang/nim:alpine

RUN apk add --no-cache mingw-w64-gcc upx zlib \
&& nimble install -y argparse winim ptr_math rc4 nimprotect zip

# docker build -t pichichi-dependencies .
# cd PichichiH0ll0wer
# docker run -it --rm -v ${pwd}:/PichichiH0ll0wer -w /PichichiH0ll0wer pichichi-dependencies
