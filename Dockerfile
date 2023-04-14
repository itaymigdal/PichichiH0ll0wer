FROM nimlang/nim:1.6.12-alpine

RUN apk add --no-cache python3 py3-pip mingw-w64-gcc upx \
&& pip3 install ... \
&& nimble install -y winim ptr_math rc4 https://github.com/itaymigdal/NimProtect