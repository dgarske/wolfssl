# Emscripten based Javascript wrapper for wolfCrypt


## Installing

### Dependencies

  * cmake
  * xutils-dev
  * npm install uglify-js -g
  * npm install -g jsesc
  * sed (on Mac brew install gnu-sed `gsed`)

```
sudo apt install cmake xutils-dev
make init_emcc
```

## Building

To build the node tester and code for index.html:

```
make emsdk-portable64
source emsdk-portable/emsdk_env.sh 

emmake make clean
emmake make wolfssl
emmake make wcjs.js
emmake make wcjsgen
emmake make wrapper
emmake make tester
```



Other useful commands

```
./emsdk install latest
./emsdk activate latest

emmake make wolfssl
emmake make wcjs
emmake make wrapper
emmake make tester
emmake make libscheck

emmake make -C wcjs
emmake make -C ../..
emmake make -C ../.. install
rm ./wcjs/wcjs.js 

uglifyjs ./wcjs/wcjs.js --output ./wcjs/wcjs_s.js
uglifyjs ./wcjs/wcjs.asm.js --output ./wcjs/wcjs_s.asm.js
cat ./wcjs/wcjs_s.asm.js | jsesc --double-quotes --wrap > ./wcjs/wcjs_s.asm.js.txt
base64 --wrap=0 ./wcjs/wcjs.js.mem > ./wcjs/wcjs.js.mem.base64
```
