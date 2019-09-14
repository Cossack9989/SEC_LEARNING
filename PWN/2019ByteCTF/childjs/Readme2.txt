If you want to build it by yourself, plz follow these instructs21s
```
git clone https://github.com/Microsoft/ChakraCore
cd ChakraCore
git reset --hard 8fcb0f1
patch -p1 < ../diff.patch
cd ChakraCore && ./build.sh
```
Send `EOF` at last to execute your script