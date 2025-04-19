# MtA using COT

The MtA using COT protocol is a technique used in secure multiparty computation—which basically means several parties work together to do math without sharing their secret numbers.

## Installation

To Compile and run firstly clone the trezor-firmware inside the source repository and compile the crypto/ folder by using the following commands 

```bash
git clone --recurse-submodules https://github.com/trezor/trezor-firmware.git
cd ./trezor-firmware/crypto
make 
```
After the compilation create a build directory from the source and run the cmake commands

```mkdir build
cd build
cmake ..
make
```


## Usage

Run the executive binary by the command

```
./MtA
```



## License

[MIT](https://choosealicense.com/licenses/mit/)
