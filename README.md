Bloom Filter Encryption library
===============================

This library implements bloom filter encryption (BFE) based on the paper [*Bloom Filter Encryption
and Applications to Efficient Forward-Secret 0-RTT Key Exchange*](https://eprint.iacr.org/2018/199)
by David Derler, Tibor Jager, Daniel Slamanig, and Christoph Striecks. It implements IND-CCA2-secure
BFE based on the Boneh-Franklin IBE.

Dependencies
------------

The BFE library requires the following dependencies:
* [relic](https://github.com/relic-toolkit/relic)
* [doxygen](http://www.doxygen.nl/index.html) (optional, for documentation)
* [cgreen](https://github.com/cgreen-devs/cgreen) (optional, for tests)

Building
--------

First configure the build with `cmake` and then run `make`:
```sh
mkdir build
cd build
cmake ..
make
```

License
-------

The code is licensed under the CC0 license and was written by Sebastian Ramacher (AIT Austrian
Institute of Technolgy) as part of [IoT4CPS](https://iot4cps.at). The IoT4CPS project is partially
funded by the "ICT of the Future" Program of the FFG and the BMVIT.

The SHAKE implementation is taken from [eXtended Keccak Code Package](https://github.com/XKCP/XKCP)
which is also available under the CC0 license.
