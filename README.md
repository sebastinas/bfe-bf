Bloom Filter Encryption from Boneh-Franklin IBE
===============================================

This library implements bloom filter encryption (BFE) based on the paper [*Bloom Filter Encryption
and Applications to Efficient Forward-Secret 0-RTT Key Exchange*](https://eprint.iacr.org/2018/199)
by David Derler, Tibor Jager, Daniel Slamanig, and Christoph Striecks. It implements IND-CCA2-secure
BFE based on the Boneh-Franklin IBE.

Dependencies
------------

The BFE library requires the following dependencies:
* [relic](https://github.com/relic-toolkit/relic)
* [libsodium](https://libsodium.gitbook.io/doc/)
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
Institute of Technolgy) and Erkan Tairi while at AIT. This work has been partially funded by the
"ICT of the Future" Program of the FFG and the BMVIT as part of [IoT4CPS](https://iot4cps.at) and by
the EU projects [SECREDAS](https://secredas-project.eu/), [COMP4DRONES](https://www.comp4drones.eu),
[LABYRINTH](https://labyrinth2020.eu/). This project has received funding from the European Union’s
Horizon 2020 research and innovation programme under grant agreement No 783119, 826610, and 861696.

The SHAKE implementation is taken from [eXtended Keccak Code Package](https://github.com/XKCP/XKCP)
which is also available under the CC0 license.
