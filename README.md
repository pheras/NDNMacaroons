# NDNMacaroons
===============

Installation instructions
-------------------------

### Prerequisites

This implementation has been tested in Ubuntu 14.04.

Required:

* [ndn-cxx and its dependencies](http://named-data.net/doc/ndn-cxx/)
* Boost libraries
* libmacaroons: https://github.com/rescrv/libmacaroons (cython)
* [protobuf] (https://github.com/google/protobuf)


### Build

To build `NDNMacaroons` library run the following commands from 
`NDNMacaroons/` folder:

    cd libNDNMacaroon
    ./waf configure
    ./waf
    sudo ./waf install
    sudo ldconfig
  
To build `NDNMacaroons` examples run the following commands from 
`NDNMacaroons/` folder:

    ./waf configure
    ./waf


### Run the example

There are 4 principals:
   - *Producer*: produces data and provides a macaroon to access data.
   - *Consumer1*: gets macaroon from Producer and provides attenuated macaroon to other consumer: Consumer2.
   - *Consumer2*: gets attenuated macaroon from Consumer1, it contains a Third Party Caveat. 
                Gets discharge macaroon from Third Party and sends macaroon and discharge macaroon to Producer in order to access data.
   - *Third Party*: provides discharge macaroon to principals.
   
First time you want to test the NDNmacaroons example, you shoukd create DSK/KSK keys. It is only required the first time. Keys will be added to the keyChain. To create DSK/KSK keys execute the following script from `NDNMacaroons/` folder:

    ./createKeys.sh

Run each principal, each one in a different terminal, from `NDNMacaroons/` folder:

    1) Producer:                  ./build/bin/producer/producer
    2) Third Party Authenticator: ./build/bin/third-party/third-party
    3) Consumer1:                 ./build/bin/consumer1/consumer1
    4) Consumer2:                 ./build/bin/consumer2/consumer2

   
   
