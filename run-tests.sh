#!/bin/bash

set -e

cmake -E remove_directory build
cmake -E make_directory build
cd build
cmake .. -DENABLE_TESTS=ON -DENABLE_DOCS=OFF -DENABLE_OSCORE=OFF -DENABLE_OSCORE_NG=ON
cmake --build .
sudo cmake --build . -- install
./testdriver
cd ..
