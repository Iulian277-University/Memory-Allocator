#!/bin/bash

cd ../allocator
make clean && make -j
cd ../tests
make clean && make -j
python3 checker.py
