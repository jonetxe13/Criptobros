#!/bin/bash

gcc -o decrypt decrypt.c tiny_aes/aes.c libaesni/libaes_lin64.so -lm
./decrypt 707269766174656b65796165736379706865726b7574786162616e6b00000000 28_29_30_31 6f776e656462796b7574786162616e6b -1 7acac984301516fa801fd624d5889330

# ownedbykutxabank en hex



