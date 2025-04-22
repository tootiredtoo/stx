#!/bin/bash

set -e 

mkdir -p keys
cd keys

if [ -f "sender_private.pem" ]; then
    rm snd_private.pem snd_public.pem
fi

if [ -f "receiver_private.pem" ]; then
    rm receiver_private.pem receiver_public.pem
fi

openssl genpkey -algorithm RSA -out snd_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in snd_private.pem -pubout -out snd_public.pem

openssl genpkey -algorithm RSA -out rcv_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in rcv_private.pem -pubout -out rcv_public.pem

echo "RSA keys for sender and receiver were saved to keys/ folder"