@echo off
set local

mkdir keys
cd keys

if exist sender_private.pem (
    del sender_private.pem
    del sender_public.pem
)

if exist receiver_private.pem (
    del receiver_private.pem
    del receiver_public.pem
)

openssl genpkey -algorithm RSA -out snd_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in snd_private.pem -pubout -out snd_public.pem

openssl genpkey -algorithm RSA -out rcv_private.pem -pkeyopt rsa_keygen_bits:2048
openssl rsa -in rcv_private.pem -pubout -out rcv_public.pem

echo RSA keys for sender and receiver were saved to keys/ folder
