How it works

For Windows:
1. Run scripts/generate_keys.bat to generate public+private keys for sender and receiver

For Linux: 
1. Make a script for keys generation runnable: chmod +x scripts/generate_keys.sh 
2. Run scripts/generate_keys.sh to generate public+private keys for sender and receiver

----- ! FOR TEST PURPOSES ! -----

Generating temporary keys for windows / workng main() 

mkdir certs
cd certs
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 365 -subj "/CN=localhost"
