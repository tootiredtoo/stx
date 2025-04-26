On Linux/macOS: 
1. Make generate_keys.sh script executable and run it: 
chmod +x scripts/generate_keys.sh && scripts/generate_keys.sh
2. Make generate_data.sh script executable and run it: 
chmod +x scripts/generate_data.sh && scripts/generate_data.sh

On Windows: 
1. Run the generate_keys.bat script:
scripts/generate_keys.bat
2. Run the generate_data.bat script:
scripts/generate_data.bat

----- ! FOR TEST PURPOSES ! -----

For running stx-server:

On Linux/macOS: 
1. Make generate_debug_keys.sh script executable and run it: 
chmod +x scripts/generate_debug_keys.sh && scripts/generate_debug_keys.sh
2. Build and run application:

On Windows: 
1. Run the generate_debug_keys.bat script:
scripts/generate_debug_keys.bat
2. Build and run application:
mkdir build && cd build && cmake .. && make && build/stx-server.exe
3. In the different terminal run the client:
openssl s_client -connect 127.0.0.1:443 -CAfile certs/server.crt
4. In the client's terminal write someting (optionally) and press Enter. 