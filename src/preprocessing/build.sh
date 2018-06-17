clang -dynamiclib preprocess.c -L/usr/local/opt/libpcap/lib -lpcap -o libpreprocess.so -D NO_EMPTY_PAYLOAD
python preprocess.py
