clang -dynamiclib preprocess.c -L/usr/local/opt/libpcap/lib -lpcap -o libpreprocess.so -D NO_EMPTY_PAYLOAD # -D ONLY_TRANSPORT_LAYER
python preprocess.py
