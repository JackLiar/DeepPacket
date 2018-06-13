clang -dynamiclib preprocess.c  -lpcap -o libpreprocess.so -D NO_EMPTY_PAYLOAD
python preprocess.py
