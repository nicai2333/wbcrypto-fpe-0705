# Use "sudo bash build.sh"
mkdir build && cd build && cmake .. && make -j4 && cd test && ./fpe_test && ./fpe_app_speed_test

#Refresh
# cd build && make clean && make -j4 



