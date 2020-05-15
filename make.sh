rm -rf xsan/build
rm -rf xasan/build
rm -rf gasan/build
rm -rf llvm_instr/build
rm -rf finj/build
mkdir xsan/build
mkdir xasan/build
mkdir gasan/build
mkdir llvm_instr/build
mkdir finj/build
cd xsan/build && cmake .. && make
cd /root/xsan
cd xasan/build && cmake .. && make
cd /root/xsan
cd gasan/build && cmake .. && make
cd /root/xsan
cd llvm_instr/build && cmake .. && make
cd /root/xsan
cd finj/build && cmake .. && make
cd /root/xsan

rm -rf bin
mkdir bin
clang tools/cov.c -o bin/cov
clang tools/reset.c -o bin/reset
clang tools/error_report.c -o bin/error_report
clang tools/get_fault_site.c -o bin/get_fault_site
clang tools/reset_fault.c -o bin/reset_fault
clang tools/set_fault.c -o bin/set_fault
clang tools/test.c -o bin/test
clang tools/trigger.c -o bin/trigger

cp bin/* /root/
