
# 1) Make instrumented
python3 tools/make_instrumented.py \
  --source  CWE190_Integer_Overflow__int_fscanf_multiply_01/source.c \
  --main    CWE190_Integer_Overflow__int_fscanf_multiply_01/main_single.c \
  --adapter CWE190_Integer_Overflow__int_fscanf_multiply_01/adapter.c \
  --out     CWE190_Integer_Overflow__int_fscanf_multiply_01 \
  --stem    CWE190_Integer_Overflow__int_fscanf_multiply_01

# 2) Make driver
python3 tools/make_driver.py \
  --stem CWE190_Integer_Overflow__int_fscanf_multiply_01 \
  --instrumented CWE190_Integer_Overflow__int_fscanf_multiply_01 \
  --out CWE190_Integer_Overflow__int_fscanf_multiply_01 \
  --sym-int data size count 

# 3) Build one TU
clang -I$KLEE_INCLUDE_DIR -DUSE_KLEE_SOURCE -emit-llvm \
  -c -g -O0 -Xclang -disable-O0-optnone driver_CWE190_Integer_Overflow__int_fscanf_multiply_01.c -o driver.bc
klee driver.bc

# 4) Process output
python3 tools/klee_to_chainjson.py \
  --klee-dir CWE190_Integer_Overflow__int_fscanf_multiply_01/klee-last \
  --step CWE190_Integer_Overflow__int_fscanf_multiply_01 \
  --vars data \
  --main CWE190_Integer_Overflow__int_fscanf_multiply_01/main_single.c \
  --source CWE190_Integer_Overflow__int_fscanf_multiply_01/instrumented_CWE190_Integer_Overflow__int_fscanf_multiply_01.c \
  --type INT_OVERFLOW \
  --cwe 190 \
  --target "int result = data * 2;" \
  --assumption "data > 0" \
  --out stase_output/CWE190_Integer_Overflow__int_fscanf_multiply_01_witness.json


