#!/bin/bash

passes=("bogus-control-flow" "flattening" "mba-obfuscation" "substitution" "indirect-call" "global-encryption")
mkdir -p dump/pluto

for pass in "${passes[@]}"; do
    pass_dir="${pass/pluto-/}"
    mkdir -p "dump/pluto/$pass_dir"
done

clang main.c -o dump/main
clang -c -S -emit-llvm -O1 main.c -o dump/pluto/main.ll

# I recommend using llvm 16, because 17 and 18 used to segfault a lot
for pass in "${passes[@]}"; do
    pass_dir="${pass/pluto-/}"
        
    echo "Running pass: pluto-$pass"
    opt -load-pass-plugin=./lib/libpasses-"$(llvm-config --version | cut -d'.' -f1)".so -passes "pluto-$pass" dump/pluto/main.ll -S -o "dump/pluto/$pass_dir/$pass_dir.ll" -debug-pass-manager

    if [ $? -ne 0 ]; then
        echo "Error running pass: pluto-$pass"
        exit 1
    fi
done

for pass in "${passes[@]}"; do
    pass_dir="${pass/pluto-/}"
    ll_file="dump/pluto/$pass_dir/$pass_dir.ll"
    output_file="dump/pluto/$pass_dir/$pass_dir"
    
    echo "Compiling $ll_file to $output_file"
    clang "$ll_file" -o "$output_file"
    
    if [ $? -ne 0 ]; then
        echo "Error compiling $ll_file"
        exit 1
    fi
done

mkdir -p dump/pluto/example

# Hardcoded pass
opt -load-pass-plugin=./lib/libpasses-"$(llvm-config --version | cut -d'.' -f1)".so -passes "example-pass" dump/pluto/main.ll -S -o "dump/pluto/example/example.ll" -debug-pass-manager

if [ $? -ne 0 ]; then
    echo "Error running pass: example-pass"
    exit 1
fi

ll_file="dump/pluto/example/example.ll"
output_file="dump/pluto/example/example"

echo "Compiling $ll_file to $output_file"
clang "$ll_file" -o "$output_file"

if [ $? -ne 0 ]; then
    echo "Error compiling $ll_file"
    exit 1
fi

echo "All pluto passes ran successfully"

mkdir -p dump/tigress
mkdir -p dump/tigress/mba dump/tigress/opaquePredicate dump/tigress/flattening dump/tigress/bogus

tigress \
  --Environment=x86_64:Linux:Gcc:"$(gcc --version | grep -oP '\d+\.\d+\.\d+')" \
   --Transform=InitOpaque \
   --Functions=* \
   main.c \
   --out=dump/tigress/opaquePredicate/initOpaque.c

tigress \
  --Environment=x86_64:Linux:Gcc:"$(gcc --version | grep -oP '\d+\.\d+\.\d+')" \
  --Transform=EncodeArithmetic \
  --Functions=* \
  --EncodeArithmeticKinds=* \
  main.c \
  --out=dump/tigress/mba/mba.c

tigress \
  --Environment=x86_64:Linux:Gcc:"$(gcc --version | grep -oP '\d+\.\d+\.\d+')" \
  --Transform=Flatten \
  --Functions=* \
  --FlattenSplitBasicBlocks=true \
  --FlattenRandomizeBlocks=true \
  main.c \
  --out=dump/tigress/flattening/flattening.c

tigress \
  --Environment=x86_64:Linux:Gcc:"$(gcc --version | grep -oP '\d+\.\d+\.\d+')" \
  --Transform=Flatten \
  --Functions=* \
  --AntiAliasAnalysisObfuscateIndex=true \
  --AntiAliasAnalysisBogusEntries=true \
    main.c \
  --out=dump/tigress/bogus/antiAliasAnalysis.c

# Add missing declarations to the generated files to compile them
for file in dump/tigress/*/*.c; do
  first_fclose_usage='extern FILE \*tmpfile(void)  __attribute__((__malloc__(fclose,1), __malloc__)) ;'
  
  if grep -q "$first_fclose_usage" "$file"; then
    sed -i "/$first_fclose_usage/ i\extern int fclose (FILE *__stream);\nextern void *reallocarray(void *ptr, size_t nmemb, size_t size);" "$file"
  fi
done

gcc dump/tigress/opaquePredicate/initOpaque.c -o dump/tigress/opaquePredicate/initOpaque
gcc dump/tigress/mba/mba.c -o dump/tigress/mba/mba
gcc dump/tigress/flattening/flattening.c -o dump/tigress/flattening/flattening
gcc dump/tigress/bogus/antiAliasAnalysis.c -o dump/tigress/bogus/antiAliasAnalysis

echo "All tigress passes ran successfully"