#!/bin/bash -eu

# 1. Install your project and dependencies
pip3 install .

# 2. Package each fuzzer file (matches fuzz_*.py or *_fuzzer.py)
for fuzzer in $(find $SRC -name 'fuzz_*.py' -o -name '*_fuzzer.py'); do
  fuzzer_basename=$(basename -s .py $fuzzer)
  fuzzer_package=${fuzzer_basename}.pkg

  # Bundle standalone executable using PyInstaller
  pyinstaller --distpath $OUT --onefile --name $fuzzer_package $fuzzer

  # 3. Create execution wrapper script
  echo "#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname \"\$0\")
LD_PRELOAD=\$this_dir/sanitizer_with_fuzzer.so \\
ASAN_OPTIONS=\$ASAN_OPTIONS:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \\
\$this_dir/$fuzzer_package \"\$@\"" > $OUT/$fuzzer_basename

  chmod +x $OUT/$fuzzer_basename
done
