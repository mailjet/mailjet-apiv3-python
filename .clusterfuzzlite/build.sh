#!/bin/bash
set -euo pipefail

# 1. Install your project and dependencies
pip3 install --no-cache-dir .

# 2. Package each fuzzer file (matches fuzz_*.py or *_fuzzer.py)
while IFS= read -r -d '' fuzzer; do
  fuzzer_basename="$(basename -- "${fuzzer}" .py)"
  fuzzer_package="${fuzzer_basename}.pkg"

  # Bundle standalone executable using PyInstaller
  pyinstaller --distpath "${OUT}" --onefile --name "${fuzzer_package}" "${fuzzer}"

  # 3. Create execution wrapper script
  cat > "${OUT}/${fuzzer_basename}" <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
LD_PRELOAD=\$this_dir/sanitizer_with_fuzzer.so \\
ASAN_OPTIONS=\${ASAN_OPTIONS:-}:symbolize=1:external_symbolizer_path=\$this_dir/llvm-symbolizer:detect_leaks=0 \\
\$this_dir/${fuzzer_package} "\$@"
EOF

  chmod +x "${OUT}/${fuzzer_basename}"

  if [ -f "${SRC}/tests/fuzz/fuzzer.dict" ]; then
    cp "${SRC}/tests/fuzz/fuzzer.dict" "${OUT}/${fuzzer_basename}.dict"
  fi
done < <(find "${SRC}" \( -name 'fuzz_*.py' -o -name '*_fuzzer.py' \) -print0)
