#!/bin/bash
set -euo pipefail

# 1. Install your project and dependencies
pip3 install --no-cache-dir --no-deps .

# 2. Package each fuzzer file in parallel across available CPU cores
build_fuzzer() {
  local fuzzer="$1"
  local fuzzer_basename fuzzer_package work_dir
  fuzzer_basename="$(basename -- "${fuzzer}" .py)"
  fuzzer_package="${fuzzer_basename}.pkg"
  work_dir="${WORK}/pyi-${fuzzer_basename}"
  mkdir -p -- "${work_dir}"

  # Bundle standalone executable using isolated work/spec paths for parallel safety
  pyinstaller --distpath "${OUT}" --workpath "${work_dir}" --specpath "${work_dir}" \
    --onefile --name "${fuzzer_package}" "${fuzzer}"

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
}

max_jobs="$(nproc 2>/dev/null || echo 4)"
declare -a pids=()
while IFS= read -r -d '' fuzzer; do
  build_fuzzer "${fuzzer}" &
  pids+=("$!")
  while [ "$(jobs -rp | wc -l)" -ge "${max_jobs}" ]; do
    sleep 0.2
  done
done < <(find "${SRC}" \( -name 'fuzz_*.py' -o -name '*_fuzzer.py' \) -print0)

build_rc=0
for pid in "${pids[@]}"; do
  if ! wait "${pid}"; then
    build_rc=1
  fi
done
exit "${build_rc}"
