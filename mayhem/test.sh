#!/usr/bin/env bash
#
# pydicom/mayhem/test.sh — behavioral oracle for pydicom/pydicom.
#
# It RUNS the real reader (via the /mayhem/run-cli launcher built by mayhem/build.sh) over the
# bundled CT_small.dcm test fixture and ASSERTS the decoded element values (known-answer test):
# PatientName, Modality, image dimensions, transfer syntax, etc. This exercises the SAME pipeline
# the fuzzer drives — file read -> DICOM parse -> element value decode — so a no-op/neutered program
# (no output, or wrong output) FAILS here. It never builds; it only runs the pre-built launcher.
#
# Anti-reward-hack note: run-cli lives at /mayhem (a NON-system path), so the verify-repo sabotage
# neuter (_exit(0) on non-system exes) trips it -> empty output -> assertions fail -> detected.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${SRC:=/mayhem}"
cd "$SRC"

CLI="$SRC/run-cli"
DCM="$SRC/src/pydicom/data/test_files/CT_small.dcm"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

PASS=0; FAIL=0
check() { # check <name> <condition-rc>
  if [ "$2" -eq 0 ]; then echo "PASS: $1"; PASS=$((PASS+1)); else echo "FAIL: $1"; FAIL=$((FAIL+1)); fi
}

if [ ! -x "$CLI" ]; then
  echo "missing $CLI — run mayhem/build.sh first" >&2
  emit_ctrf "pydicom-knownanswer" 0 1 0; exit 2
fi
if [ ! -f "$DCM" ]; then
  echo "missing $DCM" >&2
  emit_ctrf "pydicom-knownanswer" 0 1 0; exit 2
fi

echo "=== reading CT_small.dcm (element dump to stdout) ==="
OUT="$("$CLI" "$DCM" 2>/dev/null)"
echo "$OUT"

# Known answers for the bundled CT_small.dcm fixture.
grep -q '^PatientName=CompressedSamples\^CT1$'      <<<"$OUT"; check "PatientName decoded" $?
grep -q '^PatientID=1CT1$'                          <<<"$OUT"; check "PatientID decoded" $?
grep -q '^Modality=CT$'                             <<<"$OUT"; check "Modality decoded" $?
grep -q '^Rows=128$'                                <<<"$OUT"; check "Rows decoded" $?
grep -q '^Columns=128$'                             <<<"$OUT"; check "Columns decoded" $?
grep -q '^StudyDate=20040119$'                      <<<"$OUT"; check "StudyDate decoded" $?
grep -q '^Manufacturer=GE MEDICAL SYSTEMS$'         <<<"$OUT"; check "Manufacturer decoded" $?
grep -q '^SOPClassUID=1.2.840.10008.5.1.4.1.1.2$'   <<<"$OUT"; check "SOPClassUID decoded" $?
grep -q '^TransferSyntaxUID=1.2.840.10008.1.2.1$'   <<<"$OUT"; check "TransferSyntaxUID (Explicit VR LE) decoded" $?

emit_ctrf "pydicom-knownanswer" "$PASS" "$FAIL" 0
