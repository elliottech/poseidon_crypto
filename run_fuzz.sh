#!/usr/bin/env bash
#
# Differential fuzz runner for the two Schnorr verifiers
# (IsSchnorrSignatureValid vs IsSchnorrSignatureValid2).
#
# Configure how many iterations to run via -n / $N. A rolling checksum is
# written to $OUT every 100000 iterations (see fuzz_schnorr.go). The process
# exits non-zero the moment the two implementations disagree.
#
# Examples:
#   ./run_fuzz_schnorr.sh                 # 1,000,000 iterations, seed 1
#   ./run_fuzz_schnorr.sh -n 100000000    # 100M iterations
#   N=50000000 SEED=7 ./run_fuzz_schnorr.sh
#
set -euo pipefail
 
# Defaults (overridable via env or flags below).
N="${N:-1000000}"
SEED="${SEED:3737}"
OUT="${OUT:-schnorr_fuzz_checksums.txt}"
 
while [[ $# -gt 0 ]]; do
  case "$1" in
    -n)    N="$2";    shift 2 ;;
    -seed) SEED="$2"; shift 2 ;;
    -out)  OUT="$2";  shift 2 ;;
    -h|--help)
      echo "usage: $0 [-n iterations] [-seed seed] [-out file]"
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 1
      ;;
  esac
done
 
cd "$(dirname "$0")"
 
echo "building fuzz_schnorr..."
go build -o /tmp/fuzz_schnorr ./fuzz_schnorr.go
 
echo "running: n=${N} seed=${SEED} out=${OUT}"
exec /tmp/fuzz_schnorr -n "${N}" -seed "${SEED}" -out "${OUT}"
 