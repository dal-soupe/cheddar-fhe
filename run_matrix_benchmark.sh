#!/bin/bash
#SBATCH --job-name=ched-matmul-%j
#SBATCH --output=./tmp/slurm/ched-matmul.%j.out
#SBATCH --error=./tmp/slurm/ched-matmul.%j.err
#SBATCH --gpus=1
#SBATCH -p a01
#SBATCH --time=00:30:00

set -euo pipefail

# Change to your project directory first
cd /home/fit/qianxueh/WORK/alchem/germain/Fed-Acceleration

ROOT_DIR="./cheddar-fhe"
BUILD_DIR="./cheddar-fhe/build"
JOBS="${JOBS:-4}"
PARAM_JSON="${1:-all}"

# Debug: show current directory
echo "Current dir: $(pwd)"
ls -la "$ROOT_DIR/CMakeLists.txt"

set +u
source /etc/profile
set -u
module load gpu/v12.4.1

if [ ! -f "$BUILD_DIR/CMakeCache.txt" ]; then
  cmake -S "$ROOT_DIR" -B "$BUILD_DIR" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_UNITTEST=ON \
    -DENABLE_EXTENSION=ON
fi

cmake --build "$BUILD_DIR" --target basic_test -j"$JOBS"

FILTER="*EncryptedSquareMatrixHMult*"
if [ "$PARAM_JSON" != "all" ]; then
  PARAM_TAG="${PARAM_JSON//./_}"
  FILTER="*EncryptedSquareMatrixHMult*${PARAM_TAG}"
fi

echo "Running matrix multiplication correctness + timing test"
echo "Build dir   : $BUILD_DIR"
echo "GTest filter: $FILTER"

"$BUILD_DIR/unittest/basic_test" \
  --gtest_filter="$FILTER" \
  --gtest_color=yes
