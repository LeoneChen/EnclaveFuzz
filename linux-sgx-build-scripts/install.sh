#!/bin/bash
set -e

script_dir=$(realpath -s $(dirname $0))
linux_sgx_src_dir="$(realpath -s ${script_dir}/../linux-sgx)"

# install sgxsdk
sudo ${linux_sgx_src_dir}/linux/installer/bin/sgx_linux_x64_sdk_*.bin <<EOF
no
/opt/intel/
EOF

# install sgxpsw
sudo apt-get update
sudo apt-get install libsgx-launch* libsgx-urts* libsgx-epid* libsgx-quote-ex* -y