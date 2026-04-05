FROM ubuntu:20.04

########## ROOT ##########
ARG USERNAME=leone
ARG USER_UID=1001
ARG USER_GID=$USER_UID

RUN sed -i "s/archive.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/" /etc/apt/sources.list
RUN sed -i "s/security.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/" /etc/apt/sources.list
RUN apt-get update

# Create the user
RUN groupadd --gid $USER_GID $USERNAME
RUN useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

# Add sudo to user
RUN apt-get install -y sudo
RUN echo $USERNAME ALL=\(root\) NOPASSWD:ALL > /etc/sudoers.d/$USERNAME
RUN chmod 0440 /etc/sudoers.d/$USERNAME
RUN usermod -aG sudo $USERNAME

########## USER ##########
USER $USERNAME
WORKDIR /home/$USERNAME

# zsh in docker
RUN sudo apt-get install -y wget
RUN sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.2.1/zsh-in-docker.sh)" -- \
    -t robbyrussell \
    -p git \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions
RUN sed -i '/export TERM=xterm/s/^/# /' /home/$USERNAME/.zshrc

# Add proxy file
RUN cat <<EOF > /home/$USERNAME/proxy
#!/bin/bash
proxy_type="http"
proxy_ip="127.0.0.1"
proxy_port="20171"
export all_proxy="\${proxy_type}://\${proxy_ip}:\${proxy_port}"
export http_proxy="\${proxy_type}://\${proxy_ip}:\${proxy_port}"
export https_proxy="\${proxy_type}://\${proxy_ip}:\${proxy_port}"
export ftp_proxy="\${proxy_type}://\${proxy_ip}:\${proxy_port}"
EOF
RUN cat <<EOF > /home/$USERNAME/noproxy
#!/bin/bash
unset all_proxy
unset http_proxy
unset https_proxy
unset ftp_proxy
EOF

RUN sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential autoconf automake cmake make g++ flex bison lsb-release vim curl debhelper git protobuf-compiler wget fakeroot pkg-config python3 python3-pip reprepro unzip uuid-dev libcurl4 libssl1.1 libtool libjsoncpp-dev liblog4cplus-dev libboost-all-dev libjsoncpp-dev libcurl4-openssl-dev libprotobuf-dev libssl-dev libelf-dev libncurses-dev libfdt-dev libncursesw5-dev libgtk-3-dev libspice-server-dev libssh-dev

# used by edger8r
RUN bash -c "sh <(curl -fsSL https://opam.ocaml.org/install.sh)" <<EOF

EOF
RUN opam init -y --disable-sandboxing
RUN opam switch create 4.14.1
RUN opam install -y dune yojson ocaml-lsp-server odoc ocamlformat utop

# prepare ssh
COPY --chown=$USERNAME:$USERNAME .ssh/id_ed25519 /home/$USERNAME/.ssh/id_ed25519
COPY --chown=$USERNAME:$USERNAME .ssh/id_ed25519.pub /home/$USERNAME/.ssh/id_ed25519.pub
RUN echo "StrictHostKeyChecking no" >> /home/$USERNAME/.ssh/config

RUN git clone git@github.com:LeoneChen/EnclaveFuzz.git -b master

WORKDIR /home/$USERNAME/EnclaveFuzz
RUN git submodule update --init --recursive third_party/edger8r
RUN git submodule update --init --recursive third_party/intel-sgx-ssl
RUN git submodule update --init --recursive third_party/json
RUN git submodule update --init --recursive third_party/libFuzzer
RUN git submodule update --init --recursive --depth 5 third_party/llvm-project
RUN git submodule update --init --recursive sgx_apps/wasm-micro-runtime
RUN ./build_target.sh -t llvm-project -b
RUN ./build.sh -g --cov --prepare-sdk --build-sdk
RUN ./build_target.sh -t wasm-micro-runtime -b -s -g
