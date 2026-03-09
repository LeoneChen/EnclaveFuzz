FROM ubuntu:22.04

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

# Add kvm sgx sgx_prv to user
RUN groupadd --gid 108 kvm
RUN groupadd --gid 136 sgx
RUN groupadd --gid 1003 sgx_prv
RUN usermod -aG kvm $USERNAME
RUN usermod -aG sgx $USERNAME
RUN usermod -aG sgx_prv $USERNAME

########## USER ##########
USER $USERNAME
WORKDIR /home/$USERNAME

# zsh in docker
RUN sudo apt-get update

RUN sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y build-essential autoconf automake cmake make g++ flex bison lsb-release vim curl debhelper git protobuf-compiler wget fakeroot pkg-config python3 python3-pip reprepro unzip uuid-dev libcurl4 libssl-dev libtool libjsoncpp-dev liblog4cplus-dev libboost-all-dev libjsoncpp-dev libcurl4-openssl-dev libprotobuf-dev libssl-dev libelf-dev libncurses-dev libfdt-dev libncursesw5-dev libgtk-3-dev libspice-server-dev libssh-dev ninja-build tmux

RUN wget http://archive.ubuntu.com/ubuntu/pool/main/o/openssl/libssl1.1_1.1.1f-1ubuntu2_amd64.deb
RUN sudo dpkg -i libssl1.1_1.1.1f-1ubuntu2_amd64.deb

RUN sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.2.1/zsh-in-docker.sh)" -- \
    -t robbyrussell \
    -p git \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions
RUN sed -i '/export TERM=xterm/s/^/# /' /home/$USERNAME/.zshrc
RUN echo ". \$HOME/.profile" >> /home/$USERNAME/.zshrc

# Add proxy file
RUN cat <<EOF > /home/$USERNAME/proxy
#!/bin/bash
my_proxy="http://172.17.0.1:20171"
export all_proxy="\${my_proxy}"
export http_proxy="\${my_proxy}"
export https_proxy="\${my_proxy}"
export ftp_proxy="\${my_proxy}"
EOF
RUN cat <<EOF > /home/$USERNAME/noproxy
#!/bin/bash
unset all_proxy
unset http_proxy
unset https_proxy
unset ftp_proxy
EOF

# used by edger8r
RUN bash -c "sh <(curl -fsSL https://opam.ocaml.org/install.sh)" <<EOF

EOF
RUN opam init -y --disable-sandboxing
RUN opam switch create 4.14.1
RUN opam install -y dune ocaml-lsp-server odoc ocamlformat utop

# prepare ssh
COPY --chown=$USERNAME:$USERNAME .ssh/id_ed25519 /home/$USERNAME/.ssh/id_ed25519
COPY --chown=$USERNAME:$USERNAME .ssh/id_ed25519.pub /home/$USERNAME/.ssh/id_ed25519.pub
RUN echo "StrictHostKeyChecking no" >> /home/$USERNAME/.ssh/config
COPY --chown=$USERNAME:$USERNAME .zsh_history /home/$USERNAME/.zsh_history

RUN git clone git@github.com:LeoneChen/EnclaveFuzz.git -b Fuzzer1.0-dev

WORKDIR /home/$USERNAME/EnclaveFuzz
RUN git submodule update --init --recursive --depth 5 third_party/llvm-project
RUN git submodule update --init --recursive
RUN ./build_target.sh -t llvm-project -b
RUN ./build.sh -g --prepare-sdk --build-sdk
RUN ./build_target.sh -t intel-sgx-ssl -b -s -g
