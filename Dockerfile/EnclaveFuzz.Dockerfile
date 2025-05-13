FROM ubuntu:20.04

########## ROOT ##########
ARG USERNAME=admin
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
RUN sh -c "$(wget -O- https://github.com/deluan/zsh-in-docker/releases/download/v1.2.0/zsh-in-docker.sh)" -- \
    -t robbyrussell \
    -p git \
    -p https://github.com/zsh-users/zsh-autosuggestions \
    -p https://github.com/zsh-users/zsh-completions
RUN sed -i '/export TERM=xterm/s/^/# /' /home/$USERNAME/.zshrc

RUN wget -qO- https://apt.llvm.org/llvm-snapshot.gpg.key | sudo tee /etc/apt/trusted.gpg.d/apt.llvm.org.asc
RUN echo "deb http://apt.llvm.org/focal/ llvm-toolchain-focal-13 main" > /tmp/llvm.list
RUN echo "deb-src http://apt.llvm.org/focal/ llvm-toolchain-focal-13 main" >> /tmp/llvm.list
RUN sudo mv /tmp/llvm.list /etc/apt/sources.list.d/llvm.list
RUN sudo apt update
RUN sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y clang-13 llvm-13 lld-13
RUN sudo apt-get install -y lsb-release opam libboost-all-dev libjsoncpp-dev
# used by ehsm
RUN sudo apt-get install -y vim autoconf automake build-essential cmake curl debhelper git libcurl4-openssl-dev libprotobuf-dev libssl-dev libtool lsb-release ocaml ocamlbuild protobuf-compiler wget libcurl4 libssl1.1 make g++ fakeroot libelf-dev libncurses-dev flex bison libfdt-dev libncursesw5-dev pkg-config libgtk-3-dev libspice-server-dev libssh-dev python3 python3-pip  reprepro unzip libjsoncpp-dev uuid-dev liblog4cplus-dev

# used by edger8r
RUN opam init -y --disable-sandboxing
RUN opam install -y dune yojson

# prepare ssh
COPY --chown=$USERNAME:$USERNAME .ssh/id_ed25519 /home/$USERNAME/.ssh/id_ed25519
COPY --chown=$USERNAME:$USERNAME .ssh/id_ed25519.pub /home/$USERNAME/.ssh/id_ed25519.pub
RUN echo "StrictHostKeyChecking no" >> /home/$USERNAME/.ssh/config

RUN git clone git@github.com:LeoneChen/EnclaveFuzz.git -b master

WORKDIR /home/$USERNAME/EnclaveFuzz
RUN git submodule update --init --recursive
RUN ./build.sh -g --cov --prepare-sdk --build-sdk
RUN git clone git@github.com:LeoneChen/SGX_APP.git

WORKDIR /home/$USERNAME/EnclaveFuzz/SGX_APP
RUN git submodule update --init --recursive ehsm

WORKDIR /home/$USERNAME/EnclaveFuzz/SGX_APP/ehsm
RUN ./build.sh MODE=DEBUG
RUN /home/$USERNAME/EnclaveFuzz/Tool/workdir/setup.sh --app out/ehsm-core/ehsm_core_test --enclave out/ehsm-core/libenclave-ehsm-core.so --workdir /home/$USERNAME/EnclaveFuzzData/EHSM/Fuzzer2 --taskset 0
