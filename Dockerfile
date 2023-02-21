FROM ubuntu:20.04 AS builder

ENV repository="openfhe-development"
ENV DEBIAN_FRONTEND=noninteractive
ENV CC_param=/usr/bin/clang
ENV CXX_param=/usr/bin/clang++
ENV CC $CC_param
ENV CXX $CXX_param

RUN apt update && apt install -y git build-essential gcc-10 \
   g++-10 cmake autoconf clang libomp5 libomp-dev doxygen graphviz libboost-all-dev=1.71.0.0ubuntu2 \
   && apt upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*


ENV PATH $PATH:/opt/cmake/bin
ENV PATH $PATH:/usr/local/include
ENV PATH $PATH:/usr/local/include/openfhe
ENV PATH $PATH:/usr/local/lib

#Install openfhe
WORKDIR /include
RUN git clone https://github.com/openfheorg/$repository.git 
WORKDIR openfhe-development
RUN git submodule sync --recursive && git submodule update --init --recursive
WORKDIR build
RUN cmake .. && make -j4 && make install



FROM ubuntu:20.04 

ENV PYTHON_VERSION=3.7.4
ENV DEBIAN_FRONTEND=noninteractive
ENV CC_param=/usr/bin/clang
ENV CXX_param=/usr/bin/clang++
ENV CC $CC_param
ENV CXX $CXX_param

RUN apt update && apt install -y git build-essential gcc-10 \
   g++-10 cmake clang libomp5 libomp-dev libbz2-dev libdb-dev \
  libreadline-dev libffi-dev libgdbm-dev liblzma-dev \
  libncursesw5-dev libsqlite3-dev libssl-dev pip\
  zlib1g-dev uuid-dev wget tk-dev && apt upgrade -y && apt-get clean && rm -rf /var/lib/apt/lists/*


COPY --from=builder /usr/local/include/openfhe /usr/local/include/openfhe
COPY --from=builder /usr/local/lib /usr/local/lib

# Install Python by pyenv and pyenv-virtualenv
SHELL ["/bin/bash", "-c"]
ENV PATH $PATH:/opt/cmake/bin
ENV PATH $PATH:/usr/local/include
ENV PATH $PATH:/usr/local/include/openfhe
ENV PATH $PATH:/usr/local/lib
ENV MYPY /root/.pyenv/versions/3.7.4/envs/myenv/bin/python

ENV HOME /root
ENV PYENV_ROOT $HOME/.pyenv
ENV PATH $PYENV_ROOT/bin:$PATH

RUN git clone https://github.com/pyenv/pyenv.git ~/.pyenv
RUN echo 'eval "$(pyenv init --path)"' >> ~/.bashrc &&\
    echo 'eval "$(pyenv init -)"' >> ~/.bashrc
RUN source ~/.bashrc && pyenv install ${PYTHON_VERSION} && pyenv global ${PYTHON_VERSION}
RUN git clone https://github.com/pyenv/pyenv-virtualenv.git ~/.pyenv/plugins/pyenv-virtualenv
RUN echo 'eval "$(pyenv virtualenv-init -)"' >> ~/.bashrc
RUN source ~/.bashrc


# Install openfhe-pybind"
COPY . /openfhe-pybind
WORKDIR /openfhe-pybind
RUN source ~/.bashrc && pyenv virtualenv ${PYTHON_VERSION} myenv && pyenv global ${PYTHON_VERSION}
RUN echo 'eval "source activate myenv"' >> ~/.bashrc
RUN source ~/.bashrc && pip install --upgrade pip setuptools

#install "pybind11"
RUN git clone https://github.com/pybind/pybind11.git
WORKDIR /openfhe-pybind/pybind11/build
RUN cmake .. -DCMAKE_INSTALL_PREFIX=../install/ -DPYBIND11_TEST=Off -DPYTHON_EXECUTABLE=$MYPY && make install

WORKDIR /openfhe-pybind/build
RUN source ~/.bashrc && cmake -DPYTHON_EXECUTABLE=$MYPY .. && make -j4
RUN mv openfhe_pybind.cpython* ~/.pyenv/versions/3.7.4/envs/myenv/lib/python3.7/site-packages/

WORKDIR /openfhe-pybind
