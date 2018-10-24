FROM ubuntu:18.04

# requiring >= gcc-7 7.3.0-27: there was a konwn issue of afl/gcc in debian
RUN apt-get update
RUN apt-get upgrade -y && apt-get autoremove -y
RUN apt-get install -y git sudo vim

RUN apt-get install -y clang libfuzzer-6.0-dev
RUN apt-get install -y afl

WORKDIR /root
COPY . .

# trim for release
RUN rm -rf .git
RUN rm NOTE.plan