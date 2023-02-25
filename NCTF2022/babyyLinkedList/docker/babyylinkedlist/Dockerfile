FROM ubuntu:20.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
    apt-get update && apt-get -y dist-upgrade && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y lib32z1 xinetd git libglib2.0-dev libfdt-dev libpixman-1-dev zlib1g-dev qemu qemu-system-x86

RUN useradd -m ctf

WORKDIR /home/ctf

COPY ./ctf.xinetd /etc/xinetd.d/ctf
COPY ./start.sh /start.sh
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail
RUN chmod +x /start.sh

COPY ./bin/ /home/ctf/
RUN chown -R root:ctf /home/ctf && \
        chmod -R 750 /home/ctf

CMD ["/start.sh"]

EXPOSE 9999