FROM cimg/base:2020.08

# For now we'll be building PHP from source, so we need a lot of tools
# Throw in some developer helpers too like vim

RUN sudo apt update \
    && sudo apt install -y \
        autoconf \
        bison \
        build-essential \
        clang-format \
        curl \
        gdb \
        git \
        libcurl4-gnutls-dev \
        libonig-dev \
        libreadline-dev \
        libsodium-dev \
        libsqlite3-dev \
        libssl-dev \
        libxml2-dev \
        libzip-dev \
        pkg-config \
        re2c \
        vim \
        zlib1g-dev

# Please remember gdb history
RUN echo 'set history save on' >> /home/circleci/.gdbinit \
    && chmod 600 /home/circleci/.gdbinit

# Make source directory
RUN sudo mkdir -p /usr/local/src/php/8.0 \
    && sudo chown circleci:circleci /usr/local/src/php/8.0 \
    && cd /usr/local/src/php \
    && git clone -b master https://github.com/php/php-src.git 8.0 \
    && cd 8.0 \
    && ./buildconf

# Let's start with an asan build!
# TODO: pear
RUN sudo mkdir -p /tmp/build-php/debug-zts-asan /opt/php/8.0-debug-zts-asan \
    && sudo chown circleci:circleci /tmp/build-php/debug-zts-asan /opt/php/8.0-debug-zts-asan \
    && cd /tmp/build-php/debug-zts-asan \
    && /usr/local/src/php/8.0/configure \
        --enable-option-checking=fatal \
        --enable-debug \
        --enable-zts \
        --prefix=/opt/php/8.0-debug-zts-asan \
        --with-config-file-scan-dir=/opt/php/8.0-debug-zts-asan/etc/php.d \
        --enable-cgi \
        --enable-embed \
        --enable-phpdbg \
        --enable-fpm \
        --enable-mbstring \
        --enable-sockets \
        --with-curl \
        --with-mysqli=mysqlnd \
        --with-openssl \
        --with-pdo-mysql=mysqlnd \
        --with-pdo-sqlite \
        --without-pear \
        --with-readline \
        --with-zip \
        --with-zlib \
        CFLAGS='-fsanitize=undefined,address -DZEND_TRACK_ARENA_ALLOC' \
        LDFLAGS='-fsanitize=undefined,address' \
    && make all install \
    && cd /home/circleci \
    && sudo rm -fr /tmp/build-php/debug-zts-asan

# Regular debug build next!
# TODO: pear
RUN sudo mkdir -p /tmp/build-php/debug /opt/php/8.0-debug \
    && sudo chown circleci:circleci /tmp/build-php/debug /opt/php/8.0-debug \
    && cd /tmp/build-php/debug \
    && /usr/local/src/php/8.0/configure \
        --enable-option-checking=fatal \
        --enable-debug \
        --prefix=/opt/php/8.0-debug \
        --with-config-file-scan-dir=/opt/php/8.0-debug/etc/php.d \
        --enable-cgi \
        --enable-embed \
        --enable-phpdbg \
        --enable-fpm \
        --enable-mbstring \
        --enable-sockets \
        --with-curl \
        --with-mysqli=mysqlnd \
        --with-openssl \
        --with-pdo-mysql=mysqlnd \
        --with-pdo-sqlite \
        --without-pear \
        --with-readline \
        --with-zip \
        --with-zlib \
    && make all install \
    && cd /home/circleci \
    && sudo rm -fr /tmp/build-php/debug

# Regular ndebug, nts build
# TODO: pear
RUN sudo mkdir -p /tmp/build-php/ndebug /opt/php/8.0 \
    && sudo chown circleci:circleci /tmp/build-php/ndebug /opt/php/8.0 \
    && cd /tmp/build-php/ndebug \
    && /usr/local/src/php/8.0/configure \
        --enable-option-checking=fatal \
        --prefix=/opt/php/8.0 \
        --with-config-file-scan-dir=/opt/php/8.0/etc/php.d \
        --enable-cgi \
        --enable-embed \
        --enable-phpdbg \
        --enable-fpm \
        --enable-mbstring \
        --enable-sockets \
        --with-curl \
        --with-mysqli=mysqlnd \
        --with-openssl \
        --with-pdo-mysql=mysqlnd \
        --with-pdo-sqlite \
        --without-pear \
        --with-readline \
        --with-zip \
        --with-zlib \
    && make all install \
    && cd /home/circleci \
    && sudo rm -fr /tmp/build-php/ndebug

WORKDIR /home/circleci


