#
# NOTE: THIS DOCKERFILE IS GENERATED VIA "update.sh"
#
# PLEASE DO NOT EDIT IT DIRECTLY.
#
FROM debian:buster-slim

LABEL maintainer="NGINX Docker Maintainers <docker-maint@nginx.com>"

ENV NGINX_VERSION   1.21.0
ENV NJS_VERSION     0.5.3
ENV PKG_RELEASE     1~buster

RUN set -x \
# create nginx user/group first, to be consistent throughout docker variants
    && addgroup --system --gid 101 nginx \
    && adduser --system --disabled-login --ingroup nginx --no-create-home --home /nonexistent --gecos "nginx user" --shell /bin/false --uid 101 nginx \
    && apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y gnupg1 ca-certificates \
    && \
    NGINX_GPGKEY=573BFD6B3D8FBC641079A6ABABF5BD827BD9BF62; \
    found=''; \
    for server in \
        ha.pool.sks-keyservers.net \
        hkp://keyserver.ubuntu.com:80 \
        hkp://p80.pool.sks-keyservers.net:80 \
        pgp.mit.edu \
    ; do \
        echo "Fetching GPG key $NGINX_GPGKEY from $server"; \
        apt-key adv --keyserver "$server" --keyserver-options timeout=10 --recv-keys "$NGINX_GPGKEY" && found=yes && break; \
    done; \
    test -z "$found" && echo >&2 "error: failed to fetch GPG key $NGINX_GPGKEY" && exit 1; \
    apt-get remove --purge --auto-remove -y gnupg1 && rm -rf /var/lib/apt/lists/* \
    && dpkgArch="$(dpkg --print-architecture)" \
    && nginxPackages=" \
        nginx=${NGINX_VERSION}-${PKG_RELEASE} \
        nginx-module-xslt=${NGINX_VERSION}-${PKG_RELEASE} \
        nginx-module-geoip=${NGINX_VERSION}-${PKG_RELEASE} \
        nginx-module-image-filter=${NGINX_VERSION}-${PKG_RELEASE} \
        nginx-module-njs=${NGINX_VERSION}+${NJS_VERSION}-${PKG_RELEASE} \
    " \
    && case "$dpkgArch" in \
        amd64|i386|arm64) \
# arches officialy built by upstream
            echo "deb https://nginx.org/packages/mainline/debian/ buster nginx" >> /etc/apt/sources.list.d/nginx.list \
            && apt-get update \
            ;; \
        *) \
# we're on an architecture upstream doesn't officially build for
# let's build binaries from the published source packages
            echo "deb-src https://nginx.org/packages/mainline/debian/ buster nginx" >> /etc/apt/sources.list.d/nginx.list \
            \
# new directory for storing sources and .deb files
            && tempDir="$(mktemp -d)" \
            && chmod 777 "$tempDir" \
# (777 to ensure APT's "_apt" user can access it too)
            \
# save list of currently-installed packages so build dependencies can be cleanly removed later
            && savedAptMark="$(apt-mark showmanual)" \
            \
# build .deb files from upstream's source packages (which are verified by apt-get)
            && apt-get update \
            && apt-get build-dep -y $nginxPackages \
            && ( \
                cd "$tempDir" \
                && DEB_BUILD_OPTIONS="nocheck parallel=$(nproc)" \
                    apt-get source --compile $nginxPackages \
            ) \
# we don't remove APT lists here because they get re-downloaded and removed later
            \
# reset apt-mark's "manual" list so that "purge --auto-remove" will remove all build dependencies
# (which is done after we install the built packages so we don't have to redownload any overlapping dependencies)
            && apt-mark showmanual | xargs apt-mark auto > /dev/null \
            && { [ -z "$savedAptMark" ] || apt-mark manual $savedAptMark; } \
            \
# create a temporary local APT repo to install from (so that dependency resolution can be handled by APT, as it should be)
            && ls -lAFh "$tempDir" \
            && ( cd "$tempDir" && dpkg-scanpackages . > Packages ) \
            && grep '^Package: ' "$tempDir/Packages" \
            && echo "deb [ trusted=yes ] file://$tempDir ./" > /etc/apt/sources.list.d/temp.list \
# work around the following APT issue by using "Acquire::GzipIndexes=false" (overriding "/etc/apt/apt.conf.d/docker-gzip-indexes")
#   Could not open file /var/lib/apt/lists/partial/_tmp_tmp.ODWljpQfkE_._Packages - open (13: Permission denied)
#   ...
#   E: Failed to fetch store:/var/lib/apt/lists/partial/_tmp_tmp.ODWljpQfkE_._Packages  Could not open file /var/lib/apt/lists/partial/_tmp_tmp.ODWljpQfkE_._Packages - open (13: Permission denied)
            && apt-get -o Acquire::GzipIndexes=false update \
            ;; \
    esac \
    \
    && apt-get install --no-install-recommends --no-install-suggests -y \
                        $nginxPackages \
                        gettext-base \
                        curl \
    && apt-get remove --purge --auto-remove -y && rm -rf /var/lib/apt/lists/* /etc/apt/sources.list.d/nginx.list \
    \
# if we have leftovers from building, let's purge them (including extra, unnecessary build deps)
    && if [ -n "$tempDir" ]; then \
        apt-get purge -y --auto-remove \
        && rm -rf "$tempDir" /etc/apt/sources.list.d/temp.list; \
    fi \
# forward request and error logs to docker log collector
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
# create a docker-entrypoint.d directory
    && mkdir /docker-entrypoint.d

COPY docker-entrypoint.sh /
COPY 10-listen-on-ipv6-by-default.sh /docker-entrypoint.d
COPY 10-tune-nginx.sh /docker-entrypoint.d
COPY 20-envsubst-on-templates.sh /docker-entrypoint.d
COPY 30-tune-worker-processes.sh /docker-entrypoint.d
RUN chmod +x /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.d/10-listen-on-ipv6-by-default.sh
RUN chmod +x /docker-entrypoint.d/10-tune-nginx.sh
RUN chmod +x /docker-entrypoint.d/20-envsubst-on-templates.sh
RUN chmod +x /docker-entrypoint.d/30-tune-worker-processes.sh

RUN mkdir -p /etc/nginx/modules
COPY modules/ngx_http_brotli_filter_module.so /etc/nginx/modules
COPY modules/ngx_http_brotli_static_module.so /etc/nginx/modules
COPY modules/ngx_http_headers_more_filter_module.so /etc/nginx/modules

COPY config/nginx/gzip.conf /etc/nginx
COPY config/nginx/brotli.conf /etc/nginx
COPY config/nginx/ssl.conf /etc/nginx
COPY config/nginx/nginx_limits.conf /etc/nginx

RUN mkdir -p /etc/nginx/extra

COPY config/nginx/block.conf /etc/nginx/extra
COPY config/nginx/security.conf /etc/nginx/extra
COPY config/nginx/disable_user_api.conf /etc/nginx/extra
COPY config/nginx/disable_xmlrpc.conf /etc/nginx/extra
COPY config/nginx/staticfiles.conf /etc/nginx/extra

RUN mkdir -p /usr/share/nginx/logs
RUN mkdir -p /var/log/php-fpm

RUN mkdir -p /etc/nginx/certs
COPY certs/server.crt /etc/nginx/certs
COPY certs/server.csr /etc/nginx/certs
COPY certs/server.key /etc/nginx/certs
RUN openssl dhparam -out /etc/nginx/certs/dhparams.pem 2048

## Install PHP-FPM

RUN apt update -y && apt install wget software-properties-common apt-transport-https lsb-release ca-certificates curl -y
RUN wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
RUN sh -c 'echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" > /etc/apt/sources.list.d/php.list'
RUN apt-get update
#RUN apt-get install -y --no-install-recommends g++ \
#           libbz2-dev \
#           libc-client-dev \
#           libcurl4-gnutls-dev \
#           libedit-dev \
#           libfreetype6-dev \
#           libicu-dev \
#           libjpeg62-turbo-dev \
#           libkrb5-dev \
#           libldap2-dev \
#           libldb-dev \
#           libmagickwand-dev \
#           libmcrypt-dev \
#           libmemcached-dev \
#           libpng-dev \
#           libpq-dev \
#           libwebp-dev \
#           libsqlite3-dev \
#           libssl-dev \
#           libreadline-dev \
#           libxslt1-dev \
#           libzip-dev \
#           wget \
#           unzip \
#           zlib1g-dev \
#           nano

RUN apt-get -y install nano wget unzip zlib1g-dev php8.0 php8.0-fpm php8.0-ldap php8.0-zip \
            php8.0-cli php8.0-mysql php8.0-gd php8.0-xml \
            php8.0-mbstring php8.0-common php8.0-soap \
            php8.0-curl php8.0-bcmath php8.0-snmp php8.0-pspell \
            php8.0-gmp php8.0-intl php8.0-imap php8.0-enchant \
            php8.0-xmlrpc php8.0-tidy php8.0-opcache php8.0-cli \
            php8.0-dev php8.0-imagick php8.0-sqlite3

COPY config/php/00-hostvn-custom.ini /etc/php/8.0/cli/conf.d
COPY config/php/00-hostvn-custom.ini /etc/php/8.0/fpm/conf.d
COPY config/php/php-fpm.conf /etc/php/8.0/fpm

## install memcached
RUN apt-get install memcached libmemcached-dev libmemcached-tools -y

RUN wget https://pecl.php.net/get/igbinary-3.2.2.tgz -P /opt
RUN wget https://pecl.php.net/get/memcached-3.1.5.tgz -P /opt

RUN cd /opt && tar -xvf /opt/igbinary-3.2.2.tgz && tar -xvf /opt/memcached-3.1.5.tgz
RUN cd /opt/igbinary-3.2.2 && /usr/bin/phpize8.0 && ./configure --with-php-config=/usr/bin/php-config8.0 && make && make install
RUN cd /opt/memcached-3.1.5 && /usr/bin/phpize8.0 \
    && ./configure --enable-memcached-igbinary --with-php-config=/usr/bin/php-config8.0 \
    && make && make install

## Install wp-cli
RUN wget https://raw.githubusercontent.com/wp-cli/builds/gh-pages/phar/wp-cli.phar
RUN chmod +x wp-cli.phar
RUN mv wp-cli.phar /usr/local/bin/wp

## Download Wordpress
RUN wget https://wordpress.org/wordpress-5.7.2.tar.gz -P /usr/share/nginx/html
RUN cd /usr/share/nginx/html && tar -xvf /usr/share/nginx/html/wordpress-5.7.2.tar.gz
RUN rm -rf /usr/share/nginx/html/wordpress-5.7.2.tar.gz
RUN cd /usr/share/nginx/html/wordpress && mv * /usr/share/nginx/html && cd /usr/share/nginx/html \
    && rm -rf wordpress readme.html license.txt index.html 50x.html
RUN chown -R nginx. /usr/share/nginx

RUN rm -rf /opt/*
RUN apt-get autoremove --purge -y && apt-get autoclean -y && apt-get clean -y \
        && rm -rf /var/lib/apt/lists/* \
        && rm -rf /tmp/* /var/tmp/*

ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 80

WORKDIR /usr/share/nginx/html

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]
