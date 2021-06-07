
<p align="center"><strong><a href="https://hostvn.net">Hostvn.net - Tên miền, Web Hosting, Email, VPS &amp; Dịch vụ lưu trữ Website</a></strong></p>
<p align="center"> <img src="https://blog.hostvn.net/wp-content/uploads/2020/07/logo-big-2.png" /> </p>

#####################################################################################

## About Hostvn.net WordPress

Hostvn.net - WordPress is Docker Images, pre-installed with Nginx, php-fpm and WordPress, with the best security configurations and optimization for WordPress

## Quick reference

- Maintained by: <a href="https://hostvn.net">Hostvn.net</a>
- Docker hub: https://hub.docker.com/r/hostvn/wordpress
- WordPress: https://wordpress.org/
- Nginx Brotli module: https://github.com/google/ngx_brotli
- Nginx header more module: https://github.com/openresty/headers-more-nginx-module

## Changes:

- Customize <b>/etc/nginx/nginx.conf</b> file configuration more optimally
- Add module ngx_brotli
- Add module ngx_headers_more
- Security configuration file at: <b>/etc/nginx/extra/security.conf</b>
- Block SQL injections, file injections, spam ... at: <b>/etc/nginx/extra/block.conf</b>
- Disable xmlrpc.php: <b>/etc/nginx/extra/disable_xmlrpc.conf</b>
- Disable User API: <b>/etc/nginx/extra/disable_user_api.conf</b>
- Config browse cache: <b>/etc/nginx/extra/staticfiles.conf</b>
- Add the configuration file CloudFlare ip: <b>/etc/nginx/cloudflare.conf</b>
- Custom PHP Ini: <b>/etc/php/7.4/cli/conf.d/00-hostvn-custom.ini, /etc/php/7.4/fpm/conf.d/00-hostvn-custom.ini</b>
- Added security header structure

## PHP Extensions

- ldap
- zip
- cli
- mysql
- gd
- xml
- mbstring
- soap
- common
- curl
- bcmath
- snmp
- pspell
- gmp
- intl
- imap
- enchant
- xmlrpc
- tidy
- opcache
- imagick
- sqlite3
- json
- memcached
- redis
- igbinary

## Using:

```html
docker run --name nginx -p 80:80 -p 443:443 --restart always -v ./web:/usr/share/nginx/html -d hostvn/wordpress-php7
```

```html
docker run --name nginx -p 80:80 -p 443:443 --restart always -v ./web:/usr/share/nginx/html -d hostvn/wordpress-php8
```
