FROM php:8.5-apache

# curl, openssl and argon2 are already compiled into the official image
# (docker-library/php configures --with-curl, --with-openssl and
# --with-password-argon2), so there is nothing to install. Assert it at build
# time instead of assuming: without curl, proxy.php cannot reach any provider;
# without argon2, auth_hash_password() silently downgrades to bcrypt.
RUN php -r 'exit(extension_loaded("curl") && extension_loaded("openssl") && defined("PASSWORD_ARGON2ID") ? 0 : 1);' \
 || { echo "FATAL: base image is missing curl, openssl or argon2 support"; exit 1; }

RUN a2enmod rewrite headers

# Deny all HTTP access to the persisted state/credentials directory.
# Enforced at the Apache config level (the image ships AllowOverride None, so a
# .htaccess inside json/ would be ignored).
RUN printf '<Directory /var/www/html/json>\n    Require all denied\n    Options -Indexes\n</Directory>\n' \
    > /etc/apache2/conf-available/aliaser-json.conf \
 && a2enconf aliaser-json

# Security headers for every response (static HTML/CSS/JS included, not just PHP).
COPY docker/security-headers.conf /etc/apache2/conf-available/aliaser-headers.conf
RUN a2enconf aliaser-headers

# PHP hardening (no error output to clients, hide version).
COPY docker/php-hardening.ini /usr/local/etc/php/conf.d/zz-aliaser-hardening.ini

# Copy application files from app/ subfolder
COPY app/ /var/www/html/

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
