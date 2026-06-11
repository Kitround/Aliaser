FROM php:8.2-apache

# Install curl extension (openssl is already a core PHP extension)
RUN apt-get update \
    && apt-get install -y --no-install-recommends libcurl4-openssl-dev \
    && docker-php-ext-configure curl \
    && docker-php-ext-install curl \
    && rm -rf /var/lib/apt/lists/*

RUN a2enmod rewrite

# Deny all HTTP access to the persisted state/credentials directory.
# Enforced at the Apache config level (the image ships AllowOverride None, so a
# .htaccess inside json/ would be ignored).
RUN printf '<Directory /var/www/html/json>\n    Require all denied\n    Options -Indexes\n</Directory>\n' \
    > /etc/apache2/conf-available/aliaser-json.conf \
 && a2enconf aliaser-json

# Copy application files from app/ subfolder
COPY app/ /var/www/html/

COPY docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
