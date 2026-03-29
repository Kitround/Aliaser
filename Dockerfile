FROM php:8.2-apache

# Enable Apache mod_rewrite
RUN a2enmod rewrite

# Set working directory
WORKDIR /var/www/html

# Copy application files
COPY . .

# Ensure json/ directory exists and is writable by Apache
RUN mkdir -p /var/www/html/json \
    && chown -R www-data:www-data /var/www/html/json \
    && chmod 755 /var/www/html/json \
    # Remove any local data files that may have been copied
    && rm -f /var/www/html/json/credentials.json \
             /var/www/html/json/secret.key \
             /var/www/html/json/state.json \
             /var/www/html/json/notes.json \
             /var/www/html/json/addy-contacts.json

EXPOSE 80
