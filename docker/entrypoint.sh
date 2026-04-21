#!/bin/sh
set -e

# Ensure json/ (mounted as a volume at runtime) is writable by Apache.
# Docker creates the volume directory as root:root on first start — this fixes it.
mkdir -p /var/www/html/json
chown -R www-data:www-data /var/www/html/json
chmod 750 /var/www/html/json

exec apache2-foreground
