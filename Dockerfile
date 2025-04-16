FROM php:8.1-fpm

# Install dependencies
RUN apt-get update && apt-get install -y nginx

# Copy application code
WORKDIR /app
COPY . .

# Install Composer dependencies
RUN curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer
RUN composer install --optimize-autoloader --no-dev

# Set permissions
RUN chown -R www-data:www-data /app/storage /app/bootstrap/cache
RUN chmod -R 775 /app/storage /app/bootstrap/cache

# Copy Nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf

# Expose port
EXPOSE 3000

# Start PHP-FPM and Nginx
CMD php-fpm -D && nginx -g "daemon off;"

explin me after this
what will the extension of this file 