# Use official PHP image with FPM
FROM php:8.1-fpm

# Install system dependencies including PDF generation requirements
RUN apt-get update && apt-get install -y \
    git \
    curl \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    zip \
    unzip \
    libpq-dev \
    # PDF generation dependencies
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    fonts-dejavu-core \
    fontconfig \
    wkhtmltopdf \
    # Additional dependencies that might be needed
    libzip-dev \
    && rm -rf /var/lib/apt/lists/*

# Configure and install PHP extensions
RUN docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) \
        pdo \
        pdo_mysql \
        mbstring \
        exif \
        pcntl \
        bcmath \
        gd \
        zip

# Install Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /app

# Copy composer files first for better caching
COPY composer.json composer.lock ./

# Install PHP dependencies
RUN composer install --ignore-platform-reqs --no-dev --optimize-autoloader --no-scripts

# Copy application files
COPY . /app

# Run composer scripts after copying all files
RUN composer dump-autoload --optimize

# Create necessary directories and set permissions
RUN mkdir -p /app/storage/app/public \
    && mkdir -p /app/storage/app/invoices \
    && mkdir -p /app/storage/logs \
    && mkdir -p /app/storage/framework/cache \
    && mkdir -p /app/storage/framework/sessions \
    && mkdir -p /app/storage/framework/views \
    && mkdir -p /app/bootstrap/cache

# Set proper permissions
RUN chown -R www-data:www-data /app/storage /app/bootstrap/cache
RUN chmod -R 775 /app/storage /app/bootstrap/cache

# Set environment variables
ENV PORT=8080
ENV APP_ENV=production

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:${PORT}/health || exit 1

# Expose port
EXPOSE ${PORT}

# Start PHP built-in server for Lumen
CMD php -S 0.0.0.0:${PORT} -t public
