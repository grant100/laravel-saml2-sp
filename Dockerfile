FROM ubuntu:18.04
FROM php:7.2-cli
FROM composer:latest

WORKDIR /app

COPY . /app

EXPOSE 8000

RUN php --version
RUN composer --version

RUN composer global require laravel/installer
RUN composer update

CMD ["php", "artisan","serve", "--host=0.0.0.0","--port=8000"]

