FROM php:8.2-apache

# Deliberately vulnerable lab config (by design):
#  - Apache executes .php AND .phtml/.pht/.php5/.phar  (real, common misconfig;
#    this is WHY an extension blacklist that only blocks "php" is bypassable).
#  - AllowOverride All lets an uploaded .htaccess re-enable execution (advanced).
#  - +Indexes directory-lists the document folders (discovery / IDOR).
COPY lab.conf /etc/apache2/conf-available/lab.conf
RUN a2enconf lab

COPY app/ /var/www/html/
RUN mkdir -p /var/www/html/docs/loan /var/www/html/docs/card \
             /var/www/html/docs/mortgage /var/www/html/docs/verify \
             /var/www/html/docs/dispute \
 && chown -R www-data:www-data /var/www/html
