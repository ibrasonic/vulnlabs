FROM php:8.2-apache

# VULN (by design): make Apache execute more than just .php.  Treating
# .phtml/.pht/.php5/.phar as PHP is a real, common server misconfiguration and
# is exactly WHY extension blacklists that only block "php" get bypassed.
# AllowOverride All lets an uploaded .htaccess re-enable execution (advanced
# bypass).  +Indexes directory-lists the upload folders (discovery / IDOR).
COPY lab.conf /etc/apache2/conf-available/lab.conf
RUN a2enconf lab

COPY app/ /var/www/html/
RUN mkdir -p /var/www/html/u /var/www/html/avatars /var/www/html/gallery \
 && chown -R www-data:www-data /var/www/html
