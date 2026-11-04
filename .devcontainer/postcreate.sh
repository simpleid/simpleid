#!/usr/bin/env bash
# Exit immediately if a command exits with a non-zero status
set -e

# Install composer modules
composer install

# Install node modules
npm install

# Link code to the web server root and start Apache
sudo rm -rf /var/www/html
sudo ln -s "$(pwd)/www" /var/www/html
echo "ServerName localhost" | sudo tee -a /etc/apache2/apache2.conf > /dev/null
sudo apache2ctl start
echo "Web server started"
