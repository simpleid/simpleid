#!/usr/bin/env bash
# Exit immediately if a command exits with a non-zero status
set -e

# Set web host name
if [ -n "${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN:-}" ]; then
    WEB_HOST_NAME="${CODESPACE_NAME}-8080.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"
else
    WEB_HOST_NAME="localhost"
fi
export WEB_HOST_NAME

# Install composer modules
composer install

# Install node modules
npm install

# Link code to the web server root and start Apache
sudo rm -rf /var/www/html
sudo ln -s "$(pwd)/www" /var/www/html
echo "ServerName ${WEB_HOST_NAME}" | sudo tee -a /etc/apache2/apache2.conf > /dev/null
sudo apache2ctl start
echo "Web server started"
