ARG BASE_IMAGE=apache/apisix
ARG BASE_IMAGE_VERISON=3.9.1-debian

# Use a base image with Lua and development tools
FROM ${BASE_IMAGE}:${BASE_IMAGE_VERISON}

USER root

RUN apt install -y default-libmysqlclient-dev luarocks libyaml-dev
# RUN apt install gcc -y
RUN luarocks install luasql-mysql MYSQL_INCDIR=/usr/include/mysql
RUN luarocks install yaml
RUN luarocks install lua-cjson
# RUN luarocks install lua-resty-hmac

USER apisix

# Copy the plugin source code into the Docker image
# COPY ./plugins/ /usr/local/apisix/plugins/

# Configuration (if necessary)
# For APISIX to load the plugin, you may need to update the APISIX configuration

# Expose ports
EXPOSE 9080 9443

# Start APISIX
CMD ["apisix", "start"]