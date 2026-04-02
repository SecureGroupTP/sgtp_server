FROM nginx:1.27-alpine
RUN apk add --no-cache bash gettext
COPY deploy/nginx/entrypoint.sh /entrypoint.sh
COPY deploy/nginx/templates/http-only.conf.template /etc/nginx/templates/http-only.conf.template
COPY deploy/nginx/templates/https.conf.template /etc/nginx/templates/https.conf.template
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
