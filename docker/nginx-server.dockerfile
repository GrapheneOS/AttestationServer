# Copying same dockerfile content, as they are built only once
FROM archlinux:base-20240101.0.204074

# Installing dev dependencies
# moreutils is required for packages: sponge
RUN pacman --noconfirm -Sy jdk-openjdk zopfli parallel yajl brotli nginx-mod-brotli python3 python-pip nodejs npm libxml2 moreutils

ENV GITHUB_ACTIONS="true"
ENV PATH="/opt/venv/bin:$PATH"
ENV SKIP_REMOTE_PUBLISHING="1"


WORKDIR /app
COPY . /app

RUN npm i
RUN python -m venv /opt/venv
RUN pip install -r requirements.txt

RUN ./process-static

FROM archlinux:base-20240101.0.204074

RUN pacman --noconfirm -Sy nginx nginx-mod-brotli

COPY --from=0 /app/nginx-tmp/nginx.conf /etc/nginx/
COPY --from=0 /app/nginx-tmp/mime.types /etc/nginx/
COPY --from=0 /app/nginx-tmp/root_attestation.app.conf /etc/nginx/
COPY --from=0 /app/nginx-tmp/snippets /etc/nginx/snippets
COPY --from=0 /app/static-tmp /srv/attestation.app_a
COPY ./docker/nginx/nginx.conf /etc/nginx/nginx.conf

RUN mkdir -p /etc/nginx/modules/
RUN ln -s /usr/lib/nginx/modules/ngx_http_brotli_filter_module.so /etc/nginx/modules/ngx_http_brotli_filter_module.so
RUN ln -s /usr/lib/nginx/modules/ngx_http_brotli_static_module.so /etc/nginx/modules/ngx_http_brotli_static_module.so

CMD [ "nginx", "-g", "daemon off;" ]