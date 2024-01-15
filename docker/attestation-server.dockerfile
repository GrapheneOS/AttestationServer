FROM archlinux:base-20240101.0.204074

WORKDIR /app
RUN pacman --noconfirm -Sy jdk-openjdk

COPY . /app
RUN ./gradlew build

FROM fedora:39

RUN dnf -y update
RUN dnf -y install java-latest-openjdk-headless

WORKDIR /data
RUN mkdir /app
COPY --from=0 /app/build/libs/ /app
COPY --from=0 /app/libs/sqlite4java-prebuilt/ /usr/lib

CMD [ "/usr/bin/java", "-cp", "/app/*", "app.attestation.server.AttestationServer" ]