See the overview of the project at https://attestation.app/about.

## Installation guide

This is an generic guide on setting up the attestation server.

You need to set up nginx using the nginx configuration in the nginx directory
in this repository. You'll need to adjust it based on your domain name. The
sample configuration relies on certbot and certbot-ocsp-fetcher. Setting up the
web server is out-of-scope for this guide.

Install a headless Java runtime environment. The package name on Debian-based
distributions is `default-jre-headless`. Install `sqlite3` in order to set up
the email configuration for the database.

As root, on the server:

    useradd -m -s /bin/bash -b /var/lib attestation

    mkdir -p /opt/attestation/deploy_{a,b}
    cd /opt/attestation
    ln -s deploy_a deploy

    mkdir -p /var/www/html_{a,b}
    cd /var/www
    ln -s html_a html
    chown -R www-data:www-data /var/www

Set up ssh `authorized_keys` for the www-data and attestation users.

Copy attestation.service to /etc/systemd/system/attestation.service.

On your development machine, deploy the code:

    ./deploy_server
    ./deploy_static

As root, on the server:

    systemctl enable attestation
    systemctl start attestation

## Email alert configuration

In order to send email alerts, AttestationServer needs to be configured with valid credentials for
an SMTP server. The configuration is stored in the `Configuration` table in the database and can
be safely modified while the server is running to have it kick in for the next email alert cycle.

Only SMTPS (SMTP over TLS) with a valid certificate is supported for remote email servers.
STARTTLS is deliberately not supported because it's less secure unless encrypted is enforced, in
which case it makes more sense to use SMTPS anyway. The username must also be the full address for
sending emails.

For example, making an initial configuration:

    sqlite3 attestation.db "INSERT INTO Configuration VALUES ('emailUsername', 'alert@attestation.app'), ('emailPassword', '<password>'), ('emailHost', 'mail.grapheneos.org'), ('emailPort', '465')"

### Handling abuse

The `emailBlacklistPatterns` array in
`src/main/java/app/attestation/server/AttestationServer.java` can be used to blacklist email
addresses using regular expressions. We plan to move this to a table in the database so that it
can be configured dynamically without modifying the sources, rebuilding and redeploying. For now,
this was added to quickly provide a way to counter abuse.

## API for the Auditor app

### QR code

The scanned QR code contains space-separated values in plain-text: `<domain> <userId>
<subscribeKey> <verifyInterval>`. The `subscribeKey` should be treated as an opaque string rather
than assuming base64 encoding. Additional fields may be added in the future.

### /challenge

* Request method: POST
* Request headers: n/a
* Request body: n/a
* Response body:

Returns a standard challenge message in the same format as the Auditor app QR code. The challenge
can only be used once and expires in 1 minute.

The server challenge index is always zeroed out and the userId should be used instead.

### /verify

* Request method: POST
* Request headers:

The `Authorization` header needs to be set to `Auditor <userId> <subscribeKey>` for an unpaired
attestation. That will also work for a paired attestation if the subscribeKey matches, but it
should be set to `Auditor <userId>` to allow for subscribeKey rotation.

* Request body:

Standard attestation message in the same format as the Auditor app QR code.

* Response body:

Returns space-separated values in plain text: `<subscribeKey> <verifyInterval>`. Additional fields
may be added in the future.
