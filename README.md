See the overview of the project at https://attestation.app/about.

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
