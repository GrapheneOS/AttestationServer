
# Docker deployment

Read [README.md](/README.md) first.
Don't forget to adapt the app ID and signature  as those can only be changed by rebuilding the container.
Also you need to clone submodules as the dockerfile requires them: `git submodule update --init`

Adapt:
- [AttestationProtocol.java:154-162](/src/main/java/app/attestation/server/AttestationProtocol.java#L154-L162) to your app ID and signature
- [AttestationServer.java:85-86](/src/main/java/app/attestation/server/AttestationServer.java#L85-L86) to your domain and protocol
- [AttestationServer.java:320](/src/main/java/app/attestation/server/AttestationServer.java#L320) to "0.0.0.0", or enable IPv6 support in docker