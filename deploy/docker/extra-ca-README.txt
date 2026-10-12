extra-ca/ - OPTIONAL trusted roots for the test image.

Leave this folder empty on a normal network. If pip inside the build fails with CERTIFICATE_VERIFY_FAILED because a proxy or antivirus re-signs HTTPS, put the PUBLIC root
certificate (*.crt, PEM) of that software here (python docker_test/export_system_ca.py "<name>" does it on Windows) and build with PIP_CERT_FILE=/etc/ssl/certs/ca-certificates.crt.
Only public certificates belong here. Certificate verification is never turned off.
