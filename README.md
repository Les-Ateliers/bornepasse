# bornepasse Project
This repo contains simple Python code for controlling a Raspberry Pi along with a webcam, a few relays and colored lights, to scan and validate Digital Green Certificates (EU Digital Covid Certificates).

The relay shield is a [Keyestudio KS0212](https://www.keyestudio.com/products/keyestudio-rpi-4channel-relay-5v-shield-for-raspberry-pi-ce-certification), but any other solution would work, all you would have to change is maybe the GPIO pin assignment according to your custom wiring.

The `/etc/rc.local` line to run it properly could be something like this:
```bash
su pi -c /home/pi/qrcode.py </dev/null >/tmp/qrcode.log 2>&1 &
```
