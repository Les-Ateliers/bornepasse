#! /usr/bin/python3
# coding:utf8

import json
import time
import threading

import requests

import sys

import platform
import subprocess

import RPi.GPIO as GPIO

from signal import *

from datetime import date, datetime, timezone, timedelta

from dateutil.parser import parse, isoparse

from cose.messages import Sign1Message, CoseMessage

from cose.keys import CoseKey

from cose.headers import KID

from cose.keys.keyparam import KpKty

from cose.algorithms import Es256, Ps256
from cose.keys.curves import P256
from cose.keys import CoseKey
from cose.keys.keyparam import KpAlg, EC2KpX, EC2KpY, EC2KpCurve, RSAKpE, RSAKpN
from cose.keys.keyparam import KpKty
from cose.keys.keytype import KtyEC2, KtyRSA
from cose.exceptions import CoseException

from cryptography.utils import int_to_bytes
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives import serialization

import zlib
from base64 import b64encode, b64decode

import cbor2
from base45 import b45decode

import cv2
import pyzbar.pyzbar as pyzbar

kids = {}
keyid = None
key = None
status_valid = False
status_sign = False

thread_running = False

delta_days = 2
delta_days_v = 6
wait_light = 5

GPIO.cleanup()
GPIO.setmode(GPIO.BCM)
GPIO.setup(4, GPIO.OUT)
GPIO.setup(22, GPIO.OUT)
GPIO.setup(6, GPIO.OUT)
GPIO.setup(26, GPIO.OUT)

def ping(host):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower()=='windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', host]

    return subprocess.call(command) == 0


def load_json():
	jsonraw = ""
	# gets public signatures from the Sanipasse project (https://github.com/lovasoa/sanipasse/)
	response = requests.get("https://github.com/lovasoa/sanipasse/raw/master/src/assets/Digital_Green_Certificate_Signing_Keys.json")
	json_obj = json.loads(response.content)
	for kid_b64 in json_obj:
		add_kid(kid_b64, json_obj[kid_b64]['publicKeyPem'], json_obj[kid_b64]['notBefore'], json_obj[kid_b64]['notAfter'])
	print("Clés chargées : " + str(len(kids)))

def add_kid(kid_b64, key_b64, valid_from, valid_to):
        kid = b64decode(kid_b64 + "===")
        asn1data = b64decode(key_b64)
        kids[kid_b64] = {}
        kids[kid_b64]['from'] = valid_from
        kids[kid_b64]['to'] = valid_to

        pub = serialization.load_der_public_key(asn1data)
        if (isinstance(pub, RSAPublicKey)):
              kids[kid_b64]['key'] = CoseKey.from_dict(
               {
                    KpKty: KtyRSA,
                    KpAlg: Ps256,  # RSSASSA-PSS-with-SHA-256-and-MFG1
                    RSAKpE: int_to_bytes(pub.public_numbers().e),
                    RSAKpN: int_to_bytes(pub.public_numbers().n)
               })
        elif (isinstance(pub, EllipticCurvePublicKey)):
              kids[kid_b64]['key'] = CoseKey.from_dict(
               {
                    KpKty: KtyEC2,
                    EC2KpCurve: P256,  # Ought o be pk.curve - but the two libs clash
                    KpAlg: Es256,  # ecdsa-with-SHA256
                    EC2KpX: pub.public_numbers().x.to_bytes(32, byteorder="big"),
                    EC2KpY: pub.public_numbers().y.to_bytes(32, byteorder="big")
               })
        else:
              print(f"Skipping unexpected/unknown key type (keyid={kid_b64}, {pub.__class__.__name__}).",  file=sys.stderr)

def remove_prefix(input_string, prefix):
    if prefix and input_string.startswith(prefix):
        return input_string[len(prefix):]
    return input_string

def decodeDisplay(image):
    image = cv2.flip(image, 1)
    gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
    barcodes = pyzbar.decode(gray)
    for barcode in barcodes:

        (x, y, w, h) = barcode.rect
        cv2.rectangle(image, (x, y), (x + w, y + h), (255, 128, 0), 2)

        barcodeData = barcode.data.decode("utf-8")
        barcodeType = barcode.type
        if(barcodeType != "QRCODE"):
          return image

        data = remove_prefix(barcodeData, "HC1:")

        try:
          data = b45decode(data)
        except ValueError:
          return image

        if (data[0] == 0x78):
            data = zlib.decompress(data)
            decoded = CoseMessage.decode(data)
            if KID in decoded.phdr.keys():
               given_kid = decoded.phdr[KID]
            else:
               given_kid = decoded.uhdr[KID]
            try:
              key = kids[b64encode(given_kid).decode('ASCII')]['key']
            except KeyError:
              key = None
            decoded.key = key
            payload = cbor2.loads(decoded.payload)
            dob = date.fromisoformat(payload.get(-260).get(1).get('dob'))
            dob = dob.strftime("%d/%m/%Y")
            text = payload.get(-260).get(1).get('nam').get('gnt') + ' ' + payload.get(-260).get(1).get('nam').get('fnt') + ' - ' + dob
            int_payload = payload.get(-260).get(1)
            if(int_payload.get('r')):
              du = date.fromisoformat(int_payload.get('r')[0].get('du'))
              df = date.fromisoformat(int_payload.get('r')[0].get('df'))
              if(du >= date.today() and df <= date.today()):
                status_valid = True
              else:
                status_valid = False
            elif(int_payload.get('t')):
                sc = datetime.fromisoformat(int_payload.get('t')[0].get('sc'))
                delta = datetime.now(timezone.utc) - sc
                if(delta > timedelta(days=delta_days)):
                    status_valid = False
                else:
                    status_valid = True
            elif(int_payload.get('v')):
              if(int_payload.get('v')[0].get('dn') == 2):
                dt = datetime.fromisoformat(int_payload.get('v')[0].get('dt') + "T00:00:00+00:00")
                deltav = datetime.now(timezone.utc) - dt
                if(deltav > timedelta(days=delta_days_v)):
                  status_valid = True
                else:
                  status_valid = False
              else:
                status_valid = False

            try:
              status_sign = decoded.verify_signature()
            except CoseException:
              status_sign = False

            if(status_sign == True):
              signature_from = isoparse(kids[b64encode(given_kid).decode('ASCII')]['from'])
              signature_to = isoparse(kids[b64encode(given_kid).decode('ASCII')]['to'])
              now = datetime.now(timezone.utc)
              if(signature_from > now or now > signature_to):
                status_sign = False

            total_status = status_sign and status_valid
            if(total_status == True):
              color = (0, 255, 0)
            else:
              color = (0, 0, 255)
            cv2.putText(image, text, (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 6)
            cv2.putText(image, text, (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 1, color, 2)

            if(thread_running == False):
              t1 = threading.Thread(target=print_hello, args=(total_status,))
              t1.start()

    return image


def print_hello(status):
    global thread_running
    thread_running = True
    led = 22
    color = 'rouge'
    if(status == True):
      color = 'verte'
      led = 4
    print('Lumière ' + color)
    GPIO.output(led, GPIO.HIGH)
    GPIO.output(6, GPIO.LOW)
    time.sleep(wait_light)
    print('Lumière éteinte')
    GPIO.output(led, GPIO.LOW)
    GPIO.output(6, GPIO.HIGH)
    thread_running = False


def detect():

    camera = cv2.VideoCapture(0)

    while True:
        ret, frame = camera.read()
        gray = frame
        im = decodeDisplay(gray)

        cv2.waitKey(5)
        # commented out : if you have a display available, you can draw details on screen
        # cv2.imshow("camera", im)

    camera.release()
    cv2.destroyAllWindows()

def clean(*args):
    print("Extinction des feux, nettoyage. Bye !")
    GPIO.cleanup()
    sys.exit(0)

for sig in (SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM):
    signal(sig, clean)

if __name__ == '__main__':
    while True:
      if(ping("8.8.8.8") == True):
        load_json()
        break
    GPIO.output(6, GPIO.HIGH)
    detect()
