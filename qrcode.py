#! /usr/bin/python3
# coding:utf8

import json
import time
import threading

import hashlib

import requests

import configparser

import sys

import platform
import subprocess

try:
  import RPi.GPIO as GPIO
  raspberry = True
except ModuleNotFoundError:
  raspberry = False

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
bl_hashes = {}
keyid = None
key = None
status_valid = False
status_sign = False
status_not_blacklisted = True

thread_running = False

config = None

delta_days = 2
delta_days_v = 7
delta_days_positive_start = 11
delta_days_positive_end = 183
wait_light_red = 5
wait_light_green = 2
delta_days_r = 183
# 15th feb 2022: max 120 days after second dose
delta_days_passe_v = 120
valid_prophylaxis = { "J07BX03", "1119349007", "1119305005" }
valid_vaccines = { "EU/1/20/1528", "EU/1/20/1507", "EU/1/21/1529", "EU/1/20/1525", "Covishield", "R-Covi", "R-COVI", "Covid-19 vaccine (recombinante)", "EU/1/21/1618" }
not_detected = "260415000"
detected = "260373001"
booster = 3

if(raspberry == True):
  GPIO.setmode(GPIO.BCM)
  GPIO.setup(4, GPIO.OUT)
  GPIO.setup(22, GPIO.OUT)
  GPIO.setup(6, GPIO.OUT)
  GPIO.setup(26, GPIO.OUT)

def getConfig():
	config = configparser.ConfigParser()
	config.read('config.ini')
	print("Config charg??e")
	return config

def ping(host):
    """
    Returns True if host (str) responds to a ping request.
    Remember that a host may not respond to a ping (ICMP) request even if the host name is valid.
    """

    # Option for the number of packets as a function of
    param = '-n' if platform.system().lower()=='windows' else '-c'

    # Building the command. Ex: "ping -c 1 google.com"
    command = ['ping', param, '1', host]

    return subprocess.call(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) == 0

def put_stats(hash):
	global config
	response = requests.post(config['general']['statsHost'], data = {'hash': hash, 'pass': config['general']['pass'] })

def load_json():
	jsonraw = ""
	# gets public signatures from the Sanipasse project (https://github.com/lovasoa/sanipasse/)
	response = requests.get("https://github.com/lovasoa/sanipasse/raw/master/src/assets/Digital_Green_Certificate_Signing_Keys.json")
	json_obj = json.loads(response.content)
	for kid_b64 in json_obj:
		add_kid(kid_b64, json_obj[kid_b64]['publicKeyPem'], json_obj[kid_b64]['notBefore'], json_obj[kid_b64]['notAfter'])
	print("Cl??s charg??es : " + str(len(kids)))

def load_blacklist():
	global bl_hashes
	response = requests.get("https://app-static.tousanticovid.gouv.fr/json/version-35/CertList/certlist.json")
	bl_hashes = json.loads(response.content)
	print("Hashes blacklist??s charg??s : " + str(len(bl_hashes)))

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
    hash = None
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
        print(payload)
        dob = date.fromisoformat(payload.get(-260).get(1).get('dob'))
        dob = dob.strftime("%d/%m/%Y")
        text = payload.get(-260).get(1).get('nam').get('gnt') + ' ' + payload.get(-260).get(1).get('nam').get('fnt') + ' - ' + dob
        int_payload = payload.get(-260).get(1)
        if(int_payload.get('r')):
          du = date.fromisoformat(int_payload.get('r')[0].get('du'))
          df = date.fromisoformat(int_payload.get('r')[0].get('df'))
          fr = date.fromisoformat(int_payload.get('r')[0].get('fr'))
          deltam = date.today() - fr
          hash = hashlib.sha256((int_payload.get('r')[0].get('co')+int_payload.get('r')[0].get('ci')).encode()).hexdigest()
          if(du >= date.today() and df <= date.today() and deltam < timedelta(days=delta_days_r)):
            status_valid = True
          else:
            status_valid = False
            failure_reason = "Recovery time window exceeded (too soon or too late)"
        elif(int_payload.get('t')):
          sc = datetime.fromisoformat(int_payload.get('t')[0].get('sc'))
          delta = datetime.now(timezone.utc) - sc
          hash = hashlib.sha256((int_payload.get('t')[0].get('co')+int_payload.get('t')[0].get('ci')).encode()).hexdigest()
          if(int_payload.get('t')[0].get('tr') == detected and delta > timedelta(days=delta_days_positive_start) and delta < timedelta(days=delta_days_positive_end)):
            status_valid = True
          else:
            status_valid = False
            failure_reason = "Negative tests are not accepted anymore"
        elif(int_payload.get('v')):
          dt = datetime.fromisoformat(int_payload.get('v')[0].get('dt') + "T00:00:00+00:00")
          deltav = datetime.now(timezone.utc) - dt
          hash = hashlib.sha256((int_payload.get('v')[0].get('co')+int_payload.get('v')[0].get('ci')).encode()).hexdigest()
          if(int_payload.get('v')[0].get('dn') == int_payload.get('v')[0].get('sd')):
            if(deltav > timedelta(days = delta_days_v)):
              if(int_payload.get('v')[0].get('vp') in valid_prophylaxis and int_payload.get('v')[0].get('mp') in valid_vaccines):
                status_valid = True
              else:
                status_valid = False
                failure_reason = "Unsupported vaccine/prophylaxis types"
              if(deltav > timedelta(days = delta_days_r)):
                status_valid = False
                failure_reason = "Last vaccine shot is too old"
            else:
              if(int_payload.get('v')[0].get('sd') == booster):
                status_valid = True
              else:
                status_valid = False
                failure_reason = "Vaccination scheme delay is too short"
          elif(int_payload.get('v')[0].get('dn') == 2):
            if(deltav > timedelta(days = delta_days_passe_v)):
              status_valid = False
              failure_reason = "Second vaccine shot is too old"
            else:
              status_valid = True
          else:
            status_valid = False
            failure_reason = "Vaccination scheme incomplete"

        if hash in bl_hashes:
            status_not_blacklisted = False
            failure_reason = "Hash is blacklisted"
        else:
            status_not_blacklisted = True

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

        total_status = status_sign and status_valid and status_not_blacklisted
        if(total_status == True):
          color = (0, 255, 0)
          failure_reason = ""
        else:
          color = (0, 0, 255)
        cv2.putText(image, text, (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 1, (0, 0, 0), 6)
        cv2.putText(image, text, (x, y - 10), cv2.FONT_HERSHEY_SIMPLEX, 1, color, 2)

        if(thread_running == False):
          t1 = threading.Thread(target=disp_light, args=(total_status, failure_reason, hash,))
          t1.start()

    return image

def put_stats_thread(hash):
    put_stats(hash)

def disp_light(status, reason, hash):
    print(hash)
    global thread_running
    thread_running = True
    led = 22
    color = 'rouge'
    wait_light = wait_light_red
    if(status == True):
      wait_light = wait_light_green
      color = 'verte'
      led = 4
    print('Lumi??re ' + color + reason)
    if(raspberry == True):
      GPIO.output(led, GPIO.HIGH)
      GPIO.output(6, GPIO.LOW)
    if(hash is not None):
      t_put_stats = threading.Thread(target=put_stats_thread, args=(hash,))
      t_put_stats.start()
    time.sleep(wait_light)
    print('Lumi??re ??teinte')
    if(raspberry == True):
      GPIO.output(led, GPIO.LOW)
      GPIO.output(6, GPIO.HIGH)
    time.sleep(1)
    thread_running = False


def detect():

    camera = cv2.VideoCapture(0)

    while True:
        ret, frame = camera.read()
        gray = frame
        im = decodeDisplay(gray)

        cv2.waitKey(5)
        # commented out : if you have a display available, you can draw details on screen
        if(raspberry == False):
          cv2.imshow("camera", im)

    camera.release()
    cv2.destroyAllWindows()

def clean(*args):
    global raspberry
    print("Extinction des feux, nettoyage. Bye !")
    if(raspberry == True):
      GPIO.cleanup()
    sys.exit(0)

for sig in (SIGABRT, SIGILL, SIGINT, SIGSEGV, SIGTERM):
    signal(sig, clean)

if __name__ == '__main__':
    if(raspberry == True):
      GPIO.output(22, GPIO.HIGH)
    while True:
      if(ping("8.8.8.8") == True):
        config = getConfig()
        load_json()
        load_blacklist()
        if(raspberry == True):
          GPIO.output(22, GPIO.LOW)
        break
    if(raspberry == True):
      GPIO.output(6, GPIO.HIGH)
    detect()
