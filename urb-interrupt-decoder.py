#!/usr/bin/python
# This script automates steps to decode usb-traces described at
# https://bitvijays.github.io/LFC-Forensics.html
# Use "tshark -r usb-keyboard-data.pcap -T fields -e usb.capdata"
# to format output

import sys
import subprocess
import os


def usage():
    print("Usage: " + sys.argv[0] + " urb-interrupt.pcap")


usb_codes = {
   0x04: "aA", 0x05: "bB", 0x06: "cC", 0x07: "dD", 0x08: "eE", 0x09: "fF",
   0x0A: "gG", 0x0B: "hH", 0x0C: "iI", 0x0D: "jJ", 0x0E: "kK", 0x0F: "lL",
   0x10: "mM", 0x11: "nN", 0x12: "oO", 0x13: "pP", 0x14: "qQ", 0x15: "rR",
   0x16: "sS", 0x17: "tT", 0x18: "uU", 0x19: "vV", 0x1A: "wW", 0x1B: "xX",
   0x1C: "yY", 0x1D: "zZ", 0x1E: "1!", 0x1F: "2@", 0x20: "3#", 0x21: "4$",
   0x22: "5%", 0x23: "6^", 0x24: "7&", 0x25: "8*", 0x26: "9(", 0x27: "0)",
   0x2C: "  ", 0x2D: "-_", 0x2E: "=+", 0x2F: "[{", 0x30: "]}",  0x32: "#~",
   0x33: ";:", 0x34: "'\"",  0x36: ",<",  0x37: ".>", 0x4f: ">", 0x50: "<"
}

lines = ["", "", "", "", ""]
pos = 0


if(len(sys.argv) != 2):
    usage()
    exit(1)

cmdTshark = "tshark -r " + sys.argv[1] + " -T fields -e usb.capdata \
        >> data1.txt"

subprocess.call(cmdTshark, shell=True)

for x in open("data1.txt", "r").readlines():
    if(len(x[6:8]) == 0):
        continue
    code = int(x[6:8], 16)

    if code == 0:
        continue
    # newline or down arrow - move down
    if code == 0x51 or code == 0x28:
        pos += 1
        continue
    # up arrow - move up
    if code == 0x52:
        pos -= 1
        continue
    # select the character based on the Shift key
    if int(x[0:2], 16) == 2:
        lines[pos] += usb_codes[code][1]
    else:
        lines[pos] += usb_codes[code][0]


for x in lines:
    print(x)

os.remove('data1.txt')
