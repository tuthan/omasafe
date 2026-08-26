import urllib.request

BENIGN = ["notify-send", "omarchy update finished"]


def notify():
    import os
    os.system(" ".join(BENIGN))
