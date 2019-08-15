#!/bin/bash

/usr/bin/python3 ./app.py &
sleep 5
/usr/sbin/httpd -D FOREGROUND
