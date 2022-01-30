# slingboxstream-py

Script for running a HLS proxy server for Slingbox written in Python 3.

## Running
1. Edit config.ini with your Slingbox details.
2. Run main.py to start the server
3. Access the stream by opening http://localhost:8080/playlist.m3u8 in your media player

Remote control commands can be sent using http://localhost:8080/remote/[code]

Only tested with Slingbox 350.

## Notes

Based on a [perl script by Slinguist](https://web.archive.org/web/20170508101456/http://placeshiftingenthusiasts.com/forum/general-sling-box-discussions/how-to-record-slingbox-pro-hd-stream-in-high-definition-720-or-1080/#p7522) which is based off [SlingBox SDK](https://sourceforge.net/projects/slingboxsdk/).

SlingBox SDK is listed with a LGPLv2 license so the code in this repository is also LGPLv2.

