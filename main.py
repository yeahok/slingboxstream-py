import threading
import time

import asyncio
from aiohttp import web

import slingapi


SLING_IP = "192.168.0.123"
SLING_PORT = 5201
USERNAME = "admin"  # admin or guest
PASSWORD = "password"


# adapted from https://stackoverflow.com/a/51610341
def aiohttp_server():
    async def handle_playlist_request(request):
        playlist = slingconn.playlist
        return web.Response(body=playlist, content_type="application/vnd.apple.mpegurl")

    async def handle_segment_request(request):
        segment_name = request.match_info.get('name', "")
        segment = slingconn.segments[segment_name]
        return web.Response(body=segment, content_type="video/mp2t")

    async def handle_key_request(request):
        key = slingconn.decyption_key
        return web.Response(body=key)
    
    async def handle_remote_request(request):
        button = request.match_info.get('code', "")
        slingconn.send_remote_button(int(btn))
        return web.Response(text="Sent remote button: {0}".format(button))

    app = web.Application()
    app.add_routes([web.get('/playlist.m3u8', handle_playlist_request),
                web.get('/key.bin', handle_key_request),
                web.get('/segments/{name}', handle_segment_request),
                web.get('/remote/{code}', handle_remote_request)])
    runner = web.AppRunner(app)
    return runner

def run_web_server(runner):
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    loop.run_until_complete(runner.setup())
    site = web.TCPSite(runner, "localhost", 8080)
    loop.run_until_complete(site.start())
    loop.run_forever()

t=threading.Thread(target=run_web_server, args=(aiohttp_server(),))
t.start()

slingconn = slingapi.SlingConnection(SLING_IP, SLING_PORT, USERNAME, PASSWORD)
slingconn.connect()
print("hls start")
async def main():
    while True:
        await slingconn.update_segments()

loop = asyncio.get_event_loop()
loop.create_task(main())
loop.run_forever()