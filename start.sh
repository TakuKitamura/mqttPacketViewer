python3 tcpPayloadCapture.py > /dev/null 2>&1 &
echo $! > /tmp/tcpPayloadCapture.pid
python3 server.py > /dev/null 2>&1 &
echo $! > /tmp/server.pid