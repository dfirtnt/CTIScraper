#!/bin/bash

# CTI Scraper - Network Access Helper
# This script displays network access information for mobile devices

echo "🌐 CTI Scraper - Network Access Information"
echo "=========================================="
echo ""

# Get local IP address
LOCAL_IP=$(ifconfig | grep "inet " | grep -v 127.0.0.1 | awk '{print $2}' | head -1)

echo "📱 Mobile Access URLs:"
echo "   Primary: http://$LOCAL_IP:8000"
echo "   Alternative: http://$LOCAL_IP"
echo ""

echo "🔧 How to Connect:"
echo "   1. Ensure your mobile device is on the same WiFi network"
echo "   2. Open a web browser on your iPhone/iPad/Android"
echo "   3. Navigate to: http://$LOCAL_IP:8000"
echo "   4. Bookmark the URL for easy access"
echo ""

echo "📊 Service Status:"
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" | grep cti_
echo ""

echo "🛡️ Security Note:"
echo "   This setup allows access from any device on your local network."
echo "   For production use, consider adding authentication and HTTPS."
echo ""

echo "📱 QR Code:"
if [ -f "mobile_access_qr.png" ]; then
    echo "   QR code saved as: mobile_access_qr.png"
    echo "   Scan with your mobile device for instant access"
else
    echo "   QR code not found. Run: python3 -c \"import qrcode; qrcode.make('http://$LOCAL_IP:8000').save('mobile_access_qr.png')\""
fi
echo ""

echo "🔍 Troubleshooting:"
echo "   If you can't access from mobile devices:"
echo "   1. Check WiFi connection (same network)"
echo "   2. Try different URLs above"
echo "   3. Check macOS firewall settings"
echo "   4. Restart services: docker-compose restart web nginx"
echo ""

echo "✅ Ready for mobile access!"
