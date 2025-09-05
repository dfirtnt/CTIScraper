# CTI Scraper - Network Access Information

## 🌐 Access from Mobile Devices & Other Computers

The CTI Scraper web UI is already configured to be accessible from any device on your local network.

### 📱 **Mobile Access URLs:**

**Primary Access:**
- **http://192.168.1.236:8000** (Direct FastAPI access)

**Alternative Access (if Nginx is configured):**
- **http://192.168.1.236** (Port 80 - Nginx proxy)

### 🔧 **How to Connect:**

1. **Ensure your mobile device is on the same WiFi network** as your Mac
2. **Open a web browser** on your iPhone/iPad/Android
3. **Navigate to:** `http://192.168.1.236:8000`
4. **Bookmark the URL** for easy access

### 📊 **Current Service Status:**

| Service | Status | Port | Network Access |
|---------|--------|------|----------------|
| Web UI (FastAPI) | ✅ Running | 8000 | ✅ Available |
| Nginx Proxy | ✅ Running | 80 | ✅ Available |
| PostgreSQL | ✅ Running | 5432 | ✅ Available |
| Redis | ✅ Running | 6379 | ✅ Available |
| Ollama AI | ✅ Running | 11434 | ✅ Available |

### 🔍 **Troubleshooting:**

If you can't access from mobile devices:

1. **Check WiFi Connection:** Ensure both devices are on the same network
2. **Try Different URLs:**
   - `http://192.168.1.236:8000`
   - `http://192.168.1.236`
3. **Check Firewall:** macOS firewall might be blocking connections
4. **Restart Services:** `docker-compose restart web nginx`

### 🛡️ **Security Note:**

This setup allows access from any device on your local network. For production use, consider:
- Adding authentication
- Using HTTPS with SSL certificates
- Restricting access to specific IP ranges

### 📱 **Mobile-Optimized Features:**

The web UI includes:
- Responsive design for mobile screens
- Touch-friendly interface
- Mobile-optimized article viewing
- Swipe gestures for navigation

---

**Last Updated:** $(date)
**Local IP:** 192.168.1.236
**Network:** 192.168.1.0/24
