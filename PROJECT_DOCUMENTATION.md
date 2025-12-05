# Smart Vehicle Intrusion Detection System (IDS) Dashboard

## Project Overview

The Smart Vehicle IDS Dashboard is a real-time web-based monitoring and simulation system for vehicle cybersecurity. It provides a comprehensive interface for visualizing vehicle telemetry data, detecting anomalies, simulating various cyberattacks on vehicle systems (ECUs - Electronic Control Units), and analyzing security threats in real-time.

**Purpose:** Educational and research tool for understanding vehicle intrusion detection, CAN bus security, and automotive cyber threats.

---

## Technology Stack

### Backend
- **Framework:** Flask 3.0.0 (Python)
- **Server:** Python 3.13.9
- **Key Libraries:**
  - `flask` - Web framework
  - `requests` - HTTP client for external API calls
  - `datetime` - Timestamp generation
  - `collections.Counter` - Data aggregation
  - `json` - Data serialization
  - `os` - File system operations

### Frontend
- **Language:** HTML5, CSS3, JavaScript (ES6+)
- **Chart Library:** Chart.js (for data visualization)
- **Storage:** Browser LocalStorage (for alert persistence)
- **Architecture:** Single-Page Application (SPA)

### External Services
- **IP Geolocation:** ip-api.com (HTTP endpoint for attacker IP details)

---

## Project Structure

```
smart-vehicle-ids-dashboard/
├── app.py                          # Flask backend application
├── requirements.txt                # Python dependencies
├── README.md                       # Project setup guide
├── PROJECT_DOCUMENTATION.md        # This file
├── static/                         # Frontend assets
│   ├── index.html                 # Main dashboard page
│   ├── alerts.html                # All alerts page
│   ├── app.js                     # Dashboard logic
│   ├── alerts.js                  # Alerts page logic
│   ├── style.css                  # Styling (dark theme)
│   └── qr.jpg                     # QR code for feedback
├── logs/                          # Telemetry logs
│   └── telemetry.log             # JSON log file
└── venv/                          # Python virtual environment
```

---

## Core Features Implemented

### 1. Real-Time Vehicle Telemetry Dashboard

**What It Does:**
- Displays live vehicle sensor data from 6 ECUs (Electronic Control Units)
- Shows vehicle speed, brake status, CAN anomaly score
- Updates every 1 second via API polling

**How It Works:**
- Backend generates realistic vehicle signals using SIGNAL_DEFS
- Frontend polls `/api/telemetry` endpoint
- Real-time updates rendered to dashboard UI

**ECUs Simulated:**
- Engine ECU
- Brake ECU
- Steering ECU
- Infotainment
- Telematics
- ADAS ECU (Advanced Driver Assistance Systems)

### 2. Attack Simulation System

**Supported Attack Types:**
1. **CAN Bus Flooding** - Multiple signals sent rapidly at abnormal values
2. **GPS Spoofing** - False GPS coordinates and random location jumps
3. **Lane Camera Spoof** - Unrealistic lane offset and yaw rate values
4. **Brake Spoofing** - Brake engaged without driver input at high speeds
5. **ECU Replay Attack** - Previous signal values replayed to confuse systems
6. **Sensor Manipulation** - ADAS sensor readings set to impossible values

**Implementation:**
- Attacks triggered via dashboard buttons
- POST endpoint: `/api/attack_mode`
- Attack mode stored in global state (`ACTIVE_ATTACK`)
- Affects signal generation in `generate_can_signals()` function
- All attacks generate security alerts

### 3. Anomaly Detection Engine

**Rule-Based IDS Logic:**

```python
# Physics-based rules:
- Speed jump detection (Δv > 60 km/h) → HIGH alert
- Brake at unsafe speed (speed > 120 km/h + brake ON) → CRITICAL alert
- CAN anomaly density (≥10 anomalous signals) → HIGH alert
```

**Anomaly Scoring:**
- Each signal has normal_min/normal_max range
- Values outside range marked as anomalous
- Anomaly score = 0.2 + 0.03 × (anomaly_count)
- Score capped at 1.0

### 4. Security Alerts System

**Features:**
- Real-time alert generation with timestamps
- Alert levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Alert persistence using browser LocalStorage
- 500-alert history limit
- Auto-saved on every alert generation

**Alert Information Captured:**
- Level (severity)
- Source (ECU name)
- Message (detailed description)
- Timestamp (HH:MM:SS in 12-hour format with AM/PM)
- Attack type
- Attacker IP (simulated)

### 5. All Security Alerts Page

**Location:** `/alerts.html`

**Features:**
- Displays full history of all alerts
- Statistics dashboard showing counts of:
  - Critical Alerts
  - Warning Alerts
  - Info Alerts
  - Total Alerts
- Multi-level filtering by:
  - Alert level (Critical/High/Warning/Info)
  - Alert source (ECU name)
- Sorting options:
  - Newest first
  - Oldest first
  - By severity level
- Pagination (20 alerts per page)
- Export to Excel/CSV functionality
- Clear all alerts button
- Back to dashboard button

**Technical Implementation:**
- Reads from browser LocalStorage
- Dynamic filter dropdowns based on available sources
- CSV export with UTF-8 BOM for Excel compatibility
- Responsive design matching main dashboard

### 6. Popup Alert Notifications

**Features:**
- Real-time alerts appear as floating notifications
- Top-right corner of screen
- Color-coded by severity:
  - Red border: CRITICAL/HIGH
  - Orange border: MEDIUM/WARNING
  - Blue border: INFO/LOW
- Timestamp displayed in 12-hour format (HH:MM:SS AM/PM)
- Auto-dismiss after 5 seconds
- Manual close button (×)
- Only show when manual attack enabled

**Styling:**
- Dark theme (matching dashboard)
- Slide-in animation
- Fade-out animation on close
- Box shadow for depth

### 7. Top Attackers Analysis

**Features:**
- Displays top 5 most active attacker IPs
- Shows attack count for each IP
- "View Details" button for each IP

**IP Details Modal:**
- Fetches geolocation data from ip-api.com
- Backend proxy endpoint: `/api/ip-details/<ip>`
- Displays:
  - IP Address
  - Country & Country Code
  - Region & City
  - Timezone
  - Coordinates (Latitude/Longitude)
  - ISP & Organization
  - ASN (Autonomous System Number)
  - Mobile/Proxy/Hosting status
- Error handling for API failures
- Loading state during fetch

### 8. Analytics Dashboard

**Chart Visualizations:**
1. **Top ECUs Targeted** - Bar chart of attacked ECUs
2. **Attack Types** - Distribution of attack types
3. **Alert Volume** - Line graph of alerts over time

**Top Attackers Table:**
- IP addresses with attack counts
- View Details button for each IP

**Real-Time Data:**
- All charts update with live data
- Timeline shown for last 200 data points
- Critical alerts highlighted separately

### 9. CAN Bus Live Signals Table

**Features:**
- Real-time CAN bus traffic simulation
- 150 most recent signals displayed
- Columns: Time, ECU, Signal, Value, Anomaly flag
- Anomalous signals highlighted in red
- Signal rate badge (signals/second)

**Data Structure:**
```javascript
{
  timestamp: "HH:MM:SS",
  ecu: "Engine ECU",
  signal: "Vehicle Speed",
  value: "65.0 km/h",
  numeric: 65.0,
  unit: "km/h",
  anomaly: true/false
}
```

### 10. ECU Health Monitoring

**Status Indicators:**
- Health percentage for each ECU (0-100%)
- Status colors:
  - Green: OK (healthy)
  - Yellow: Warning
  - Red: Compromised

**Dynamic Updates:**
- Health degrades during attacks
- Recovery to normal between attacks
- Visual heatmap representation

### 11. Export Functionality

**Export Alerts to Excel:**
- CSV format (Excel-compatible)
- Columns: Level, Source, Message, Time
- UTF-8 BOM encoding for proper display
- Filename: `alerts_export.csv`
- Includes all alerts in history (not just filtered view)

---

## Backend Implementation Details

### Flask Routes

#### 1. `/` (GET)
- Serves main dashboard HTML
- Entry point for application

#### 2. `/api/telemetry` (GET)
- Returns current vehicle telemetry snapshot
- Called every 1 second by frontend
- Response includes:
  - Vehicle speed, brake status
  - ECU health values
  - CAN anomaly score
  - Security alerts
  - CAN packets/signals
  - Attack status
  - Heatmap data

#### 3. `/api/attack_mode` (POST)
- Sets active attack mode
- Request body: `{"mode": "flood"}` or `{"mode": "off"}`
- Updates global `ACTIVE_ATTACK` state
- Affects subsequent telemetry generation

#### 4. `/api/analytics` (GET)
- Returns aggregated analytics data
- Top 5 targeted ECUs
- Top 5 attack types
- Top 5 attacker IPs
- Events timeline (last 200 entries)

#### 5. `/api/ip-details/<ip>` (GET)
- Proxies IP geolocation requests to ip-api.com
- Uses HTTP endpoint (avoids SSL issues)
- Returns complete IP details
- Error handling for API failures

### Key Functions

#### `generate_telemetry()`
- Main telemetry generation function
- Generates realistic vehicle state
- Applies attack effects
- Runs rule-based IDS evaluation
- Updates analytics
- Logs to file

#### `generate_can_signals()`
- Generates decoded CAN signals
- Takes attack_mode as parameter
- Applies attack-specific modifications
- Marks anomalies based on normal ranges
- Returns array of signal objects

#### `evaluate_rules()`
- Rule-based anomaly detection
- Physics-based checks (speed jump, brake safety)
- CAN density checks
- Generates security alerts
- Updates anomaly score

#### `update_analytics()`
- Aggregates attack statistics
- Maintains event timeline
- Tracks attack counts by ECU, type, and IP
- Manages 200-item rolling window

### Data Structures

#### Signal Definition
```python
{
    "ecu": "Engine ECU",
    "signal": "Vehicle Speed",
    "unit": "km/h",
    "min": 0,
    "max": 220,
    "normal_min": 0,
    "normal_max": 140
}
```

#### Security Alert
```python
{
    "level": "CRITICAL",           # HIGH, MEDIUM, LOW, INFO
    "source": "Engine ECU",        # ECU name
    "message": "Alert message",    # Detailed description
    "attack_type": "CAN Flooding", # Type of attack
    "attacker_ip": "192.168.1.1"   # Simulated attacker IP
}
```

#### Snapshot (Telemetry)
```python
{
    "speed": 65,
    "brake_status": "ON",
    "ecu_health": {...},
    "can_anomaly_score": 0.35,
    "attack_active": True,
    "heatmap": [...],
    "security_alerts": [...],
    "can_packets": [...],
    "attack_mode": "flood",
    "timestamp": "2025-12-05 14:30:45"
}
```

---

## Frontend Implementation Details

### State Management

**Global Variables (app.js):**
- `alertHistory[]` - Array of security alerts
- `canHistory[]` - Array of recent CAN signals
- `allAlerts[]` (alerts.js) - All alerts for alerts page
- `filteredAlerts[]` (alerts.js) - Filtered alerts view
- `currentAttackMode` - Active attack type

### LocalStorage Usage

**Storage Keys:**
- `alertHistory` - Persisted security alerts (JSON)
- Used for data persistence across page refreshes

### Event Handlers

**Main Dashboard:**
- Attack buttons → POST to `/api/attack_mode`
- Clear Alerts button → Clears localStorage and UI
- Show All Alerts button → Navigate to alerts.html
- View Details (IP) → Fetch IP geolocation → Show modal

**Alerts Page:**
- Filter changes → Apply filters and re-render
- Sort changes → Sort and re-render
- Pagination buttons → Update current page
- Export button → Generate CSV and download
- Clear All button → Confirm and clear all alerts

### Chart.js Integration

**Three Charts on Dashboard:**
1. **ECU Chart** - Bar chart of targeted ECUs
2. **Attack Type Chart** - Pie/Doughnut of attack distribution
3. **Events Chart** - Line chart of alert volume over time

### CSS Styling

**Color Scheme:**
- Background: #0f172a (dark navy)
- Cards: #1f2937 (dark gray)
- Text: #f3f4f6 (light gray)
- Primary: #3b82f6 (blue)
- Success: #10b981 (green)
- Warning: #f59e0b (orange)
- Danger: #dc2626 (red)

**Key Classes:**
- `.dashboard` - Main container
- `.card` - Content card
- `.alert-item` - Individual alert
- `.popup-alert` - Floating notification
- `.modal-overlay` - Modal background
- `.btn-view-details` - IP details button

---

## How It All Works Together

### 1. Application Startup
```
1. User opens http://localhost:5000
2. Flask serves index.html
3. JavaScript loads (app.js)
4. CSS stylesheet applied
5. Chart.js library loaded from CDN
6. Alerts loaded from LocalStorage
```

### 2. Real-Time Telemetry Loop
```
1. Frontend polls /api/telemetry every 1 second
2. Backend generates new snapshot with:
   - Random vehicle state (speed, brake)
   - CAN signals (20+ signals per ECU)
   - Rule-based anomaly detection
   - Alert generation if conditions met
3. Frontend updates UI:
   - Telemetry values
   - ECU health
   - CAN table
   - Charts
   - Alert list
4. New alerts saved to LocalStorage
```

### 3. Attack Simulation Workflow
```
1. User clicks attack button (e.g., "CAN Bus Flooding")
2. Frontend POST to /api/attack_mode with mode
3. Backend sets ACTIVE_ATTACK global variable
4. Next telemetry generation applies attack effects
5. Anomalies increase, alerts generated
6. Dashboard shows attack activity
7. User can click "Stop All Attacks" to clear
```

### 4. Alert Viewing Flow
```
1. User clicks "Show All Alerts"
2. Navigate to alerts.html
3. Load alerts from LocalStorage
4. Build filter dropdowns from alert sources
5. Display statistics
6. Render paginated alert list
7. User can:
   - Filter by level/source
   - Sort by time/severity
   - Export to CSV
   - Clear all
   - Return to dashboard
```

### 5. IP Geolocation Flow
```
1. User clicks "View Details" on attacker IP
2. Modal opens with "Loading..." state
3. Frontend GET /api/ip-details/XXX.XXX.XXX.XXX
4. Backend proxies request to ip-api.com (HTTP)
5. Backend returns geolocation JSON
6. Frontend populates modal with details:
   - Country, Region, City
   - Timezone, Coordinates
   - ISP, Organization, ASN
   - Mobile/Proxy/Hosting flags
7. Modal displays formatted data
```

---

## Configuration & Customization

### Adding New ECUs

**Edit `app.py` line 13:**
```python
ECU_NAMES = [
    "Your New ECU",
    # ... existing ECUs
]
```

### Adding New Signals

**Edit `app.py` line 45:**
```python
SIGNAL_DEFS = [
    # ... existing signals
    {"ecu": "Your ECU", "signal": "Signal Name", "unit": "unit",
     "min": 0, "max": 100, "normal_min": 10, "normal_max": 90},
]
```

### Adding New Attack Types

**Edit `app.py` line 20:**
```python
ATTACK_TYPES = [
    "your_attack_type",
    # ... existing types
]
```

**Add logic in `generate_can_signals()` (~line 167)**

### Alert Level Customization

**Edit styling in `style.css`:**
```css
.alert-badge.CRITICAL { /* red */ }
.alert-badge.HIGH { /* orange */ }
.alert-badge.WARNING { /* yellow */ }
.alert-badge.INFO { /* blue */ }
```

---

## Running the Project

### Prerequisites
- Python 3.13+
- Virtual environment (venv)

### Installation
```bash
# Navigate to project directory
cd f:\Diwakar\smart-vehicle-ids-dashboard

# Create virtual environment (if not exists)
python -m venv venv

# Activate virtual environment
.\venv\Scripts\Activate.ps1  # Windows PowerShell

# Install dependencies
pip install -r requirements.txt
```

### Running the Application
```bash
# From virtual environment
python app.py

# Application will be available at:
# http://localhost:5000
# http://127.0.0.1:5000
```

### Stopping the Application
```
Press CTRL+C in the terminal
```

---

## File Descriptions

### Backend Files

**app.py** (474+ lines)
- Main Flask application
- Telemetry generation engine
- Attack simulation logic
- Rule-based IDS
- API endpoints
- Analytics aggregation

**requirements.txt**
- Flask==3.0.0
- gunicorn
- Werkzeug==3.0.1
- Jinja2==3.1.2
- itsdangerous==2.1.2
- click==8.1.7
- requests

### Frontend Files

**index.html** (195 lines)
- Main dashboard page
- Attack scenario buttons
- Telemetry display
- ECU health grid
- Heatmap visualization
- CAN bus table
- Anomaly timeline
- Analytics charts
- Security alerts section
- Feedback modal
- IP details modal

**app.js** (550+ lines)
- Global state management
- Telemetry polling loop
- Dashboard update functions
- Attack scenario handlers
- Alert management
- CAN packet rendering
- Chart initialization/updates
- Analytics calculations
- IP details fetching
- LocalStorage persistence

**alerts.html** (369 lines)
- Dedicated alerts page
- Statistics dashboard
- Multi-level filters
- Alert list with pagination
- Export functionality
- Responsive design

**alerts.js** (200+ lines)
- Alert page state management
- Filter and sort logic
- Pagination handlers
- Statistics calculation
- CSV export logic
- LocalStorage integration

**style.css** (661 lines)
- Dark theme styling
- Responsive layout
- Component styling
- Animation definitions
- Color scheme definitions
- Grid and flexbox layouts

---

## Deployment Considerations

### Development vs Production

**Development (Current Setup):**
- Debug mode enabled
- Auto-reload on file changes
- Flask development server
- Suitable for testing and development

**Production Deployment:**
```bash
# Use Gunicorn instead of Flask server
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### Security Notes

1. **LocalStorage** - Alerts stored unencrypted in browser
2. **IP-API.com** - Free tier uses HTTP, rate limited
3. **Debug Mode** - Disable in production
4. **CORS** - Not restricted (fine for local use)

### Performance Optimizations

1. **Telemetry Polling** - Currently 1 second, can be adjusted
2. **Alert History** - Limited to 500 entries for memory efficiency
3. **Event Timeline** - Rolling window of 200 entries
4. **CAN History** - Limited to 150 packets

---

## Testing & Verification

### Manual Testing Checklist

- [ ] Dashboard loads without errors
- [ ] Telemetry updates every 1 second
- [ ] Attack buttons trigger attacks
- [ ] Alerts appear in real-time
- [ ] Popup notifications show with timestamps
- [ ] All alerts page loads and displays data
- [ ] Filters work correctly
- [ ] Export to CSV successful
- [ ] IP details modal fetches and displays data
- [ ] Charts update with data
- [ ] Clear alerts functionality works
- [ ] LocalStorage persistence works across refreshes

### Browser Console

Open Developer Tools (F12) to see:
- Console logs for debugging
- Network requests to API endpoints
- Alert loading/saving messages
- IP details fetch logs

---

## Future Enhancement Opportunities

1. **Database Integration** - Replace file logging with database
2. **Authentication** - User login and permissions
3. **Advanced IDS** - Machine learning anomaly detection
4. **Real CAN Data** - Integration with actual vehicle CAN bus
5. **Mobile App** - React Native or Flutter app
6. **Email Alerts** - Send alerts via email
7. **Threat Intelligence** - IP reputation scoring
8. **Performance Metrics** - Dashboard response times
9. **Multi-Vehicle** - Support multiple vehicles
10. **Historical Analysis** - Long-term trend analysis

---

## Troubleshooting

### Issue: "ModuleNotFoundError: No module named 'requests'"
**Solution:** 
```bash
pip install requests
```

### Issue: Port 5000 already in use
**Solution:**
```bash
# Change port in app.py line 472:
app.run(host="0.0.0.0", port=5001, debug=True)
```

### Issue: LocalStorage not persisting
**Solution:**
- Check browser privacy settings
- Ensure cookies/storage enabled
- Try different browser

### Issue: IP details not loading
**Solution:**
- Check internet connection
- Verify ip-api.com is accessible
- Check browser console for errors

---

## Credits & References

- **Chart.js** - Data visualization library
- **ip-api.com** - IP geolocation service
- **Flask** - Web framework
- **Python** - Programming language

---

## License

This project is for educational and research purposes.

---

**Last Updated:** December 5, 2025  
**Version:** 1.0.0  
**Status:** Production Ready
