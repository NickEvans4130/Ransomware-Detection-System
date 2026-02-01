# Phase 6: Web Dashboard

## Objective
Create intuitive web interface for monitoring, configuration, and recovery.

## Dashboard Components

### 1. Real-Time Monitoring View
- Live feed of file system events
- Current threat level indicator
- Active processes being monitored
- System health status

### 2. Threat History
- Timeline of detected threats
- Threat details: process, files affected, actions taken
- Filtering by date, severity, process
- Export incident reports

### 3. File Recovery Interface
- Browse available backups by date/time
- Search for specific files
- Preview file metadata
- One-click restore buttons
- Batch restoration

### 4. Configuration Panel
- Monitored directories management
- Detection threshold tuning
- Response action preferences
- Whitelist/blacklist processes
- Backup retention settings

### 5. Statistics Dashboard
- Files monitored
- Threats blocked
- Files recovered
- Entropy distribution graphs
- Timeline of activity

## Technical Stack
- **Backend**: Flask or FastAPI
- **Frontend**: React (or vanilla JS + Bootstrap for simplicity)
- **Real-time**: WebSockets for live updates
- **Charting**: Chart.js or Recharts
- **Database**: SQLite (existing)

## API Endpoints
```
GET  /api/status          - Current system status
GET  /api/events          - Recent file events (paginated)
GET  /api/threats         - Threat history
POST /api/quarantine      - Manual quarantine process
GET  /api/backups         - List available backups
POST /api/restore         - Restore files
GET  /api/config          - Get configuration
PUT  /api/config          - Update configuration
WS   /ws/live             - WebSocket for real-time updates
```

## UI Mockup Structure
```
┌─────────────────────────────────────────┐
│  Ransomware Detection System            │
├─────────────────────────────────────────┤
│ Status: ● Protected   Threats: 0 Today  │
├─────────────────────────────────────────┤
│ [Monitor] [Threats] [Recovery] [Config] │
├─────────────────────────────────────────┤
│                                          │
│  Live Activity Feed                      │
│  • 14:32:15 - Modified: document.docx    │
│  • 14:32:16 - Created: backup.zip        │
│  • 14:32:18 - Deleted: temp.txt          │
│                                          │
│  Monitored Processes                     │
│  ⚪ WINWORD.EXE     (Normal)             │
│  ⚪ chrome.exe      (Normal)             │
│                                          │
└─────────────────────────────────────────┘
```

## Deliverables
- `app.py` - Flask/FastAPI application
- `static/` - Frontend assets
- `templates/` - HTML templates
- `api/` - API route handlers
- `websocket_handler.py` - Real-time updates

## Testing
- Test all API endpoints
- Verify real-time updates work
- Test recovery workflow UI
- Cross-browser testing
- Mobile responsiveness