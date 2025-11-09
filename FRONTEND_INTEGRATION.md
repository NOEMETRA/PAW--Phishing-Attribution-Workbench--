# Frontend Integration Guide

## Backend API Ready

The PAW backend REST API is **fully functional** and ready for frontend integration.

### API Server

**Base URL**: `http://localhost:8000`

**Start Server**:
```bash
cd PAW
uvicorn paw.web.api:app --reload --host 0.0.0.0 --port 8000
```

**Production**:
```bash
uvicorn paw.web.api:app --host 0.0.0.0 --port 8000 --workers 4
```

---

## Available Endpoints

### Analysis

#### Submit Email for Analysis
```http
POST /api/analyze
Content-Type: multipart/form-data

file: <email.eml>
profile: "quick" | "full" | "forensic"
options: {} (optional)
```

**Response**:
```json
{
  "analysis_id": "uuid-string",
  "status": "queued",
  "created_at": "2025-11-09T10:00:00Z"
}
```

#### Get Analysis Status
```http
GET /api/analysis/{analysis_id}
```

**Response**:
```json
{
  "analysis_id": "uuid-string",
  "status": "completed" | "running" | "failed",
  "progress": 100,
  "case_id": "case-2025-11-09-abc",
  "created_at": "...",
  "completed_at": "..."
}
```

---

### Cases Management

#### List All Cases
```http
GET /api/cases?limit=20&offset=0
```

**Response**:
```json
{
  "cases": [
    {
      "case_id": "case-2025-11-09-abc",
      "created_at": "...",
      "status": "completed",
      "summary": {...}
    }
  ],
  "total": 100,
  "limit": 20,
  "offset": 0
}
```

#### Get Case Details
```http
GET /api/cases/{case_id}
```

**Response**: Complete case data including:
- Manifest
- Headers analysis
- Deobfuscation results
- Attribution matrix
- Threat intelligence
- Detonation results (if available)

---

### Query & Search

#### Query Cases
```http
POST /api/query
Content-Type: application/json

{
  "query_type": "ip" | "domain" | "asn",
  "value": "192.168.1.100",
  "days": 30
}
```

**Response**:
```json
{
  "query_type": "ip",
  "value": "192.168.1.100",
  "matches": [
    {
      "case_id": "...",
      "created_at": "...",
      "score": 0.85,
      "origin_ip": "192.168.1.100",
      "manifest": {...}
    }
  ],
  "total": 5
}
```

---

### Dashboard & Statistics

#### Get Dashboard Stats
```http
GET /api/dashboard
```

**Response**:
```json
{
  "total_cases": 150,
  "cases_last_24h": 10,
  "cases_last_7d": 45,
  "unique_asns": 25,
  "unique_countries": 15,
  "threat_actors": ["APT28", "Lazarus", ...]
}
```

---

### Victim Intelligence

#### Get Victim Data
```http
GET /api/victim_intelligence?case_id=case-2025-11-09-abc
```

**Response**:
```json
{
  "case_id": "case-2025-11-09-abc",
  "victims": [
    {
      "victim_ip": "1.2.3.4",
      "click_time": "...",
      "interaction_type": "victim" | "attacker" | "suspicious",
      "interaction_confidence": 0.85,
      "geolocation_data": {...},
      "risk_score": 7
    }
  ],
  "total": 42
}
```

---

### Export

#### Export Case as ZIP
```http
GET /api/export/{case_id}?format=zip
```

**Response**: ZIP file download containing complete case directory

---

## CORS Configuration

CORS is enabled for development:
```python
allow_origins=["*"]  # Change in production
```

For production, update in `paw/web/api.py`:
```python
allow_origins=["https://yourdomain.com"]
```

---

## WebSocket Support (Future)

For real-time analysis progress, WebSocket endpoints can be added:
```http
WS /api/ws/analysis/{analysis_id}
```

---

## Authentication (Future)

Currently no authentication. For production, add:
- JWT tokens
- API keys
- OAuth2

---

## Frontend Development

### Recommended Stack
- **Framework**: React, Vue, Svelte, or any modern framework
- **HTTP Client**: axios, fetch
- **State Management**: Redux, Zustand, Pinia
- **UI Components**: Material-UI, Ant Design, Shadcn/ui

### Example Integration (React)

```typescript
// api.ts
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000/api'
});

export const analyzeEmail = async (file: File, profile: string) => {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('profile', profile);
  
  const { data } = await api.post('/analyze', formData);
  return data;
};

export const getAnalysisStatus = async (analysisId: string) => {
  const { data } = await api.get(`/analysis/${analysisId}`);
  return data;
};
```

### Polling Example

```typescript
const pollAnalysis = async (analysisId: string) => {
  const poll = setInterval(async () => {
    const status = await getAnalysisStatus(analysisId);
    
    if (status.status === 'completed') {
      clearInterval(poll);
      console.log('Analysis complete:', status.case_id);
    } else if (status.status === 'failed') {
      clearInterval(poll);
      console.error('Analysis failed:', status.error);
    }
  }, 2000); // Poll every 2 seconds
};
```

---

## File Upload Limits

Default: 50MB per file (configurable in FastAPI)

To increase:
```python
# In api.py
app = FastAPI(
    title="PAW",
    max_upload_size=100 * 1024 * 1024  # 100MB
)
```

---

## Error Handling

All endpoints return standard HTTP status codes:
- `200` - Success
- `400` - Bad Request
- `404` - Not Found
- `500` - Internal Server Error

Error response format:
```json
{
  "detail": "Error message here"
}
```

---

## Testing API

### Using cURL

```bash
# Upload email
curl -X POST http://localhost:8000/api/analyze \
  -F "file=@test.eml" \
  -F "profile=full"

# Get status
curl http://localhost:8000/api/analysis/{id}

# List cases
curl http://localhost:8000/api/cases
```

### Using Postman

Import base URL: `http://localhost:8000`

---

## Health Check

```http
GET /health
```

**Response**:
```json
{
  "status": "ok",
  "version": "2.0.0"
}
```

---

## Documentation

Interactive API docs available at:
- Swagger UI: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`

---

**Ready for frontend integration!** 🚀
