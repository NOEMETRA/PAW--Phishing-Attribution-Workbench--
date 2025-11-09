# GUI Module

This directory contains the graphical user interface for PAW.

## Status

🚧 **Under Development** - New GUI implementation in progress

The previous Tkinter-based GUI (`tk_gui.py`) has been removed to make way for a modern interface.

## Planned Architecture

- Modern web-based UI (React/Vue/Svelte)
- RESTful API integration via FastAPI backend
- Real-time analysis progress tracking
- Interactive dashboards and visualizations

## Backend API

The backend REST API is fully functional and ready for frontend integration.

**Base URL**: `http://localhost:8000`

### Available Endpoints:

- `POST /api/analyze` - Submit email for analysis
- `GET /api/analysis/{id}` - Get analysis status
- `GET /api/cases` - List all cases
- `GET /api/cases/{case_id}` - Get case details
- `POST /api/query` - Query cases by IP/domain/ASN
- `GET /api/export/{case_id}` - Export case as ZIP
- `GET /api/dashboard` - Dashboard statistics
- `GET /api/victim_intelligence` - Victim intelligence data

See [paw/web/api.py](../web/api.py) for complete API documentation.

## Development

To start the API server:

```bash
uvicorn paw.web.api:app --reload --host 0.0.0.0 --port 8000
```

Frontend can connect to this endpoint for all PAW functionality.
