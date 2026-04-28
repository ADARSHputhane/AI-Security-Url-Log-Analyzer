# AI Security URL & Log Analyzer - Enhanced Backend Setup

## New Features

### File Upload Support

- **CSV File Analysis**: Upload CSV files with URLs, IPs, or log entries. Each row is analyzed automatically.
- **LOG File Analysis**: Upload `.log` or `.txt` files for line-by-line security analysis.
- **Bulk Processing**: Process multiple entries at once with detailed threat reports.

## Backend API Endpoints

### Existing Endpoints

- `POST /api/analyze-url` - Analyze a single URL
- `POST /api/analyze-log` - Analyze a single log entry

### New Endpoints

- `POST /api/upload-csv` - Upload and analyze CSV files
- `POST /api/upload-log` - Upload and analyze LOG files

## Setup Instructions

### 1. Update Backend Dependencies

```bash
cd Backend
conda env update --file environment.yml
```

The updated `environment.yml` now includes:

- `pandas` - for CSV file processing
- `flask-cors` - for cross-origin requests

### 2. Required Python Packages

The backend now requires:

```
flask==3.0.0
flask-cors
pandas
transformers==4.35.0
torch==2.1.0
```

### 3. Start the Backend

```bash
cd Backend
python app.py
```

The Flask server will run on `http://localhost:5000`

## Frontend Usage

### Tabs

1. **Single Payloads** - Analyze individual URLs or log entries
2. **Bulk Files** - Upload and analyze CSV and LOG files

### CSV File Format

The CSV file should have headers. Supported column types:

- URLs (automatically detected, must start with http://, https://, or ftp://)
- Log entries or payloads (analyzed as security threats)
- IP addresses (analyzed as log entries)

Example:

```csv
url,ip,log_entry
https://example.com,192.168.1.1,GET /admin.php?id=1
https://malicious.com,10.0.0.1,SELECT * FROM users
```

### LOG File Format

Plain text file with one log entry per line. Example:

```
GET /admin.php?id=1' OR '1'='1 --
POST /login HTTP/1.1
220.181.111.1 - - [01/Jan/2024:12:00:00] "GET /script.php HTTP/1.1" 200
```

## File Size Limits

- Maximum file size: 50MB
- Recommended: < 10MB for optimal performance

## API Response Format

### CSV Upload Response

```json
{
  "filename": "data.csv",
  "total_rows": 100,
  "results": [
    {
      "row_number": 1,
      "data": { "url": "https://example.com", "ip": "192.168.1.1" },
      "threat_analysis": [
        {
          "column": "url",
          "value": "https://example.com",
          "type": "URL",
          "prediction": "BENIGN (SAFE)",
          "confidence": 95.5
        }
      ]
    }
  ]
}
```

### LOG Upload Response

```json
{
  "filename": "access.log",
  "total_lines": 150,
  "results": [
    {
      "line_number": 1,
      "log_entry": "GET /admin.php?id=1' OR '1'='1 --",
      "prediction": "SQL Injection Attack",
      "confidence": 92.3
    }
  ]
}
```

## Error Handling

The backend handles:

- Invalid file formats
- Malformed CSV/LOG files
- Missing required columns
- Network timeouts
- Model inference errors

All errors return descriptive JSON responses with error details.

## Performance Tips

1. **CSV Processing**: Analyze up to 1000 rows per file for best performance
2. **LOG Processing**: Works efficiently with logs up to 10,000 lines
3. **Batch Size**: The UI displays first 20 results, with ability to scroll

## Troubleshooting

### "Flask backend is offline"

- Ensure `python app.py` is running in Backend folder
- Check port 5000 is available
- Verify no firewall is blocking localhost:5000

### CSV not processing

- Verify CSV is valid format
- Check file encoding is UTF-8
- Ensure no empty rows

### LOG file too slow

- Split large files into smaller chunks
- Consider reducing log verbosity
- Check system resources

## Technology Stack

### Backend

- Flask 3.0.0
- Transformers (Hugging Face)
- PyTorch/CUDA
- Pandas (CSV processing)

### Frontend

- Next.js 16.2.4
- React 19.2.4
- TypeScript
- Tailwind CSS v4

### ML Models

- `Eason918/malicious-url-detector` - URL classification
- `facebook/bart-large-mnli` - Log entry classification
