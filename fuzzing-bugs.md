## Bug #XXX: Path parameter ':' causes 500
- **Endpoint**: `/get-document/:`
- **Input**: `':'`
- **Response**: `500 Internal Server Error`
- **Expected**: `400 Bad Request` or `404 Not Found`
- **Root Cause**: Unescaped colon triggers routing failure
- **Regression Test**: `test_colon_id_does_not_crash`
- **Status**: Open (Verified on 2025-10-09)