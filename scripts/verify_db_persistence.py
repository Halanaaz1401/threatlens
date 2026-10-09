import sqlite3
import json
import sys

def main():
    import os
    db_path = 'backend/threatlens.db' if os.path.exists('backend/threatlens.db') else 'threatlens.db'
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # 1. Check created cases
    cursor.execute("SELECT id, case_number, title, status FROM cases WHERE title LIKE 'E2E-AUTO-%' ORDER BY created_at DESC LIMIT 1")
    case_row = cursor.fetchone()

    # 2. Check total audit records
    cursor.execute("SELECT COUNT(*) FROM audit_log")
    audit_count = cursor.fetchone()[0]

    # 3. Check engine-level immutability trigger
    trigger_blocked = False
    try:
        cursor.execute("UPDATE audit_log SET action = 'TAMPERED_RECORD' WHERE id = (SELECT id FROM audit_log LIMIT 1)")
        conn.commit()
    except (sqlite3.OperationalError, sqlite3.DatabaseError) as e:
        trigger_blocked = True

    result = {
        "caseFound": bool(case_row),
        "caseData": {
            "id": case_row[0],
            "case_number": case_row[1],
            "title": case_row[2],
            "status": case_row[3]
        } if case_row else None,
        "auditCount": audit_count,
        "triggerBlocked": trigger_blocked
    }

    print(json.dumps(result))
    conn.close()

if __name__ == '__main__':
    main()
