import os
import sqlite3
import math
from datetime import datetime, timezone

def _get_db(env):
    db_dir = os.path.join(env["STORAGE_ROOT"], "admin")
    os.makedirs(db_dir, exist_ok=True)
    db_path = os.path.join(db_dir, "audit.sqlite")
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            admin_email TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT,
            details TEXT
        )
    """)
    conn.commit()
    return conn

def log_admin_action(email, action, target, details, env):
    conn = _get_db(env)
    try:
        c = conn.cursor()
        timestamp = datetime.now(timezone.utc).isoformat()
        c.execute("""
            INSERT INTO audit_log (timestamp, admin_email, action, target, details)
            VALUES (?, ?, ?, ?, ?)
        """, (timestamp, email, action, target, details))
        conn.commit()
    finally:
        conn.close()

def get_audit_log(page, per_page, action_filter, env):
    conn = _get_db(env)
    try:
        c = conn.cursor()
        
        # Build query filters
        where_clauses = []
        params = []
        
        if action_filter and action_filter.lower() != "all":
            filter_val = action_filter.lower()
            # Check if it's a category
            CATEGORY_MAP = {
                "users": ["user_"],
                "aliases": ["alias_"],
                "spam": ["spam_"],
                "dns": ["dns_"],
                "ssl": ["ssl_"],
                "system": ["system_"],
                "security": ["f2b_", "mfa_"],
            }
            if filter_val in CATEGORY_MAP:
                prefixes = CATEGORY_MAP[filter_val]
                clause = " OR ".join(["action LIKE ?" for _ in prefixes])
                where_clauses.append(f"({clause})")
                for prefix in prefixes:
                    params.append(f"{prefix}%")
            else:
                # Direct match or pattern match
                where_clauses.append("action = ?")
                params.append(action_filter)
                
        where_str = f"WHERE {' AND '.join(where_clauses)}" if where_clauses else ""
        
        # Get total entries count
        count_query = f"SELECT COUNT(*) FROM audit_log {where_str}"  # nosec B608
        c.execute(count_query, params)
        total_entries = c.fetchone()[0]
        
        # Paginated fetch (latest first)
        limit = per_page
        offset = (page - 1) * per_page
        
        query = f"SELECT id, timestamp, admin_email, action, target, details FROM audit_log {where_str} ORDER BY id DESC LIMIT ? OFFSET ?"  # nosec B608
        c.execute(query, params + [limit, offset])
        
        rows = c.fetchall()
        entries = []
        for r in rows:
            entries.append({
                "id": r["id"],
                "timestamp": r["timestamp"],
                "admin_email": r["admin_email"],
                "action": r["action"],
                "target": r["target"],
                "details": r["details"]
            })
            
        total_pages = math.ceil(total_entries / per_page) if total_entries > 0 else 1
        
        return {
            "entries": entries,
            "total_entries": total_entries,
            "total_pages": total_pages,
            "page": page,
            "per_page": per_page
        }
    finally:
        conn.close()
