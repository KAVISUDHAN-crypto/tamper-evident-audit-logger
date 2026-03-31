# demo.py
from log_store import create_db
from tamper_log import add_log_entry, verify_log_chain

DB = "audit_log.db"


def main():
    # 1. Create the DB (run once)
    create_db(DB)

    # 2. Add some test entries
    add_log_entry(DB, "LOGIN_ATTEMPT", "User 'alice' tried to log in from 192.168.1.100")
    add_log_entry(DB, "TRANSACTION", "Transferred 500 INR from acc123 to acc456")
    add_log_entry(DB, "USER_ACTIVITY", "Admin viewed audit logs")

    # 3. Verify integrity
    ok, bad_ids = verify_log_chain(DB)
    if ok:
        print("[✓] Log chain integrity verified; no tampering detected.")
    else:
        print(f"[✗] Tampering detected around IDs: {bad_ids}")


if __name__ == "__main__":
    main()
