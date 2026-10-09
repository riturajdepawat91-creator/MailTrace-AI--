import pathlib
import tempfile

import database.database as db


def test_soc_routing():
    original = db.DATABASE_PATH
    temp_db = pathlib.Path(tempfile.mktemp(suffix='.db'))
    db.DATABASE_PATH = temp_db
    try:
        db.initialize_database()
        db.initialize_soc_routing()
        conn = db.get_connection()
        conn.execute("INSERT INTO cases(case_id,title,status) VALUES(?,?,?)", ("CASE-REGION", "Regional", "OPEN"))
        conn.execute("INSERT INTO cases(case_id,title,status) VALUES(?,?,?)", ("CASE-FALLBACK", "Fallback", "OPEN"))
        conn.commit()
        conn.close()

        db.configure_soc_queue("tenant-test", "NORTH-SOC", "North SOC", "NORTH")
        db.configure_employee_region("tenant-test", "employee-1", "NORTH")
        db.configure_soc_analyst("tenant-test", "analyst-1", "NORTH", max_open_cases=2)

        routed = db.route_case_to_soc("CASE-REGION", "tenant-test", "employee-1")
        assert routed["queue_id"] == "NORTH-SOC"
        assert routed["assigned_analyst"] == "analyst-1"
        assert routed["status"] == "ASSIGNED"

        fallback = db.route_case_to_soc("CASE-FALLBACK", "tenant-test", "employee-without-region")
        assert fallback["queue_id"] == "CENTRAL"
        assert fallback["region_key"] == "CENTRAL"
        assert fallback["status"] == "FALLBACK"

        print("Regional routing: PASS")
        print("Central fallback: PASS")
        print("SOC routing tests: PASS")
    finally:
        db.DATABASE_PATH = original
        temp_db.unlink(missing_ok=True)


if __name__ == "__main__":
    test_soc_routing()
