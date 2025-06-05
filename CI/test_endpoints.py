import time
import requests
import json
from uuid import UUID


BASE_URL = "http://localhost:1227"
from cassandra.cluster import Cluster
from cassandra.auth import PlainTextAuthProvider


def wipe_db():
    # print("🔁 Connecting to ScyllaDB to truncate all tables in `mma`...")
    
    auth_provider = PlainTextAuthProvider(username='cassandra', password='cassandra')
    cluster = Cluster(['mmapod'], auth_provider=auth_provider, port=9042)
    session = cluster.connect()

    keyspace = 'ci_mma'
    session.set_keyspace(keyspace)

    # Get list of tables in keyspace
    rows = session.execute(f"SELECT table_name FROM system_schema.tables WHERE keyspace_name = '{keyspace}'")
    tables = [row.table_name for row in rows]

    if not tables:
        print("⚠️ No tables found in keyspace 'mma'. Nothing to truncate.")
        return

    for table in tables:
        # print(f"🧹 Truncating table: {table}")
        session.execute(f"TRUNCATE {keyspace}.{table}")

    # print("✅ Database wiped clean.")

    session.shutdown()
    cluster.shutdown()

def run_user_flow(school_name):
    session = requests.Session()
    headers = {"Content-Type": "application/json"}

    user_id = create_school_user(session, school_name)

    login_user(session, school_name)

    venue_id = create_venue(session)
    style_id = create_style(session)
    class_id = create_class(session, venue_id, style_id)

    profile_response = session.get(f"{BASE_URL}/api/user/profile")

    check_class_list(session)
    check_get_students(session, class_id)

    logout_response = session.post(f"{BASE_URL}/api/user/logout")

    failed_profile_response = session.get(f"{BASE_URL}/api/user/profile")
    # print(f"✅ User flow for school '{school_name}' passed.")

def login_user(session: requests.Session, school_name):
    headers = {"Content-Type": "application/json"}

    login_payload = {
        "email": "narsue@"+str(school_name)+".com",
        "password": "Secure123!"
    }
    login_response = session.post(f"{BASE_URL}/api/user/login", json=login_payload, headers=headers)
    for cookie in session.cookies:
        cookie.secure = False
    login_response.raise_for_status()
    data = login_response.json()
    assert data["success"]

def create_school_user(session: requests.Session, school_name):
    headers = {"Content-Type": "application/json"}

    # print("🧑 Creating user...")
    create_payload = {
        "email": "narsue@"+str(school_name)+".com",
        "password": "Secure123!",
        "first_name": "John",
        "surname": str(school_name)
    }
    resp = session.post(f"{BASE_URL}/api/user/create", json=create_payload, headers=headers)
    resp.raise_for_status()
    data = resp.json()
    assert data["success"]
    return data["user_id"]


def check_class_list(session: requests.Session):
    url = f"{BASE_URL}/api/class/get_list"
    resp = session.get(url)
    resp.raise_for_status()
    data = resp.json()
    assert isinstance(data, list), "Expected a list of classes"
    assert len(data) == 1, f"Expected exactly 1 class, got {len(data)}"

def check_get_students(session: requests.Session, class_id):
    url = f"{BASE_URL}/api/class/get_students"
    payload = {
        "class_id": class_id,
        "class_start_ts": 0
    }
    resp = session.post(url, json=payload)
    resp.raise_for_status()
    data = resp.json()
    assert data["success"]

def wait_for_server():
    for _ in range(30):
        try:
            r = requests.get(f"{BASE_URL}/")
            if r.status_code == 200:
                return
        except:
            pass
        time.sleep(1)
    raise Exception("Server did not start in time.")

def create_venue(session: requests.Session):
    url = f"{BASE_URL}/api/venue/create"
    payload = {
        "title": "Main Hall",
        "description": "Spacious venue with mirrors",
        "address": "123 Test St",
        "suburb": "Testville",
        "state": "TS",
        "country": "Testland",
        "postcode": "12345",
        "latitude": None,
        "longitude": None,
        "contact_phone": "555-1234"
    }
    headers = {"Content-Type": "application/json"}
    resp = session.post(url, json=payload, headers=headers)
    # print("Create Venue:", resp.status_code, resp.text)
    resp.raise_for_status()
    data = resp.json()
    assert data["success"] is True
    venue_id = data["class_id"]  # note: your Rust handler returns class_id for venue creation response?
    return venue_id

def create_style(session: requests.Session):
    url = f"{BASE_URL}/api/style/create"
    payload = {
        "title": "Yoga",
        "description": "Relaxing stretching style"
    }
    headers = {"Content-Type": "application/json"}
    resp = session.post(url, json=payload, headers=headers)
    # print("Create Style:", resp.status_code, resp.text)
    resp.raise_for_status()
    data = resp.json()
    assert data["success"] is True
    style_id = data["class_id"]  # same note as above for response key
    return style_id

def create_class(session: requests.Session, venue_id, style_id):
    url = f"{BASE_URL}/api/class/create"
    payload = {
        "title": "Yoga for Beginners",
        "description": "A relaxing yoga class",
        "venue_id": venue_id,
        "style_ids": [style_id],
        "grading_ids": [],  # Assuming empty list for grading_ids if none
        "price": "15.00",
        "publish_mode": 1,
        "capacity": 20,
        "frequency": [
            {
                "frequency": 1,
                "start_date": "2025-06-01",
                "end_date": "2025-06-30",
                "start_time": "10:00:00",
                "end_time": "11:00:00"
            }
        ],
        "notify_booking": False,
        "waiver_id": None
    }
    headers = {"Content-Type": "application/json"}
    resp = session.post(url, json=payload, headers=headers)
    # print("Create Class:", resp.status_code, resp.text)
    resp.raise_for_status()
    data = resp.json()
    assert data["success"] is True
    class_id = data["class_id"]
    return class_id

def get_class(session: requests.Session, class_id: str, expect_success: bool):
    url = f"{BASE_URL}/api/class/get"
    payload = {"class_id": class_id}
    resp = session.post(url, json=payload)
    # print(f"Fetching class {class_id}: {resp.status_code} - {resp.text}")

    if expect_success:
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True
        assert data.get("class")['class_id'] == class_id
    else:
        assert resp.status_code == 200 # or resp.status_code == 400
        data = resp.json()
        assert data.get("success") is False


def get_style(session: requests.Session, style_id: str, expect_success: bool):
    url = f"{BASE_URL}/api/style/get"
    payload = {"style_id": style_id}
    resp = session.post(url, json=payload)
    # print(f"Fetching class {class_id}: {resp.status_code} - {resp.text}")

    if expect_success:
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True
        assert data.get("style")['style_id'] == style_id
    else:
        assert resp.status_code == 200 # or resp.status_code == 400
        data = resp.json()
        assert data.get("success") is False

def get_venue(session: requests.Session, venue_id: str, expect_success: bool):
    url = f"{BASE_URL}/api/venue/get"
    payload = {"venue_id": venue_id}
    resp = session.post(url, json=payload)
    # print(f"Fetching class {class_id}: {resp.status_code} - {resp.text}")

    if expect_success:
        assert resp.status_code == 200
        data = resp.json()
        assert data.get("success") is True
        assert data.get("venue")['venue_id'] == venue_id
    else:
        assert resp.status_code == 200 # or resp.status_code == 400
        data = resp.json()
        assert data.get("success") is False

def test_visibility_across_schools():
    wipe_db()

    s1 = requests.Session()
    s2 = requests.Session()

    class1, venue1, style1 = setup_school_with_class(s1, "school1")
    class2, venue2, style2 = setup_school_with_class(s2, "school2")

    # ✅ Should access their own class
    get_class(s1, class1, expect_success=True)
    get_class(s2, class2, expect_success=True)

    # ❌ Should NOT access the other school's class
    get_class(s1, class2, expect_success=False)
    get_class(s2, class1, expect_success=False)
    print("✅ Class visibility test passed")

    # ✅ Should access their own class
    get_style(s1, style1, expect_success=True)
    get_style(s2, style2, expect_success=True)

    # ❌ Should NOT access the other school's styles
    get_style(s1, style2, expect_success=False)
    get_style(s2, style1, expect_success=False)

    print("✅ Style visibility test passed")


    # ✅ Should access their own class
    get_venue(s1, venue1, expect_success=True)
    get_venue(s2, venue2, expect_success=True)

    # ❌ Should NOT access the other school's styles
    get_venue(s1, venue2, expect_success=False)
    get_venue(s2, venue1, expect_success=False)

    print("✅ Venue visibility test passed")

def setup_school_with_class(session: requests.Session, school_name: str) -> str:
    create_school_user(session, school_name)
    login_user(session, school_name)
    venue_id = create_venue(session)
    style_id = create_style(session)
    return create_class(session, venue_id, style_id), venue_id, style_id

def test_basic_logins_lists_no_cross_access():
    wipe_db()
    run_user_flow("school1")
    run_user_flow("school2")
    print(f"✅ test_basic_logins_lists_no_cross_access passed.")


if __name__ == "__main__":
    wait_for_server()
    test_basic_logins_lists_no_cross_access()
    test_visibility_across_schools()
    

    # seed_db()
    # test_endpoint_security()
