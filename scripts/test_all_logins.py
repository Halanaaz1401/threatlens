import urllib.request
import json

base_url = 'http://127.0.0.1:8000/api/v1/auth/login'
users = ['admin_user@threatlens.io', 'engineer_user@threatlens.io', 'analyst_user@threatlens.io', 'viewer_user@threatlens.io']

for u in users:
    req = urllib.request.Request(
        base_url,
        data=json.dumps({'email': u, 'password': 'RoleTestPass!123'}).encode('utf-8'),
        headers={'Content-Type': 'application/json'}
    )
    try:
        res = urllib.request.urlopen(req)
        body = json.loads(res.read().decode('utf-8'))
        print(f"SUCCESS: {u} -> role={body['role']}")
    except Exception as e:
        print(f"FAILED: {u} -> {e}")
