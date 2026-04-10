import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app import create_app
import app.routes as routes


class _FakeResult:
    def __init__(self, data):
        self.data = data


class _FakeQuery:
    def __init__(self, client, table_name):
        self._client = client
        self._table_name = table_name
        self._filters = {}
        self._limit = None
        self._pending_insert = None

    def select(self, *_args, **_kwargs):
        return self

    def eq(self, key, value):
        self._filters[key] = value
        return self

    def limit(self, _value):
        self._limit = _value
        return self

    def insert(self, payload):
        self._pending_insert = payload
        return self

    def update(self, _payload):
        self._pending_update = _payload
        return self

    def order(self, *_args, **_kwargs):
        return self

    def in_(self, *_args, **_kwargs):
        return self

    def execute(self):
        if self._table_name == 'users':
            user_id = self._filters.get('id')
            row = self._client.users.get(user_id)
            return _FakeResult([row] if row else [])

        if self._table_name == 'incidents':
            if self._pending_insert is not None:
                incident = {
                    'id': '99999999-9999-9999-9999-999999999999',
                    **self._pending_insert,
                }
                self._client.incidents.append(incident)
                return _FakeResult([incident])

            if hasattr(self, '_pending_update'):
                incident_id = self._filters.get('id')
                for incident in self._client.incidents:
                    if incident.get('id') == incident_id:
                        incident.update(self._pending_update)
                        return _FakeResult([incident])
                return _FakeResult([])

            rows = list(self._client.incidents)
            if self._filters.get('id'):
                rows = [item for item in rows if item.get('id') == self._filters.get('id')]
            if self._filters.get('org_id'):
                rows = [item for item in rows if item.get('org_id') == self._filters.get('org_id')]
            if self._limit is not None:
                rows = rows[:self._limit]
            return _FakeResult(rows)

        if self._table_name == 'tasks':
            if self._pending_insert is not None:
                task = {
                    'id': '77777777-7777-7777-7777-777777777777',
                    **self._pending_insert,
                }
                self._client.tasks.append(task)
                return _FakeResult([task])

            if hasattr(self, '_pending_update'):
                task_id = self._filters.get('id')
                for task in self._client.tasks:
                    if task.get('id') == task_id:
                        task.update(self._pending_update)
                        return _FakeResult([task])
                return _FakeResult([])

            rows = list(self._client.tasks)
            if self._filters.get('id'):
                rows = [item for item in rows if item.get('id') == self._filters.get('id')]
            if self._filters.get('org_id'):
                rows = [item for item in rows if item.get('org_id') == self._filters.get('org_id')]
            if self._filters.get('incident_id'):
                rows = [item for item in rows if item.get('incident_id') == self._filters.get('incident_id')]
            if self._filters.get('status'):
                rows = [item for item in rows if item.get('status') == self._filters.get('status')]
            if self._limit is not None:
                rows = rows[:self._limit]
            return _FakeResult(rows)

        if self._table_name == 'feedback':
            if self._pending_insert is not None:
                feedback = {
                    'id': '66666666-6666-6666-6666-666666666666',
                    'created_at': '2026-04-08T12:00:00Z',
                    **self._pending_insert,
                }
                self._client.feedback.append(feedback)
                return _FakeResult([feedback])

            rows = list(self._client.feedback)
            if self._filters.get('id'):
                rows = [item for item in rows if item.get('id') == self._filters.get('id')]
            if self._filters.get('org_id'):
                rows = [item for item in rows if item.get('org_id') == self._filters.get('org_id')]
            if self._limit is not None:
                rows = rows[:self._limit]
            return _FakeResult(rows)

        return _FakeResult([])


class _FakeAuth:
    def __init__(self, token_to_user_id):
        self._token_to_user_id = token_to_user_id

    def get_user(self, token):
        user_id = self._token_to_user_id.get(token)
        if not user_id:
            raise ValueError('invalid token')
        return {'user': {'id': user_id}}


class _FakeSupabaseClient:
    def __init__(self, users, token_to_user_id, incidents):
        self.users = users
        self.incidents = incidents
        self.tasks = [
            {
                'id': 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
                'org_id': '11111111-1111-1111-1111-111111111111',
                'incident_id': '88888888-8888-8888-8888-888888888888',
                'assignee_id': '00000000-0000-0000-0000-000000000002',
                'title': 'Collect endpoint logs',
                'status': 'pending',
            }
        ]
        self.feedback = [
            {
                'id': 'bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb',
                'org_id': '11111111-1111-1111-1111-111111111111',
                'summary_id': None,
                'user_id': '00000000-0000-0000-0000-000000000001',
                'rating': 4,
                'suggestion_text': 'More detail on the timeline would help.',
                'created_at': '2026-04-08T11:30:00Z',
            }
        ]
        self.auth = _FakeAuth(token_to_user_id)

    def table(self, table_name):
        return _FakeQuery(self, table_name)


@pytest.fixture
def client(monkeypatch):
    os.environ.setdefault('SUPABASE_URL', 'http://localhost:54321')
    os.environ.setdefault('SUPABASE_SERVICE_ROLE_KEY', 'test-service-key')

    flask_app = create_app()
    flask_app.config['TESTING'] = True

    fake_users = {
        '00000000-0000-0000-0000-000000000001': {
            'id': '00000000-0000-0000-0000-000000000001',
            'org_id': '11111111-1111-1111-1111-111111111111',
            'role': 'viewer',
        },
        '00000000-0000-0000-0000-000000000002': {
            'id': '00000000-0000-0000-0000-000000000002',
            'org_id': '11111111-1111-1111-1111-111111111111',
            'role': 'analyst',
        },
    }
    token_map = {
        'viewer-token': '00000000-0000-0000-0000-000000000001',
        'analyst-token': '00000000-0000-0000-0000-000000000002',
    }

    fake_incidents = [
        {
            'id': '88888888-8888-8888-8888-888888888888',
            'org_id': '11111111-1111-1111-1111-111111111111',
            'title': 'Unauthorized login chain',
            'status': 'open',
            'severity': 'high',
        }
    ]

    fake_supabase = _FakeSupabaseClient(users=fake_users, token_to_user_id=token_map, incidents=fake_incidents)
    monkeypatch.setattr(routes, 'supabase_client', fake_supabase)

    return flask_app.test_client()


def test_cross_org_access_denied_for_viewer(client):
    response = client.get(
        '/timeline/org/22222222-2222-2222-2222-222222222222',
        headers={'Authorization': 'Bearer viewer-token'},
    )

    assert response.status_code == 403
    payload = response.get_json()
    assert payload['error']['message'] == 'Cross-organization access denied'


def test_viewer_denied_write_endpoint(client):
    response = client.post(
        '/upload-sessions/init',
        json={
            'org_id': '11111111-1111-1111-1111-111111111111',
            'filename': 'demo.csv',
            'source_type': 'custom',
            'total_parts': 1,
        },
        headers={'Authorization': 'Bearer viewer-token'},
    )

    assert response.status_code == 403
    payload = response.get_json()
    assert payload['error']['message'] == 'Insufficient role permissions for this endpoint'


def test_analyst_denied_admin_model_endpoint(client):
    response = client.post(
        '/rf/train',
        json={
            'org_id': '11111111-1111-1111-1111-111111111111',
            'dataset_path': '/tmp/fake.csv',
        },
        headers={'Authorization': 'Bearer analyst-token'},
    )

    assert response.status_code == 403
    payload = response.get_json()
    assert payload['error']['message'] == 'Insufficient role permissions for this endpoint'


def test_viewer_can_read_incidents(client):
    response = client.get(
        '/incidents?org_id=11111111-1111-1111-1111-111111111111',
        headers={'Authorization': 'Bearer viewer-token'},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload['items']) == 1


def test_analyst_can_create_incident(client):
    response = client.post(
        '/incidents',
        json={
            'org_id': '11111111-1111-1111-1111-111111111111',
            'title': 'Suspicious lateral movement',
            'severity': 'high',
            'status': 'open',
        },
        headers={'Authorization': 'Bearer analyst-token'},
    )

    assert response.status_code == 201
    payload = response.get_json()
    assert payload['incident']['title'] == 'Suspicious lateral movement'


def test_viewer_can_read_tasks(client):
    response = client.get(
        '/tasks?org_id=11111111-1111-1111-1111-111111111111',
        headers={'Authorization': 'Bearer viewer-token'},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload['items']) == 1
    assert payload['items'][0]['title'] == 'Collect endpoint logs'


def test_analyst_can_update_incident_status(client):
    response = client.patch(
        '/incidents/88888888-8888-8888-8888-888888888888',
        json={'status': 'resolved'},
        headers={'Authorization': 'Bearer analyst-token'},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload['incident']['status'] == 'resolved'


def test_viewer_can_submit_feedback(client):
    response = client.post(
        '/feedback',
        json={
            'org_id': '11111111-1111-1111-1111-111111111111',
            'rating': 5,
            'suggestion_text': 'Add one-click incident promotion from findings.',
        },
        headers={'Authorization': 'Bearer viewer-token'},
    )

    assert response.status_code == 201
    payload = response.get_json()
    assert payload['feedback']['rating'] == 5


def test_viewer_can_read_feedback(client):
    response = client.get(
        '/feedback?org_id=11111111-1111-1111-1111-111111111111',
        headers={'Authorization': 'Bearer viewer-token'},
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert len(payload['items']) >= 1
