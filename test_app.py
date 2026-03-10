from app import app


def test_index():
    with app.test_client() as client:
        response = client.get("/")
        assert response.status_code == 200
        assert "Bienvenue sur l'API Secure Task" in response.get_data(as_text=True)


def test_health():
    with app.test_client() as client:
        response = client.get("/health")
        assert response.status_code == 200
        assert response.get_json()["status"] == "ok"


def test_get_tasks():
    with app.test_client() as client:
        response = client.get("/tasks")
        assert response.status_code == 200
        assert isinstance(response.get_json(), list)


def test_add_task():
    with app.test_client() as client:
        response = client.post(
            "/tasks",
            json={"title": "Écrire des tests"},
        )
        assert response.status_code == 201
        assert response.get_json()["title"] == "Écrire des tests"


def test_add_task_without_title():
    with app.test_client() as client:
        response = client.post(
            "/tasks",
            json={},
        )
        assert response.status_code == 400
