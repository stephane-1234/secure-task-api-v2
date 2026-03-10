from flask import Flask, jsonify, request

app = Flask(__name__)

tasks = [
    {"id": 1, "title": "Apprendre Jenkins", "done": False},
    {"id": 2, "title": "Ajouter un pipeline DevSecOps", "done": False},
]


@app.route("/")
def index():
    return "Bienvenue sur l'API Secure Task! Utilisez /tasks pour voir les tâches.", 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/tasks", methods=["GET"])
def get_tasks():
    return jsonify(tasks), 200


@app.route("/tasks", methods=["POST"])
def add_task():
    data = request.get_json()

    if not data or "title" not in data:
        return jsonify({"error": "Le champ 'title' est requis"}), 400

    new_task = {
        "id": len(tasks) + 1,
        "title": data["title"],
        "done": False,
    }

    tasks.append(new_task)
    return jsonify(new_task), 201


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000)
