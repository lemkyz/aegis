import sqlite3


def get_user(user_id):
    db = sqlite3.connect("app.db")
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query).fetchone()
