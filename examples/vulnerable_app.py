def get_user(user_id):
    db = sqlite3.connect("app.db")
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,)).fetchone()