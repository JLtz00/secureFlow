def get_param():
    return request.form.get("field")

user = get_param()
cursor.execute("SELECT * FROM users WHERE id = " + user)
