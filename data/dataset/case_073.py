def get_param():
    return request.form.get("field")

name = get_param()
cursor.execute("SELECT * FROM users WHERE id = " + name)
