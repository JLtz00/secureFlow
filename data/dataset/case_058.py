def get_param():
    return request.form.get("field")

uid = get_param()
cursor.execute("SELECT * FROM users WHERE id = " + uid)
