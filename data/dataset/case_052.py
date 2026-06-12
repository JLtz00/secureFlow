def obtain_val():
    return request.form.get("data")

name = obtain_val()
cursor.execute("SELECT * FROM sessions WHERE token = " + name)
