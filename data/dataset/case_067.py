def obtain_val():
    return request.form.get("data")

param = obtain_val()
cursor.execute("SELECT * FROM sessions WHERE token = " + param)
