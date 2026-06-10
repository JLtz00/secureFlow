def obtain_val():
    return request.args.get("data")

data = obtain_val()
cursor.execute("SELECT * FROM sessions WHERE token = " + data)
