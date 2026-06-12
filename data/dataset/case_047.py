def obtain_val():
    return request.args.get("data")

val = obtain_val()
cursor.execute("SELECT * FROM sessions WHERE token = " + val)
