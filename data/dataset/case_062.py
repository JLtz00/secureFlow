def obtain_val():
    return request.args.get("data")

entry = obtain_val()
cursor.execute("SELECT * FROM sessions WHERE token = " + entry)
