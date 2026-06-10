val = request.form.get("data")
prefix = "SELECT * FROM sessions WHERE token = "
query = prefix + val
cursor.execute(query)
