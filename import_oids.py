import mysql.connector

mydb = mysql.connector.connect(
    host = "localhost",
    user = "Alex_Sohaib",
    password = "1234",
    database = "mib_browser_Alex_Sohaib"
)

cursorObject = mydb.cursor()

delete_oid = "DELETE FROM oids"
cursorObject.execute(delete_oid)

add_oid = ("INSERT INTO oids "
           "(traduccion, oid) "
           "VALUES (%s, %s)")

inserted = 0

with open("oid.txt", "r", encoding="latin1") as file:
    for line_number, line in enumerate(file, 1):
        line = line.strip()
        if not line:
            continue
        # Separar usando la comilla como delimitador
        parts = line.split('"')
        # parts[0] es vacío, parts[1] es traduccion, parts[2] es espacios, parts[3] es oid
        if len(parts) < 4:
            print(f"Línea {line_number} malformada: {line}")
            continue
        traduccion = parts[1]
        oid = parts[3]
        cursorObject.execute(add_oid, (traduccion, oid))
        inserted += 1

mydb.commit()
cursorObject.close()
mydb.close()
print(f"Importación completada correctamente. Filas insertadas: {inserted}")