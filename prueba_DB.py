import mysql.connector
from aaa.config import DB_CONFIG

try:
    conn = mysql.connector.connect(**DB_CONFIG)
    print("Conexión exitosa a la base de datos!")
    conn.close()
except mysql.connector.Error as err:
    print(f"Error al conectar a la base de datos: {err}")