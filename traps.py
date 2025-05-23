import pymysql
import datetime
import random

def insertar_en_bd(trap_data):
    conn = pymysql.connect(
        host='localhost',
        user='Alex_Sohaib',
        password='1234',
        db='mib_browser_Alex_Sohaib',
        charset='utf8mb4',
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        with conn.cursor() as cursor:
            for trap in trap_data:
                cursor.execute("""
                    INSERT INTO notifications (date_time, host, auth, type, version, request_id, snmpTrapOID, transport, security_model)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    trap['date_time'], trap['host'], trap['auth'], trap['type'],
                    trap['version'], trap['request_id'], trap['snmpTrapOID'],
                    trap['transport'], trap['security_model']
                ))
                trap_id = conn.insert_id()

                for vb in trap['varbinds']:
                    cursor.execute("""
                        INSERT INTO varbinds (trap_id, oid, type, value)
                        VALUES (%s, %s, %s, %s)
                    """, (trap_id, vb['oid'], vb['type'], vb['value']))

        conn.commit()
    finally:
        conn.close()

# Generación artificial de traps
def generar_traps(n=30):
    hosts = [f"192.168.1.{i}" for i in range(1, 11)]
    comunidades = ['publicSA', 'testCommunity']
    mensajes = ['Todo bien', 'Error crítico', 'Fallo en interfaz', 'Reinicio', 'Alerta de temperatura']
    tipos_varbind = ['octet', 'integer', 'oid', 'counter']

    traps = []
    for _ in range(n):
        mensaje = random.choice(mensajes)
        varbinds = []
        for _ in range(random.randint(1, 3)):
            tipo = random.choice(tipos_varbind)
            valor = mensaje.encode('utf-8') if tipo == 'octet' else str(random.randint(1, 100)).encode('utf-8')
            varbinds.append({
                'oid': f"1.3.6.1.2.1.1.{random.randint(1,10)}.0",
                'type': tipo,
                'value': valor
            })

        traps.append({
            'date_time': datetime.datetime.now(),
            'host': random.choice(hosts),
            'auth': random.choice(comunidades),
            'type': 'trap',
            'version': 'v2c',
            'request_id': random.randint(1000, 9999),
            'snmpTrapOID': f"1.3.6.1.4.1.8072.9999.9999.{random.randint(1,5)}",
            'transport': 'UDP',
            'security_model': 'snmpV2c',
            'varbinds': varbinds
        })
    return traps

# Ejecutar
if __name__ == "__main__":
    traps = generar_traps()
    insertar_en_bd(traps)
    print("Se insertaron 30 traps artificiales correctamente.")
