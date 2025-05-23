from flask import Flask, render_template, request, jsonify
from pysnmp.hlapi import (
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
    getCmd,
    nextCmd,
    bulkCmd,
    setCmd
)
from pysnmp.proto.rfc1902 import OctetString, Integer
from pysnmp.error import PySnmpError
import mysql.connector
import socket
from datetime import datetime
import threading
import sys
from config import DB_CONFIG
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

print(sys.path)

app = Flask(__name__)

# Función helper para la conexión a la base de datos
def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# Nueva ruta para ver los traps
@app.route("/traps")
def view_traps():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Obtener filtros de fecha si existen
    exact_date = request.args.get('exact_date')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    if exact_date:
        query = """
        SELECT trap_id, date_time, transport
        FROM notifications
        WHERE DATE(date_time) = %s
        ORDER BY date_time DESC
        """
        cursor.execute(query, (exact_date,))
    elif start_date and end_date:
        query = """
        SELECT trap_id, date_time, transport
        FROM notifications
        WHERE date_time BETWEEN %s AND %s
        ORDER BY date_time DESC
        """
        cursor.execute(query, (start_date, end_date))
    else:
        query = """
        SELECT trap_id, date_time, transport
        FROM notifications
        ORDER BY date_time DESC
        """
        cursor.execute(query)

    traps = cursor.fetchall()
    cursor.close()
    conn.close()

    return render_template("traps.html", traps=traps)

# Nueva ruta para ver los detalles de un trap específico
@app.route("/trap/<int:trap_id>")
def trap_detail(trap_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Obtener detalles del trap
    cursor.execute("""
        SELECT v.* 
        FROM varbinds v 
        WHERE v.trap_id = %s
    """, (trap_id,))
    
    varbinds = cursor.fetchall()
    cursor.close()
    conn.close()
    
    return render_template("trap_detail.html", varbinds=varbinds, trap_id=trap_id)

# Modificar la ruta existente /snmp para incluir el desplegable de OIDs
@app.route("/", methods=["GET"])
def index():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    
    # Obtener lista de OIDs
    cursor.execute("SELECT oid, traduccion FROM oids")
    oids = cursor.fetchall()
    
    cursor.close()
    conn.close()
    
    return render_template("index.html", oids=oids)

@app.route("/snmp", methods=["POST"])
def snmp():
    try:
        agent_ip = request.form["agent_ip"]
        version = request.form["version"]
        community = request.form["community"]
        oid = request.form["oid"]
        operation = request.form["operation"]
        result = []  # Inicializamos result aquí

        if operation == "get":
            result = snmp_get(agent_ip, community, oid)
        elif operation == "next":
            result = snmp_next(agent_ip, community, oid)
        elif operation == "bulkwalk":
            result = snmp_bulkwalk(agent_ip, community, oid)
        elif operation == "set":
            set_type = request.form.get("set_type", "OctetString")
            set_value = request.form.get("set_value", "")
            result = snmp_set(agent_ip, community, oid, set_value, set_type)
        else:
            result = ["Operación no válida"]

        return render_template("result.html", result=result)

    except Exception as e:
        return render_template("error.html",
                             error_message="Error en la operación SNMP",
                             error_detail=str(e))
    
def snmp_get(ip, community, oid):
    result = []
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        result.append(str(errorIndication))
    elif errorStatus:
        result.append(f'{errorStatus.prettyPrint()} at {errorIndex}')
    else:
        for varBind in varBinds:
            result.append(f'{varBind[0]} = {varBind[1]}')
    return result

def snmp_next(ip, community, oid):
    result = []
    iterator = nextCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid)),
    )
    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)
    if errorIndication:
        result.append(str(errorIndication))
    elif errorStatus:
        result.append(f'{errorStatus.prettyPrint()} at {errorIndex}')
    else:
        for varBind in varBinds:
            result.append(f'{varBind[0]} = {varBind[1]}')
    return result

def snmp_bulkwalk(ip, community, oid):
    result = []
    iterator = bulkCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((ip, 161)),
        ContextData(), 0, 1,
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode = False
    )
    for (errorIndication, errorStatus, errorIndex, varBinds) in iterator:
        if errorIndication:
            result.append(str(errorIndication))
            break
        elif errorStatus:
            result.append(f'{errorStatus.prettyPrint()} at {errorIndex}')
            break
        else:
            for varBind in varBinds:
                result.append(f'{varBind[0]} = {varBind[1]}')
    return result

def snmp_set(ip, community, oid, value, set_type="OctetString"):
    result = []

    # Convertir el valor según el tipo seleccionado
    try:
        if set_type == "Integer":
            snmp_value = Integer(int(value))
        else:  # OctetString por defecto
            snmp_value = OctetString(value)

        iterator = setCmd(
            SnmpEngine(),
            CommunityData(community),
            UdpTransportTarget((ip, 161)),
            ContextData(),
            ObjectType(ObjectIdentity(oid), snmp_value)
        )

        errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

        if errorIndication:
            result.append(f"Error: {errorIndication}")
        elif errorStatus:
            if str(errorStatus) == "noAccess":
                result.append(f"Error: No tens permís per modificar aquest OID ({oid}). Verifica que la comunitat té permisos d'escriptura.")
            else:
                result.append(f"Error: {errorStatus.prettyPrint()} at {errorIndex}")
        else:
            for varBind in varBinds:
                result.append(f'{varBind[0]} = {varBind[1]}')

    except ValueError as e:
        result.append(f"Error: Valor no vàlid per al tipus {set_type}")
    except Exception as e:
        result.append(f"Error inesperat: {str(e)}")

    return result

# Añade estos imports al principio del archivo
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.proto import rfc1902


# ... (el resto de imports y código existente se mantiene igual)

# Añade estas funciones antes del bloque principal

def get_snmp_type(value):
    """Mapea los tipos SNMP a los tipos de la base de datos"""
    type_map = {
        rfc1902.Boolean: 'boolean',
        rfc1902.Integer: 'integer',
        rfc1902.BitString: 'bit',
        rfc1902.OctetString: 'octet',
        rfc1902.Null: 'null',
        rfc1902.ObjectIdentifier: 'oid',
        rfc1902.IpAddress: 'ipaddress',
        rfc1902.Counter32: 'counter',
        rfc1902.Gauge32: 'unsigned',
        rfc1902.TimeTicks: 'timeticks',
        rfc1902.Opaque: 'opaque',
        rfc1902.Counter64: 'counter64'
    }
    return type_map.get(type(value), 'octet')  # Default a octet

def trap_callback(snmp_engine, state_reference, context_engine_id, context_name,
                  var_binds, cb_ctx):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Insertar en notifications
        cursor.execute(
            "INSERT INTO notifications (date_time, transport) VALUES (%s, 'udp')",
            (datetime.now(),)
        )
        trap_id = cursor.lastrowid
        
        # Insertar varbinds
        for oid, value in var_binds:
            snmp_type = get_snmp_type(value)
            # Convertir el valor a binario para BLOB
            value_bytes = str(value).encode('utf-8')
            cursor.execute(
                "INSERT INTO varbinds (trap_id, oid, type, value) VALUES (%s, %s, %s, %s)",
                (trap_id, str(oid), snmp_type, value_bytes)
            )
        
        conn.commit()
        print(f"Trap {trap_id} registrado correctamente")
        
    except Exception as e:
        print(f"Error registrando trap: {str(e)}")
        if conn.is_connected():
            conn.rollback()
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()

def start_trap_listener():
    """Inicia el listener de traps en segundo plano"""
    snmp_engine = engine.SnmpEngine()
    print(snmp_engine)
    try:
        # Intentar abrir el puerto SNMP estándar (162)
        config.addTransport(
            snmp_engine,
            udp.domainName,
            udp.UdpTransport().openServerMode(('0.0.0.0', 162))
        )
        print("✅ Listener SNMP iniciado en puerto UDP 162")
    except Exception as e:
        print(f"❌ Error al abrir puerto UDP 162: {e}")
        print("ℹ️ Intenta ejecutar el script como administrador o usa un puerto alternativo como 10162.")
        
        # Intentar abrir un puerto no privilegiado como fallback
        try:
            config.addTransport(
                snmp_engine,
                udp.domainName,
                udp.UdpTransport().openServerMode(('0.0.0.0', 10162))
            )
            print("✅ Listener SNMP iniciado en puerto UDP 10162 (modo fallback)")
        except Exception as e2:
            print(f"❌ Error también en puerto UDP 10162: {e2}")
            print("🚫 No se pudo iniciar el listener SNMP.")
            return

    
    # Configurar comunidad (SNMPv1/v2c)
    config.addV1System(snmp_engine, 'trap-area', 'public_mp')
    
    # Registrar callback
    ntfrcv.NotificationReceiver(snmp_engine, trap_callback)
    
    # Iniciar dispatcher en un hilo separado
    def run_dispatcher():
        try:
            snmp_engine.transportDispatcher.jobStarted(1)
            snmp_engine.transportDispatcher.runDispatcher()
        except Exception as e:
            print(f"Error en dispatcher: {str(e)}")
    
    threading.Thread(target=run_dispatcher, daemon=True).start()

# Modifica el bloque principal para iniciar el listener
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=2000, debug=True)

    start_trap_listener()  # Iniciar listener de traps
