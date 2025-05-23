from flask import Flask, render_template, request
from pysnmp.hlapi import *

app = Flask(__name__)

# Diccionari d'OIDs comuns per al selector del formulari
COMMON_OIDS = {
    'sysDescr': '1.3.6.1.2.1.1.1',
    'sysUpTime': '1.3.6.1.2.1.1.3',
    'sysContact': '1.3.6.1.2.1.1.4',
    'sysName': '1.3.6.1.2.1.1.5',
    'sysLocation': '1.3.6.1.2.1.1.6',
    'ifNumber': '1.3.6.1.2.1.2.1',
    'ifTable': '1.3.6.1.2.1.2.2'
}

# Funcions SNMP
def snmp_get(host, community, oid):
    """Realitza una operació SNMP GET"""
    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((host, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        raise Exception(errorIndication)
    elif errorStatus:
        raise Exception(f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
    else:
        for varBind in varBinds:
            return f'{varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}'

def snmp_next(host, community, oid):
    """Realitza una operació SNMP NEXT"""
    iterator = nextCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((host, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        raise Exception(errorIndication)
    elif errorStatus:
        raise Exception(f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
    else:
        for varBind in varBinds:
            return f'{varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}'

def snmp_set(host, community, oid, value_type, value):
    """Realitza una operació SNMP SET"""
    # Convertir el valor segons el tipus
    if value_type == "Integer":
        val = Integer32(int(value))
    elif value_type in ["String", "OctetString"]:
        val = OctetString(value)
    elif value_type == "ObjectIdentifier":
        val = ObjectIdentifier(value)
    else:
        raise Exception("Tipus de valor no suportat")

    iterator = setCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((host, 161)),
        ContextData(),
        ObjectType(ObjectIdentity(oid), val)
    )

    errorIndication, errorStatus, errorIndex, varBinds = next(iterator)

    if errorIndication:
        raise Exception(errorIndication)
    elif errorStatus:
        raise Exception(f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
    else:
        for varBind in varBinds:
            return f'{varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}'

def snmp_bulkwalk(host, community, oid):
    """Realitza una operació SNMP BULKWALK"""
    results = []
    iterator = bulkCmd(
        SnmpEngine(),
        CommunityData(community),
        UdpTransportTarget((host, 161)),
        ContextData(),
        0, 25,  # non-repeaters, max-repetitions
        ObjectType(ObjectIdentity(oid))
    )

    for errorIndication, errorStatus, errorIndex, varBinds in iterator:
        if errorIndication:
            raise Exception(errorIndication)
        elif errorStatus:
            raise Exception(f'{errorStatus.prettyPrint()} at {errorIndex and varBinds[int(errorIndex) - 1][0] or "?"}')
        else:
            for varBind in varBinds:
                results.append(f'{varBind[0].prettyPrint()} = {varBind[1].prettyPrint()}')

    return '\n'.join(results)

@app.route('/', methods=['GET', 'POST'])
def index():
    result = None
    error = None
    operation_info = None
    sysdescr = None  # Per guardar la descripció del sistema

    if request.method == 'POST':
        try:
            host = request.form.get('host')
            version = request.form.get('version')
            community = request.form.get('community')
            oid = request.form.get('oid')
            operation = request.form.get('operation')

            if not all([host, community, oid, operation]):
                raise Exception("Tots els camps són obligatoris")

            operation_info = {
                'host': host,
                'version': version,
                'community': community,
                'oid': oid,
                'operation': operation
            }

            if operation != 'bulkwalk' and not oid.endswith('.0'):
                oid = f"{oid}.0"
                operation_info['oid'] = oid

            # Si és un SET, afegeix valor i tipus
            if operation == 'set':
                value = request.form.get('value')
                value_type = request.form.get('value_type')
                if not value or not value_type:
                    raise Exception("El valor i el tipus són obligatoris per l'operació SET")
                operation_info['value'] = value
                operation_info['value_type'] = value_type

            # --- OBTENIR sysDescr (sistema operatiu i versió) ---
            try:
                sysdescr = snmp_get(host, community, '1.3.6.1.2.1.1.1.0')
            except Exception as e:
                sysdescr = f"No s'ha pogut obtenir sysDescr: {e}"

            # --- MISSATGE PER LA TERMINAL ---
            print("\n--- Consulta SNMP ---")
            print(f"Dispositiu (IP): {host}")
            print(f"Versió SNMP: {version}")
            print(f"Comunitat: {community}")
            print(f"Operació: {operation.upper()}")
            print(f"OID: {oid}")
            if operation == 'set':
                print(f"Valor: {value}")
                print(f"Tipus de valor: {value_type}")
            print(f"Sistema operatiu (sysDescr): {sysdescr}")
            print("---------------------\n")

            # Executar l'operació SNMP corresponent
            if operation == 'get':
                result = snmp_get(host, community, oid)
            elif operation == 'next':
                result = snmp_next(host, community, oid)
            elif operation == 'set':
                result = snmp_set(host, community, oid, value_type, value)
            elif operation == 'bulkwalk':
                result = snmp_bulkwalk(host, community, oid)

        except Exception as e:
            error = str(e)

    return render_template('index.html',
                         oids=COMMON_OIDS,
                         result=result,
                         error=error,
                         operation_info=operation_info) 

if __name__ == '__main__':
    # Executar l'aplicació en mode debug
    app.run(debug=True)