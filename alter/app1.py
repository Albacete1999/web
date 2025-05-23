from flask import Flask, render_template, request
import asyncio
from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp.smi.rfc1902 import ObjectType, ObjectIdentity
from pysnmp.proto.rfc1902 import Integer, OctetString

app = Flask(__name__)

def process_result(errorIndication, errorStatus, errorIndex, varBinds):
    results = []
    if errorIndication:
        results.append(f"Error: {errorIndication}")
    elif errorStatus:
        results.append(f"{errorStatus.prettyPrint()} at {errorIndex}")
    else:
        for varBind in varBinds:
            results.append(" = ".join([x.prettyPrint() for x in varBind]))
    return results

async def snmp_get(target_ip, port, community, oid, snmp_version):
    snmpEngine = SnmpEngine()
    community_data = CommunityData(community, mpModel=0 if snmp_version == 'v1' else 1)

    iterator = get_cmd(
        snmpEngine,
        community_data,
        await UdpTransportTarget.create((target_ip, port)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = await iterator
    snmpEngine.close_dispatcher()
    return process_result(errorIndication, errorStatus, errorIndex, varBinds)

async def snmp_next(target_ip, port, community, oid, snmp_version):
    snmpEngine = SnmpEngine()
    community_data = CommunityData(community, mpModel=0 if snmp_version == 'v1' else 1)

    iterator = next_cmd(
        snmpEngine,
        community_data,
        await UdpTransportTarget.create((target_ip, port)),
        ContextData(),
        ObjectType(ObjectIdentity(oid))
    )

    errorIndication, errorStatus, errorIndex, varBinds = await iterator
    snmpEngine.close_dispatcher()
    return process_result(errorIndication, errorStatus, errorIndex, varBinds)

async def snmp_set(target_ip, port, community, oid, value, snmp_version):
    snmpEngine = SnmpEngine()
    community_data = CommunityData(community, mpModel=0 if snmp_version == 'v1' else 1)

    iterator = set_cmd(
        snmpEngine,
        community_data,
        await UdpTransportTarget.create((target_ip, port)),
        ContextData(),
        ObjectType(ObjectIdentity(oid), value)
    )

    errorIndication, errorStatus, errorIndex, varBinds = await iterator
    snmpEngine.close_dispatcher()
    return process_result(errorIndication, errorStatus, errorIndex, varBinds)

async def snmp_bulkwalk(target_ip, port, community, oid, snmp_version):
    snmpEngine = SnmpEngine()
    community_data = CommunityData(community, mpModel=0 if snmp_version == 'v1' else 1)
    results = []

    objects = bulk_walk_cmd(
        snmpEngine,
        community_data,
        await UdpTransportTarget.create((target_ip, port)),
        ContextData(),
        0, 25,
        ObjectType(ObjectIdentity(oid)),
        lexicographicMode=False
    )

    try:
        async for errorIndication, errorStatus, errorIndex, varBinds in objects:
            if errorIndication:
                results.append(f"Error: {errorIndication}")
                break
            elif errorStatus:
                results.append(f"{errorStatus.prettyPrint()} at {errorIndex}")
                break
            else:
                for varBind in varBinds:
                    results.append(" = ".join([x.prettyPrint() for x in varBind]))
    finally:
        snmpEngine.close_dispatcher()

    return results

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def handle_form():
    try:
        target_ip = request.form['agent_ip']
        port = 161
        community = request.form['community']
        snmp_version = 'v1' if request.form['version'] == '1' else 'v2c'
        oid = request.form['oid']
        operation = request.form['operation'].upper()
        value = request.form.get('set_value', '')

        if operation == 'SET':
            value_type = request.form['set_type']
            value = OctetString(value) if value_type == 'OctetString' else Integer(int(value))

        if operation != 'BULKWALK' and not oid.endswith('.0'):
            oid += '.0'

        if operation == 'GET':
            result = asyncio.run(snmp_get(target_ip, port, community, oid, snmp_version))
        elif operation == 'NEXT':
            result = asyncio.run(snmp_next(target_ip, port, community, oid, snmp_version))
        elif operation == 'SET':
            result = asyncio.run(snmp_set(target_ip, port, community, oid, value, snmp_version))
        elif operation == 'BULKWALK':
            result = asyncio.run(snmp_bulkwalk(target_ip, port, community, oid, snmp_version))
        else:
            result = ["Operación no válida"]

        return render_template('result.html', result=result, operation=operation)

    except KeyError as e:
        return f"Campo faltante: {e}", 400
    except Exception as e:
        return f"Error: {str(e)}", 500

if __name__ == '__main__':
    app.run(debug=True)