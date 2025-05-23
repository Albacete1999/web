import sys
import puresnmp

def test_snmp():
    try:
        print("Iniciando prueba SNMP...")

        # Configuración
        ip = '192.168.199.11'
        community = 'public'
        oid = '1.3.6.1.2.1.1.1.0'  # System Description

        print(f"Configuración:")
        print(f"- IP: {ip}")
        print(f"- Comunidad: {community}")
        print(f"- OID: {oid}")

        print("\nRealizando consulta SNMP...")
        result = puresnmp.get(ip, community, oid, timeout=2)

        print(f"\nRespuesta recibida:")
        print(f"Valor: {result}")

    except ConnectionError as ce:
        print(f"\nError de conexión: No se pudo conectar con el dispositivo.")
        print(f"Detalles: {str(ce)}")
        print("\nVerifica:")
        print("1. Que la IP sea correcta")
        print("2. Que el dispositivo esté encendido")
        print("3. Que el servicio SNMP esté activo")
        print("4. Que no haya un firewall bloqueando el puerto 161/UDP")
    except Exception as e:
        print(f"\nError: {str(e)}")
        print(f"Tipo de error: {type(e).__name__}")
        import traceback
        print("\nTraceback:")
        traceback.print_exc()

if __name__ == "__main__":
    print("Versión de Python:", sys.version)
    try:
        print("Versión de puresnmp:", puresnmp.__version__)
    except:
        print("No se pudo determinar la versión de puresnmp")

    print("\nIniciando prueba de conexión SNMP...")
    test_snmp()