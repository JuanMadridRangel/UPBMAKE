import requests
import pandas as pd

# Configuración
OCTOPRINT_URL = "http://10.37.48.82/maker5/api"
API_KEY = "DBD040687D844D36A948247CA5451EE1"
archivo_excel = r"C:\Users\000092114\Documents\UPBMAKE\userSync\usuarios.xlsx"

# Definir el usuario que NO debe ser degradado ni eliminado
USUARIO_BLOQUEADO = "tmwhite"

# Cargar Excel
df = pd.read_excel(archivo_excel)

# Función para normalizar roles
def normalizar_roles(perfil, username):
    perfil = str(perfil).strip().lower()

    if username == USUARIO_BLOQUEADO:
        return ["admins", "users"]

    if perfil == "admin":
        return ["admins", "users"]
    elif perfil == "operator":
        return ["users"]
    else:
        print(f"Advertencia: perfil inválido para usuario '{username}': '{perfil}'. Usuario ignorado.")
        return None

# Crear diccionario de usuarios válidos
usuarios_excel = {}
for _, row in df.iterrows():
    username = str(row["Usuario"]).strip()
    password = str(row["Password"])
    roles = normalizar_roles(row["Perfil"], username)
    if roles:
        usuarios_excel[username] = {
            "password": password,
            "roles": roles
        }

# Obtener usuarios actuales
headers = {"X-Api-Key": API_KEY}
resp = requests.get(f"{OCTOPRINT_URL}/users", headers=headers)

if resp.status_code == 200:
    usuarios_octoprint = {
        user["name"]: {"roles": user["groups"]}
        for user in resp.json()["users"]
    }

    # Crear nuevos usuarios
    for username, data in usuarios_excel.items():
        if username not in usuarios_octoprint:
            print(f"Creando usuario: {username}")
            new_data = {
                "name": username,
                "password": data["password"],
                "roles": data["roles"],
                "active": True
            }
            r = requests.post(f"{OCTOPRINT_URL}/users", json=new_data, headers=headers)
            if r.status_code == 201:
                print(f"Usuario {username} creado.")
            else:
                print(f"Error al crear {username}: {r.text}")

    # Actualizar usuarios existentes
    for username, data in usuarios_excel.items():
        if username in usuarios_octoprint:
            roles_actuales = set(usuarios_octoprint[username]["roles"])
            roles_deseados = set(data["roles"])

            if roles_actuales != roles_deseados:
                if username == USUARIO_BLOQUEADO and "admins" not in data["roles"]:
                    print(f"Usuario protegido '{username}' no se puede degradar.")
                    continue
                print(f"Modificando roles de: {username}")
                update_data = {
                    "password": data["password"],
                    "roles": data["roles"]
                }
                r = requests.put(f"{OCTOPRINT_URL}/users/{username}", json=update_data, headers=headers)
                if r.status_code == 204:
                    print(f"Usuario {username} actualizado.")
                else:
                    print(f"Error al actualizar {username}: {r.text}")

    # Eliminar usuarios no presentes en Excel (excepto protegidos)
    for username in usuarios_octoprint:
        if username not in usuarios_excel and username != USUARIO_BLOQUEADO:
            print(f"Eliminando usuario: {username}")
            r = requests.delete(f"{OCTOPRINT_URL}/users/{username}", headers=headers)
            if r.status_code == 204:
                print(f"Usuario {username} eliminado.")
            else:
                print(f"Error al eliminar {username}: {r.text}")
        elif username == USUARIO_BLOQUEADO:
            print(f"Usuario protegido '{username}' no se puede eliminar.")

else:
    print(f"Error al obtener la lista de usuarios: {resp.status_code} - {resp.text}")

print("Sincronización finalizada.")
