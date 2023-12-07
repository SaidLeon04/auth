import fastapi
import sqlite3
import random
import hashlib
import datetime
from fastapi import Depends
from fastapi.security import HTTPBasic
from fastapi.security import HTTPBearer
from fastapi.security import  HTTPBasicCredentials
from fastapi.security import HTTPAuthorizationCredentials

app = fastapi.FastAPI()

securityBearer = HTTPBearer()
@app.get("/")
def auth(credentials: HTTPAuthorizationCredentials = Depends(securityBearer)):
    """Autenticación"""
    token = credentials.credentials
    connx = sqlite3.connect("base.bd")
    c = connx.cursor()
    c.execute('SELECT token FROM usuarios WHERE token = ?', (token,))
    existe = c.fetchone()
    if existe is  None:
        raise fastapi.HTTPException(status_code=401, detail="No autorizado")
    else:
        c.execute('SELECT timestamp FROM usuarios WHERE token = ?',(token,))
        for row in c:
            hora_bd = row[0]

        hora_actual = datetime.datetime.now()
        hora_hash = hora_actual.strftime("%H:%M")

        if hora_bd != hora_hash:
            raise fastapi.HTTPException(status_code=430, detail="Token Caducado")
        else:
            return {"mensaje: Bienvenido"}
        
    
security = HTTPBasic()
@app.get("/token") # endpoint para obtener token
def validate_user(credentials: HTTPBasicCredentials = Depends(security)): 
    """Validación de usuario"""
    username = credentials.username # se obtiene el username
    password = credentials.password # se obtiene el password
    hashpassword = hashlib.sha256(password.encode()).hexdigest() # se hashea el password

    connx = sqlite3.connect("base.bd") # conecta a la base de datos
    c = connx.cursor() # crea un cursor

    hora_actual = datetime.datetime.now() # obtiene la hora actual
    hora_actual_formateada = hora_actual.strftime("%H:%M") # formatea la hora actual


    caracteres = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789()=+-*/@#$%&!?' # caracteres para generar el token
    longitud = 8 # longitud del token
    token = '' # variable para almacenar el token
    for i in range(longitud): # ciclo para generar el token
        token += random.choice(caracteres) # se agrega un caracter aleatorio al token
        
    hashtoken = hashlib.sha256(token.encode()).hexdigest() # se hashea el token
    # actualiza el token y la hora en la base de datos
    c.execute('UPDATE usuarios SET token = ?, timestamp = ? WHERE correo = ? AND password = ?', (hashtoken, hora_actual_formateada, username, hashpassword))
    connx.commit() # ejecuta la actualizacion

    c.execute('SELECT token FROM usuarios WHERE correo = ? AND password = ?', (username, hashpassword)) 
    existe = c.fetchone()
    if existe is None: 
        raise fastapi.HTTPException(status_code=401, detail="No autorizado")
    else:
        token = existe[0]
        return {"token":token}

    
    
    