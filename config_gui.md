# Configurador de Red y Recursos Compartidos

Este script en Python utiliza **customtkinter** para proporcionar una interfaz gráfica moderna, responsiva y organizada. Permite configurar distintos aspectos del sistema, tales como:

- **Configuración de red:** Establecer IP fija o usar DHCP, definir máscara, puerta de enlace y DNS.
- **Compartir carpeta:** Seleccionar una carpeta y compartirla en la red con permisos para todos.
- **Hacer ping:** Realizar pruebas de conectividad a una IP, ya sea seleccionada de la red local o ingresada manualmente.
- **Acceso sin contraseña:** Activar la configuración para permitir el acceso a recursos compartidos sin requerir contraseña, mediante la modificación del servicio FDResPub y ajustes de registro.

## Características

- **Interfaz gráfica responsiva:** Utiliza customtkinter para un diseño moderno y adaptable al redimensionar la ventana.
- **Secciones exclusivas:** Solo se muestra la sección activa (Red, Carpeta, Ping o Acceso); al seleccionar una, las demás se deseleccionan automáticamente.
- **Configuración persistente:** Los valores se guardan en un archivo `config.txt`, permitiendo la persistencia de datos entre ejecuciones.
- **Ejecución con privilegios de administrador:** Algunas funciones requieren permisos elevados; el script intentará reiniciarse con dichos privilegios si es necesario.

## Requisitos

- **Python 3.6 o superior**
- **customtkinter:** Instálalo con:
  ```bash
  pip install customtkinter
  ```
- **Permisos de administrador:** Necesarios para ejecutar funciones de configuración de red y compartición de carpetas.

## Uso

1. **Ejecutar el script:**
   - Desde la terminal como administrador:
     ```bash
     python config_gui.py
     ```
   - O como `.exe`, ejecutándolo como administrador.

2. **Seleccionar una opción:**
   - Checkboxes disponibles: **Red**, **Carpeta**, **Ping**, **Acceso**.
   - Al hacer clic en uno, los demás se deseleccionan y se muestra la interfaz correspondiente.

3. **Aplicar configuraciones:**
   - **Red:** Completa los campos o deja la IP vacía o con `-` para usar DHCP. Haz clic en "Aplicar configuración".
   - **Carpeta:** Selecciona una carpeta y presiona "Compartir".
   - **Ping:** Selecciona o ingresa una IP y presiona "Ping".
   - **Acceso:** Presiona "Activar acceso" para permitir acceso sin contraseña.

## Consideraciones

- **Administrador:** Ejecutar como administrador es obligatorio para que el script funcione correctamente.
- **Windows:** Diseñado para sistemas operativos Windows.

## Archivo `config.txt`

Se genera automáticamente junto al script si no existe. Almacena la configuración de red persistente.

### Estructura del archivo
```
IP=192.168.1.100
MASK=255.255.255.0
GATEWAY=192.168.1.1
DNS=8.8.8.8
```

> Si el campo IP está vacío o con `-`, se aplicará configuración DHCP.

## Contribuciones

¡Sugerencias y mejoras son bienvenidas! Puedes abrir un issue o enviar un pull request.

---

¡Disfruta de la configuración automatizada con una interfaz moderna!

