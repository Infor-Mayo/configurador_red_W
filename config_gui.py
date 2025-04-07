import os
import subprocess
import ctypes
import socket
import ipaddress
import tkinter.messagebox as messagebox
import customtkinter as ctk

ctk.set_appearance_mode("System")
ctk.set_default_color_theme("blue")

CONFIG_FILE = "config.txt"
DEFAULT_CONFIG = {
    "ip": "-",
    "mascara": "255.255.255.0",
    "puerta_enlace": "192.168.1.1",
    "dns": "8.8.8.8",
    "carpeta": os.path.join(os.getcwd(), "carpeta_compartida")
}

def leer_configuracion():
    if not os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE, "w") as f:
            for clave, valor in DEFAULT_CONFIG.items():
                f.write(f"{clave}={valor}\n")
    config = DEFAULT_CONFIG.copy()
    with open(CONFIG_FILE, "r") as f:
        for linea in f:
            if '=' in linea:
                clave, valor = linea.strip().split("=", 1)
                config[clave] = valor
    return config

def guardar_configuracion(config):
    with open(CONFIG_FILE, "w") as f:
        for clave, valor in config.items():
            f.write(f"{clave}={valor}\n")

def configurar_red(ip, mascara, puerta_enlace, dns):
    if ip.strip() == "-" or ip.strip() == "":
        subprocess.call("netsh interface ip set address name=\"Ethernet\" source=dhcp", shell=True)
        subprocess.call("netsh interface ip set dns name=\"Ethernet\" source=dhcp", shell=True)
        return
    subprocess.call(f"netsh interface ip set address name=\"Ethernet\" static {ip} {mascara} {puerta_enlace}", shell=True)
    subprocess.call(f"netsh interface ip set dns name=\"Ethernet\" static {dns}", shell=True)

def crear_carpeta_y_compartir(ruta):
    if not os.path.exists(ruta):
        os.makedirs(ruta)
    subprocess.call(f'net share Compartida="{ruta}" /GRANT:everyone,FULL', shell=True)

def hacer_ping(ip):
    resultado = subprocess.call(f"ping -n 1 {ip}", shell=True)
    return resultado == 0

def obtener_ips_red_local():
    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)
    red = ipaddress.ip_network(local_ip + '/24', strict=False)
    return [str(ip) for ip in red.hosts() if str(ip) != local_ip]

def activar_acceso_sin_contrasena():
    subprocess.call('sc config FDResPub start= auto', shell=True)
    subprocess.call('net start FDResPub', shell=True)
    subprocess.call('net config server /autodisconnect:-1', shell=True)
    subprocess.call('net user guest /active:yes', shell=True)
    subprocess.call('net share Compartida /grant:everyone,full', shell=True)
    subprocess.call('reg add "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa" /v "LimitBlankPasswordUse" /t REG_DWORD /d 0 /f', shell=True)

# Interfaz
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Configurador de Red y Compartición")
        self.geometry("850x550")
        self.grid_columnconfigure((0,1), weight=1)
        self.grid_rowconfigure((0,1,2,3,4), weight=1)

        self.config_data = leer_configuracion()

        # Variables para las opciones (usaremos BooleanVar para cada checkbox)
        self.var_red = ctk.BooleanVar(value=False)
        self.var_carpeta = ctk.BooleanVar(value=False)
        self.var_ping = ctk.BooleanVar(value=False)
        self.var_acceso = ctk.BooleanVar(value=False)
        self.opcion = ctk.StringVar(value="")  # Identificador de la sección activa

        # Sección de opciones en la parte superior
        self.frame_opciones = ctk.CTkFrame(self, corner_radius=10)
        self.frame_opciones.grid(row=0, column=0, columnspan=2, padx=20, pady=10, sticky="ew")
        self.frame_opciones.grid_columnconfigure((0,1,2,3), weight=1)

        self.btn_red = ctk.CTkCheckBox(self.frame_opciones, text="Red", variable=self.var_red,
                                        command=lambda: self.seleccionar_opcion("red"))
        self.btn_carpeta = ctk.CTkCheckBox(self.frame_opciones, text="Carpeta", variable=self.var_carpeta,
                                            command=lambda: self.seleccionar_opcion("carpeta"))
        self.btn_ping = ctk.CTkCheckBox(self.frame_opciones, text="Ping", variable=self.var_ping,
                                         command=lambda: self.seleccionar_opcion("ping"))
        self.btn_acceso = ctk.CTkCheckBox(self.frame_opciones, text="Acceso", variable=self.var_acceso,
                                           command=lambda: self.seleccionar_opcion("acceso"))

        self.btn_red.grid(row=0, column=0, padx=10, pady=10)
        self.btn_carpeta.grid(row=0, column=1, padx=10, pady=10)
        self.btn_ping.grid(row=0, column=2, padx=10, pady=10)
        self.btn_acceso.grid(row=0, column=3, padx=10, pady=10)

        # Frames para cada sección (inicialmente ocultos)
        self.frame_red = ctk.CTkFrame(self, corner_radius=10)
        self.frame_carpeta = ctk.CTkFrame(self, corner_radius=10)
        self.frame_ping = ctk.CTkFrame(self, corner_radius=10)
        self.frame_acceso = ctk.CTkFrame(self, corner_radius=10)

        self.init_seccion_red()
        self.init_seccion_carpeta()
        self.init_seccion_ping()
        self.init_seccion_acceso()

    def deseleccionar_todos(self):
        # Establece todas las variables en False
        self.var_red.set(False)
        self.var_carpeta.set(False)
        self.var_ping.set(False)
        self.var_acceso.set(False)

    def seleccionar_opcion(self, opcion):
        if self.opcion.get() == opcion:
            # Si se vuelve a clicar la opción ya seleccionada, se desactiva
            self.opcion.set("")
            self.deseleccionar_todos()
        else:
            self.opcion.set(opcion)
            self.deseleccionar_todos()
            # Activa únicamente la opción seleccionada
            if opcion == "red":
                self.var_red.set(True)
            elif opcion == "carpeta":
                self.var_carpeta.set(True)
            elif opcion == "ping":
                self.var_ping.set(True)
            elif opcion == "acceso":
                self.var_acceso.set(True)
        self.actualizar_secciones()

    def actualizar_secciones(self):
        # Oculta todas las secciones
        for frame in (self.frame_red, self.frame_carpeta, self.frame_ping, self.frame_acceso):
            frame.grid_forget()
        # Muestra la sección correspondiente
        opcion = self.opcion.get()
        if opcion == "red":
            self.frame_red.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")
        elif opcion == "carpeta":
            self.frame_carpeta.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")
        elif opcion == "ping":
            self.frame_ping.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")
        elif opcion == "acceso":
            self.frame_acceso.grid(row=1, column=0, columnspan=2, padx=20, pady=10, sticky="nsew")

    # Sección Red
    def init_seccion_red(self):
        lbl = ctk.CTkLabel(self.frame_red, text="Configuración de Red", font=ctk.CTkFont(size=16, weight="bold"))
        lbl.grid(row=0, column=0, columnspan=4, pady=10)
        self.entry_ip = ctk.CTkEntry(self.frame_red, placeholder_text="IP", width=150)
        self.entry_ip.insert(0, self.config_data.get("ip", ""))
        self.entry_mascara = ctk.CTkEntry(self.frame_red, placeholder_text="Máscara", width=150)
        self.entry_mascara.insert(0, self.config_data.get("mascara", ""))
        self.entry_puerta = ctk.CTkEntry(self.frame_red, placeholder_text="Puerta de enlace", width=150)
        self.entry_puerta.insert(0, self.config_data.get("puerta_enlace", ""))
        self.entry_dns = ctk.CTkEntry(self.frame_red, placeholder_text="DNS", width=150)
        self.entry_dns.insert(0, self.config_data.get("dns", ""))

        self.entry_ip.grid(row=1, column=0, padx=10, pady=5)
        self.entry_mascara.grid(row=1, column=1, padx=10, pady=5)
        self.entry_puerta.grid(row=1, column=2, padx=10, pady=5)
        self.entry_dns.grid(row=1, column=3, padx=10, pady=5)

        self.btn_config_red = ctk.CTkButton(self.frame_red, text="Aplicar configuración", command=self.aplicar_red)
        self.btn_config_red.grid(row=2, column=3, padx=10, pady=10, sticky="e")

    def aplicar_red(self):
        nueva = {
            "ip": self.entry_ip.get(),
            "mascara": self.entry_mascara.get(),
            "puerta_enlace": self.entry_puerta.get(),
            "dns": self.entry_dns.get(),
            "carpeta": self.config_data["carpeta"]
        }
        guardar_configuracion(nueva)
        configurar_red(nueva["ip"], nueva["mascara"], nueva["puerta_enlace"], nueva["dns"])
        messagebox.showinfo("Éxito", "Red configurada correctamente.")

    # Sección Carpeta
    def init_seccion_carpeta(self):
        lbl = ctk.CTkLabel(self.frame_carpeta, text="Compartir Carpeta", font=ctk.CTkFont(size=16, weight="bold"))
        lbl.grid(row=0, column=0, columnspan=3, pady=10)
        self.entry_carpeta = ctk.CTkEntry(self.frame_carpeta, placeholder_text="Ruta carpeta", width=400)
        self.entry_carpeta.insert(0, self.config_data.get("carpeta", ""))
        self.entry_carpeta.grid(row=1, column=0, columnspan=2, padx=10, pady=5)
        self.btn_sel_carpeta = ctk.CTkButton(self.frame_carpeta, text="Seleccionar", command=self.seleccionar_carpeta)
        self.btn_sel_carpeta.grid(row=1, column=2, padx=10, pady=5)
        self.btn_compartir = ctk.CTkButton(self.frame_carpeta, text="Compartir", command=self.compartir_carpeta)
        self.btn_compartir.grid(row=2, column=2, padx=10, pady=10, sticky="e")

    def seleccionar_carpeta(self):
        from tkinter import filedialog
        carpeta = filedialog.askdirectory()
        if carpeta:
            self.entry_carpeta.delete(0, "end")
            self.entry_carpeta.insert(0, carpeta)

    def compartir_carpeta(self):
        ruta = self.entry_carpeta.get()
        crear_carpeta_y_compartir(ruta)
        self.config_data["carpeta"] = ruta
        guardar_configuracion(self.config_data)
        messagebox.showinfo("Éxito", f"La carpeta '{ruta}' ha sido compartida.")

    # Sección Ping
    def init_seccion_ping(self):
        lbl = ctk.CTkLabel(self.frame_ping, text="Hacer Ping", font=ctk.CTkFont(size=16, weight="bold"))
        lbl.grid(row=0, column=0, columnspan=3, pady=10)
        self.combo_ips = ctk.CTkComboBox(self.frame_ping, values=obtener_ips_red_local(), width=150)
        self.combo_ips.grid(row=1, column=0, padx=10, pady=5)
        self.entry_ip_custom = ctk.CTkEntry(self.frame_ping, placeholder_text="O ingresa IP", width=150)
        self.entry_ip_custom.grid(row=1, column=1, padx=10, pady=5)
        self.btn_ping = ctk.CTkButton(self.frame_ping, text="Ping", command=self.ejecutar_ping)
        self.btn_ping.grid(row=1, column=2, padx=10, pady=5)

    def ejecutar_ping(self):
        ip = self.entry_ip_custom.get() or self.combo_ips.get()
        if hacer_ping(ip):
            messagebox.showinfo("Ping", f"{ip} respondió correctamente.")
        else:
            messagebox.showwarning("Ping", f"{ip} no respondió.")

    # Sección Acceso sin contraseña
    def init_seccion_acceso(self):
        lbl = ctk.CTkLabel(self.frame_acceso, text="Acceso sin contraseña", font=ctk.CTkFont(size=16, weight="bold"))
        lbl.grid(row=0, column=0, padx=10, pady=10)
        btn_activar = ctk.CTkButton(self.frame_acceso, text="Activar acceso", command=self.activar_acceso_sistema)
        btn_activar.grid(row=1, column=0, padx=10, pady=10, sticky="e")

    def activar_acceso_sistema(self):
        activar_acceso_sin_contrasena()
        messagebox.showinfo("Acceso", "Acceso sin contraseña activado.")

if __name__ == "__main__":
    if ctypes.windll.shell32.IsUserAnAdmin():
        app = App()
        app.mainloop()
    else:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", __file__, None, None, 1)
