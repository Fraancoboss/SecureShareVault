import socket
import threading
import json
import base64

class SimpleMITMProxy:
    def __init__(self, client_host, client_port, server_host, server_port, mitm_port):
        self.client_host = client_host
        self.client_port = client_port
        self.server_host = server_host
        self.server_port = server_port
        self.mitm_port = mitm_port
        
    def start(self):
        """Inicia el proxy MITM"""
        mitm_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mitm_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        mitm_socket.bind(('localhost', self.mitm_port))
        mitm_socket.listen(5)
        
        print(f"🔍 MITM Proxy escuchando en puerto {self.mitm_port}")
        print(f"📱 Cliente debe conectarse a: localhost:{self.mitm_port}")
        print(f"🎯 Interceptando tráfico hacia servidor real en puerto {self.server_port}")
        print("⏳ Esperando conexiones...")
        
        while True:
            try:
                client_socket, client_addr = mitm_socket.accept()
                print(f"✅ Cliente conectado desde {client_addr}")
                
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket,)
                )
                client_thread.daemon = True
                client_thread.start()
            except Exception as e:
                print(f"❌ Error aceptando conexión: {e}")

    def handle_client(self, client_socket):
        """Maneja una conexión de cliente"""
        server_socket = None
        try:
            # Conectar al servidor real
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.server_host, self.server_port))
            print("🔗 Conectado al servidor real")

            # Hilos para comunicación bidireccional
            to_server_thread = threading.Thread(
                target=self.forward_traffic,
                args=(client_socket, server_socket, "CLIENTE → SERVIDOR")
            )
            to_client_thread = threading.Thread(
                target=self.forward_traffic,
                args=(server_socket, client_socket, "SERVIDOR → CLIENTE")
            )
            
            to_server_thread.daemon = True
            to_client_thread.daemon = True
            
            to_server_thread.start()
            to_client_thread.start()
            
            # Esperar a que ambos hilos terminen
            to_server_thread.join()
            to_client_thread.join()
            
        except Exception as e:
            print(f"❌ Error en handle_client: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            try:
                if server_socket:
                    server_socket.close()
            except:
                pass
            print("🔌 Conexión cerrada")

    def forward_traffic(self, source, destination, direction):
        """Reenvía tráfico entre cliente y servidor, mostrando los datos"""
        buffer = b""
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    break
                
                # Agregar al buffer
                buffer += data
                
                # Procesar y mostrar datos
                buffer = self.process_and_display_data(buffer, direction)
                
                # Reenviar al destino
                destination.send(data)
                
        except Exception as e:
            print(f"⚠️  Error en forward {direction}: {e}")

    def process_and_display_data(self, buffer, direction):
        """Procesa el buffer y muestra los datos interesantes"""
        try:
            # Intentar decodificar como texto
            text = buffer.decode('utf-8', errors='replace')
            
            # Buscar JSON en el texto
            json_objects = self.extract_json_objects(text)
            
            if json_objects:
                for i, json_obj in enumerate(json_objects):
                    print(f"\n{'='*60}")
                    print(f"🎯 {direction} - JSON #{i+1} ENCONTRADO")
                    print(f"{'='*60}")
                    print(json.dumps(json_obj, indent=2))
                    
                    # Análisis de seguridad
                    self.analyze_security(json_obj, direction)
                    
                # Devolver buffer vacío ya que procesamos todo
                return b""
            
        except Exception as e:
            print(f"❌ Error procesando datos: {e}")
        
        return buffer

    def extract_json_objects(self, text):
        """Extrae todos los objetos JSON del texto"""
        json_objects = []
        stack = []
        start_index = -1
        
        for i, char in enumerate(text):
            if char == '{':
                if not stack:  # Inicio de un nuevo objeto
                    start_index = i
                stack.append(char)
            elif char == '}':
                if stack:
                    stack.pop()
                    if not stack and start_index != -1:  # Fin de objeto
                        try:
                            json_str = text[start_index:i+1]
                            json_obj = json.loads(json_str)
                            json_objects.append(json_obj)
                        except json.JSONDecodeError:
                            pass  # JSON incompleto o inválido
                        start_index = -1
        
        return json_objects

    def analyze_security(self, json_data, direction):
        """Analiza los datos desde perspectiva de seguridad"""
        print(f"\n🔐 ANÁLISIS DE SEGURIDAD ({direction}):")
        
        if isinstance(json_data, dict):
            # Request del cliente
            if "data" in json_data and "shares" in json_data:
                print("   ✅ Estructura correcta - Aplicación cifrada detectada")
                
                data_info = json_data["data"]
                if all(k in data_info for k in ["ciphertext", "nonce", "tag"]):
                    print("   🔒 Datos AES-GCM CIFRADOS:")
                    print(f"     • Ciphertext: {data_info['ciphertext'][:50]}...")
                    print(f"     • Nonce: {data_info['nonce'][:30]}...")
                    print(f"     • Tag: {data_info['tag'][:30]}...")
                    
                    # Verificar base64
                    try:
                        ciphertext_bytes = base64.b64decode(data_info['ciphertext'])
                        nonce_bytes = base64.b64decode(data_info['nonce'])
                        tag_bytes = base64.b64decode(data_info['tag'])
                        print(f"     • Tamaños: ciphertext={len(ciphertext_bytes)}B, nonce={len(nonce_bytes)}B, tag={len(tag_bytes)}B")
                    except Exception as e:
                        print(f"     • ❌ Error decodificando base64: {e}")
                
                print(f"   📊 Shamir Secret Sharing:")
                print(f"     • {len(json_data['shares'])} shares generados")
                if json_data['shares']:
                    share_example = json_data['shares'][0]
                    print(f"     • Ejemplo: share[{share_example[0]}] = ...{str(share_example[1])[-20:]}")
            
            # Response del servidor
            elif all(k in json_data for k in ["ciphertext", "nonce", "tag"]):
                print("   🔒 RESPUESTA CIFRADA DEL SERVIDOR:")
                print(f"     • Ciphertext: {json_data['ciphertext'][:50]}...")
                print(f"     • Nonce: {json_data['nonce'][:30]}...")
                print(f"     • Tag: {json_data['tag'][:30]}...")
                
                # Verificar que no es texto plano
                try:
                    decoded = base64.b64decode(json_data['ciphertext'])
                    print(f"     • Ciphertext decodificado: {len(decoded)} bytes (no es texto legible)")
                except:
                    print("     • ❌ Ciphertext no es base64 válido")
            
            else:
                print("   ⚠️  Estructura JSON no reconocida")
        else:
            print("   ⚠️  No es un objeto JSON")

# Uso del MITM Proxy
if __name__ == "__main__":
    proxy = SimpleMITMProxy(
        client_host='127.0.0.1',
        client_port=5000,
        server_host='127.0.0.1',
        server_port=5000,
        mitm_port=5001
    )
    
    print("🚀 Iniciando MITM Proxy...")
    proxy.start()