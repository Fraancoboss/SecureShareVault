import socket
import threading
import json
import base64

class ImprovedMITMProxy:
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
        
        while True:
            client_socket, client_addr = mitm_socket.accept()
            print(f"✅ Cliente conectado desde {client_addr}")
            
            client_thread = threading.Thread(
                target=self.handle_client,
                args=(client_socket,)
            )
            client_thread.daemon = True
            client_thread.start()
    
    def handle_client(self, client_socket):
        """Maneja una conexión de cliente"""
        try:
            # Conectar al servidor real
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.connect((self.server_host, self.server_port))
            print("🔗 Conectado al servidor real")
            
            # Buffers para reconstruir mensajes HTTP completos
            client_buffer = b""
            server_buffer = b""
            
            def forward_with_analysis(source, destination, direction, buffer):
                nonlocal client_buffer, server_buffer
                try:
                    while True:
                        data = source.recv(4096)
                        if not data:
                            break
                        
                        # Agregar al buffer
                        buffer += data
                        
                        # Intentar procesar mensajes HTTP completos
                        processed_data = self.process_http_buffer(buffer, direction)
                        if processed_data:
                            buffer = processed_data
                            
                        # Reenviar al destino
                        destination.send(data)
                        
                except Exception as e:
                    print(f"⚠️  Error en forward {direction}: {e}")
            
            # Hilos para manejar comunicación bidireccional
            to_server_thread = threading.Thread(
                target=forward_with_analysis,
                args=(client_socket, server_socket, "CLIENTE → SERVIDOR", client_buffer)
            )
            to_client_thread = threading.Thread(
                target=forward_with_analysis,
                args=(server_socket, client_socket, "SERVIDOR → CLIENTE", server_buffer)
            )
            
            to_server_thread.daemon = True
            to_client_thread.daemon = True
            
            to_server_thread.start()
            to_client_thread.start()
            
            to_server_thread.join()
            to_client_thread.join()
            
        except Exception as e:
            print(f"❌ Error en MITM: {e}")
        finally:
            client_socket.close()
            server_socket.close()
    
    def process_http_buffer(self, buffer, direction):
        """Procesa el buffer para encontrar mensajes HTTP completos"""
        try:
            text = buffer.decode('utf-8', errors='replace')
            
            # Buscar fin de headers HTTP
            header_end = text.find('\r\n\r\n')
            if header_end == -1:
                return buffer  # Headers incompletos
                
            headers = text[:header_end]
            body_start = header_end + 4
            content_length = self.get_content_length(headers)
            
            # Verificar si tenemos el cuerpo completo
            if len(text) >= body_start + content_length:
                body = text[body_start:body_start + content_length]
                
                # Analizar el mensaje completo
                self.analyze_http_message(headers, body, direction)
                
                # Devolver buffer restante
                return buffer[body_start + content_length:]
            
            return buffer  # Cuerpo incompleto
            
        except Exception as e:
            print(f"❌ Error procesando HTTP: {e}")
            return buffer
    
    def get_content_length(self, headers):
        """Extrae Content-Length de los headers HTTP"""
        for line in headers.split('\r\n'):
            if line.lower().startswith('content-length:'):
                return int(line.split(':')[1].strip())
        return 0
    
    def analyze_http_message(self, headers, body, direction):
        """Analiza un mensaje HTTP completo"""
        print(f"\n{'='*60}")
        print(f"🎯 {direction} - MENSAJE HTTP COMPLETO")
        print(f"{'='*60}")
        
        # Mostrar headers importantes
        print("📋 HEADERS:")
        for line in headers.split('\r\n'):
            if any(key in line.lower() for key in ['post', 'host', 'content-type', 'content-length']):
                print(f"   {line}")
        
        # Analizar cuerpo
        if body.strip():
            print(f"📦 CUERPO ({len(body)} bytes):")
            
            # Intentar como JSON
            try:
                json_data = json.loads(body)
                print("📄 ESTRUCTURA JSON DETECTADA:")
                print(json.dumps(json_data, indent=2))
                
                # Análisis específico de tu aplicación
                self.analyze_app_data(json_data)
                
            except json.JSONDecodeError:
                # No es JSON, mostrar como texto
                if len(body) > 200:
                    print(f"   {body[:200]}...")
                else:
                    print(f"   {body}")
    
    def analyze_app_data(self, json_data):
        """Análisis específico para tu aplicación de cifrado"""
        if isinstance(json_data, dict):
            # Request del cliente
            if "data" in json_data and "shares" in json_data:
                print("\n🔐 ANÁLISIS DE SEGURIDAD:")
                print("   ✅ Estructura correcta - datos cifrados detectados")
                
                data_info = json_data["data"]
                if all(k in data_info for k in ["ciphertext", "nonce", "tag"]):
                    print("   🔒 Datos AES-GCM:")
                    print(f"     • Ciphertext: {data_info['ciphertext'][:40]}...")
                    print(f"     • Nonce: {data_info['nonce'][:30]}...")
                    print(f"     • Tag: {data_info['tag'][:30]}...")
                    
                    # Verificar que son datos base64 cifrados
                    try:
                        ciphertext_bytes = base64.b64decode(data_info['ciphertext'])
                        print(f"     • Ciphertext (bytes): {len(ciphertext_bytes)} bytes")
                    except:
                        print("     • ❌ Ciphertext no es base64 válido")
                
                print(f"   📊 Shamir Secret Sharing:")
                print(f"     • {len(json_data['shares'])} shares generados")
                print(f"     • Ejemplo de share: {json_data['shares'][0][0]} -> ...{str(json_data['shares'][0][1])[-20:]}")
            
            # Response del servidor
            elif all(k in json_data for k in ["ciphertext", "nonce", "tag"]):
                print("\n🔐 RESPUESTA CIFRADA DEL SERVIDOR:")
                print(f"   • Ciphertext: {json_data['ciphertext'][:40]}...")
                print(f"   • Nonce: {json_data['nonce'][:30]}...")
                print(f"   • Tag: {json_data['tag'][:30]}...")

# Uso del MITM Proxy Mejorado
if __name__ == "__main__":
    proxy = ImprovedMITMProxy(
        client_host='127.0.0.1',
        client_port=5000,
        server_host='127.0.0.1',
        server_port=5000,
        mitm_port=5001
    )
    
    proxy.start()