#!/usr/bin/env python3
"""
DNS Auditor - Herramienta de análisis básico de servidores DNS
Desarrollado con fines educativos en ciberseguridad
"""

import argparse
import socket
import dns.resolver
import dns.query
import shodan
import ipaddress
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm

class DNSAuditor:
    def __init__(self, api_key=None, max_results=100):
        """
        Inicializa el auditor DNS con una API key de Shodan opcional
        
        Args:
            api_key (str): API key de Shodan (opcional)
            max_results (int): Máximo número de resultados a procesar
        """
        self.api_key = api_key
        self.max_results = max_results
        self.shodan_api = None
        self.test_domains = ["google.com", "facebook.com", "amazon.com"]
        
        if api_key:
            try:
                self.shodan_api = shodan.Shodan(api_key)
                print("[+] Conexión exitosa con Shodan API")
            except shodan.APIError as e:
                print(f"[-] Error al conectar con Shodan API: {e}")
                self.shodan_api = None
        
    def search_dns_servers(self, query="port:53", country=None):
        """
        Busca servidores DNS expuestos usando Shodan
        
        Args:
            query (str): Consulta para Shodan
            country (str): Código de país para filtrar resultados (opcional)
            
        Returns:
            list: Lista de direcciones IP con DNS expuesto
        """
        dns_servers = []
        
        if not self.shodan_api:
            print("[-] No se pudo realizar la búsqueda: API key de Shodan no configurada")
            return dns_servers
            
        try:
            # Refinar la consulta si se especifica un país
            if country:
                query = f"{query} country:{country}"
                
            print(f"[*] Buscando servidores DNS con query: {query}")
            
            # Realizar la búsqueda en Shodan
            results = self.shodan_api.search(query, limit=self.max_results)
            
            print(f"[+] Se encontraron aproximadamente {results['total']} resultados")
            print(f"[*] Procesando hasta {self.max_results} servidores...")
            
            # Extraer las IPs de los resultados
            for result in results['matches']:
                dns_servers.append(result['ip_str'])
                
            return dns_servers
            
        except shodan.APIError as e:
            print(f"[-] Error en la búsqueda de Shodan: {e}")
            return dns_servers

    def check_dns_resolution(self, ip, domains=None):
        """
        Verifica si un servidor DNS puede resolver dominios correctamente
        
        Args:
            ip (str): Dirección IP del servidor DNS a verificar
            domains (list): Lista de dominios a verificar (opcional)
            
        Returns:
            dict: Resultados de la verificación
        """
        if domains is None:
            domains = self.test_domains
            
        results = {
            "ip": ip,
            "resolutions": {},
            "success_rate": 0,
            "is_operational": False
        }
        
        resolver = dns.resolver.Resolver(configure=False)
        resolver.nameservers = [ip]
        resolver.timeout = 3
        resolver.lifetime = 3
        
        success_count = 0
        
        for domain in domains:
            try:
                start_time = time.time()
                answers = resolver.resolve(domain, 'A')
                response_time = time.time() - start_time
                
                resolved_ips = [rdata.address for rdata in answers]
                
                results["resolutions"][domain] = {
                    "status": "resolved",
                    "ips": resolved_ips,
                    "response_time": round(response_time * 1000, 2)  # en milisegundos
                }
                success_count += 1
                
            except Exception as e:
                results["resolutions"][domain] = {
                    "status": "failed",
                    "error": str(e)
                }
        
        # Calcular tasa de éxito y determinar si es operativo
        results["success_rate"] = (success_count / len(domains)) * 100
        results["is_operational"] = success_count > 0
        
        return results
    
    def check_servers_concurrently(self, ips, domains=None, max_workers=10):
        """
        Verifica múltiples servidores DNS en paralelo
        
        Args:
            ips (list): Lista de IPs a verificar
            domains (list): Lista de dominios a probar
            max_workers (int): Número máximo de hilos a utilizar
            
        Returns:
            list: Resultados de las verificaciones
        """
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Crear una barra de progreso
            futures = {executor.submit(self.check_dns_resolution, ip, domains): ip for ip in ips}
            
            # Procesar resultados a medida que se completan
            for future in tqdm(futures, desc="Verificando servidores DNS", unit="servidor"):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    ip = futures[future]
                    print(f"[-] Error al verificar {ip}: {e}")
        
        return results
    
    def print_results(self, results):
        """
        Imprime los resultados del análisis en un formato legible
        
        Args:
            results (list): Resultados del análisis
        """
        print("\n===== RESULTADOS DEL ANÁLISIS DNS =====")
        
        operational_count = sum(1 for r in results if r["is_operational"])
        print(f"\n[+] Servidores analizados: {len(results)}")
        print(f"[+] Servidores operativos: {operational_count} ({operational_count/len(results)*100:.1f}%)")
        
        print("\n----- Servidores DNS operativos -----")
        for result in sorted(results, key=lambda x: x["success_rate"], reverse=True):
            if result["is_operational"]:
                print(f"\nIP: {result['ip']} (Tasa de éxito: {result['success_rate']:.1f}%)")
                
                for domain, resolution in result["resolutions"].items():
                    if resolution["status"] == "resolved":
                        print(f"  ✓ {domain}: {', '.join(resolution['ips'])} ({resolution['response_time']}ms)")
                    else:
                        print(f"  ✗ {domain}: {resolution['error']}")
        
        print("\n----- Servidores DNS no operativos -----")
        for result in results:
            if not result["is_operational"]:
                print(f"\nIP: {result['ip']} (No responde a consultas DNS)")


def main():
    """Función principal que ejecuta el programa"""
    parser = argparse.ArgumentParser(description="Herramienta de auditoría de servidores DNS con fines educativos")
    
    parser.add_argument("-k", "--api-key", help="API Key de Shodan")
    parser.add_argument("-q", "--query", default="port:53", help="Consulta personalizada para Shodan (default: 'port:53')")
    parser.add_argument("-c", "--country", help="Filtrar por código de país (ej: US, ES, AR)")
    parser.add_argument("-m", "--max", type=int, default=100, help="Número máximo de resultados a procesar")
    parser.add_argument("-d", "--domains", nargs="+", help="Dominios a verificar (separados por espacios)")
    parser.add_argument("-i", "--ip", help="Verificar una IP específica en lugar de realizar búsqueda")
    parser.add_argument("-f", "--file", help="Archivo con lista de IPs a verificar (una por línea)")
    
    args = parser.parse_args()
    
    # Inicializar el auditor
    auditor = DNSAuditor(api_key=args.api_key, max_results=args.max)
    
    # Personalizar los dominios de prueba si se especifican
    if args.domains:
        auditor.test_domains = args.domains
        
    # Obtener lista de IPs para analizar
    ips_to_check = []
    
    if args.ip:
        # Verificar una IP específica
        try:
            ipaddress.ip_address(args.ip)  # Validar que es una IP válida
            ips_to_check = [args.ip]
            print(f"[*] Verificando servidor DNS: {args.ip}")
        except ValueError:
            print(f"[-] IP no válida: {args.ip}")
            sys.exit(1)
    
    elif args.file:
        # Cargar IPs desde archivo
        try:
            with open(args.file, 'r') as f:
                ips_to_check = [line.strip() for line in f if line.strip()]
            print(f"[*] Cargadas {len(ips_to_check)} IPs desde {args.file}")
        except Exception as e:
            print(f"[-] Error al leer el archivo: {e}")
            sys.exit(1)
    
    else:
        # Buscar servidores DNS con Shodan
        ips_to_check = auditor.search_dns_servers(query=args.query, country=args.country)
        
    if not ips_to_check:
        print("[-] No se encontraron servidores DNS para analizar.")
        sys.exit(1)
        
    # Realizar la verificación de los servidores
    print(f"[*] Verificando resolución DNS en {len(ips_to_check)} servidores...")
    results = auditor.check_servers_concurrently(ips_to_check)
    
    # Imprimir resultados
    auditor.print_results(results)
    
    print("\n[+] Análisis completo.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[-] Operación cancelada por el usuario.")
        sys.exit(0)
    except Exception as e:
        print(f"\n[-] Error inesperado: {e}")
        sys.exit(1)
