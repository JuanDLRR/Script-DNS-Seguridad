# DNS Auditor

## Herramienta de Análisis de Servidores DNS para Seguridad Informática

Este script de Python permite realizar auditorías básicas a servidores DNS, identificando aquellos expuestos en Internet y verificando sus capacidades de resolución. Desarrollado con fines educativos para comprender conceptos de ciberseguridad relacionados con servicios DNS.

## Tabla de Contenidos

- [Descripción General](#descripción-general)
- [Instalación](#instalación)
- [Uso](#uso)
- [Explicación Teórica de las Funciones](#explicación-teórica-de-las-funciones)
- [Proceso de Desarrollo con IA](#proceso-de-desarrollo-con-ia)
- [Alcance y Limitaciones](#alcance-y-limitaciones)
- [Consideraciones Éticas](#consideraciones-éticas)
- [Próximos Pasos](#próximos-pasos)

## Descripción General

DNS Auditor es una herramienta de línea de comandos que permite:

1. Buscar servidores DNS expuestos en Internet usando la API de Shodan
2. Verificar si estos servidores responden correctamente a consultas DNS
3. Analizar la operatividad real de los servidores encontrados
4. Generar informes sobre el estado de los servidores analizados

La herramienta está pensada como un recurso educativo para entender la superficie de exposición de servicios DNS en Internet y las implicaciones de seguridad asociadas.

## Instalación

### Requisitos previos

- Python 3.6+
- Conexión a Internet
- API Key de Shodan (opcional, pero recomendada para búsquedas)

### Dependencias

Instale las bibliotecas necesarias con pip:

```bash
pip install dnspython shodan tqdm
```

### Clonar el repositorio

```bash
git clone https://github.com/usuario/dns-auditor.git
cd dns-auditor
```

## Uso

### Ejemplos básicos

**Buscar servidores DNS con Shodan y verificar su operatividad:**

```bash
python dns_auditor.py -k TU_API_KEY_DE_SHODAN
```

**Verificar un servidor DNS específico:**

```bash
python dns_auditor.py -i 8.8.8.8
```

**Verificar una lista de servidores desde un archivo:**

```bash
python dns_auditor.py -f lista_servidores.txt
```

**Personalizar los dominios utilizados para la verificación:**

```bash
python dns_auditor.py -k TU_API_KEY -d google.com facebook.com amazon.com
```

**Limitar la búsqueda a un país específico:**

```bash
python dns_auditor.py -k TU_API_KEY -c ES
```

### Opciones disponibles

```
usage: dns_auditor.py [-h] [-k API_KEY] [-q QUERY] [-c COUNTRY] [-m MAX]
                      [-d DOMAINS [DOMAINS ...]] [-i IP] [-f FILE]

Herramienta de auditoría de servidores DNS con fines educativos

optional arguments:
  -h, --help            show this help message and exit
  -k API_KEY, --api-key API_KEY
                        API Key de Shodan
  -q QUERY, --query QUERY
                        Consulta personalizada para Shodan (default: 'port:53')
  -c COUNTRY, --country COUNTRY
                        Filtrar por código de país (ej: US, ES, AR)
  -m MAX, --max MAX     Número máximo de resultados a procesar
  -d DOMAINS [DOMAINS ...], --domains DOMAINS [DOMAINS ...]
                        Dominios a verificar (separados por espacios)
  -i IP, --ip IP        Verificar una IP específica en lugar de realizar búsqueda
  -f FILE, --file FILE  Archivo con lista de IPs a verificar (una por línea)
```

## Explicación Teórica de las Funciones

### Funciones Básicas

#### 1. Búsqueda de IPs con DNS expuesto

Esta función utiliza la API de Shodan para localizar servidores que tienen el puerto 53 (UDP/TCP) abierto a Internet. El proceso consiste en:

- Configurar una consulta adecuada para Shodan (por defecto `port:53`)
- Realizar la petición a la API y procesar los resultados
- Extraer las direcciones IP de los servidores encontrados

La identificación de servidores DNS expuestos es crucial ya que permite:
- Mapear la superficie de ataque potencial en una red
- Identificar servidores que podrían ser utilizados en ataques (por ejemplo, amplificación DNS)
- Detectar configuraciones incorrectas que exponen servicios innecesariamente

#### 2. Verificación de resolución DNS

Esta función comprueba si los servidores encontrados realmente funcionan como resolvedores DNS. Para cada servidor:

- Configura un resolvedor DNS que apunte a la IP del servidor a verificar
- Intenta resolver uno o varios dominios de prueba (por defecto google.com, facebook.com y amazon.com)
- Registra el éxito o fracaso de cada resolución, así como el tiempo de respuesta
- Calcula métricas como la tasa de éxito y determina si el servidor es operativo

Esta verificación es esencial para distinguir entre:
- Servidores DNS verdaderamente operativos
- Servicios que solo tienen el puerto abierto pero no funcionan correctamente
- Falsos positivos en los resultados de Shodan

## Proceso de Desarrollo con IA

### Prompt Inicial

Para iniciar el desarrollo de esta herramienta, se utilizó el siguiente prompt con Claude:

```
Me gustaria crear un script en Python para el analisis de DNS como si fueras un experto en seguridad informatica y con fines educativos con las siguientes caracteristicas: Funciones Básicas 1. Búsqueda de IPs con DNS expuesto (básico) Este proceso consiste en localizar direcciones IP que tengan un servicio DNS abierto en el puerto 53 (UDP/TCP). Con esta búsqueda, la aplicación identifica los servidores potencialmente accesibles desde Internet, permitiendo una primera aproximación a la superficie de ataque y al estado de la red. 2. Verificación de resolución DNS (por ejemplo, a un o varios dominios específicos) En esta etapa, se valida si las direcciones IP encontradas son capaces de resolver peticiones DNS correctamente. Por ejemplo, consultando un dominio predefinido (como google.com) para confirmar que el servidor DNS responde adecuadamente. Esto sirve para diferenciar servidores DNS verdaderamente operativos de aquellos que simplemente tienen el puerto abierto pero no funcionan.
```

### Justificación del Prompt

La estructura del prompt se diseñó considerando varios factores clave:

1. **Contexto experto**: Se solicitó una perspectiva de "experto en seguridad informática" para obtener código que siguiera mejores prácticas de seguridad.

2. **Finalidad educativa**: Se especificó claramente que el propósito es educativo, evitando así herramientas que pudieran tener usos maliciosos.

3. **Funcionalidades específicas**: Se describieron en detalle las dos funciones básicas requeridas, incluyendo el propósito de cada una.

4. **Claridad en los requerimientos**: El prompt proporcionó suficiente información técnica (como el puerto 53) y ejemplos concretos (como probar con google.com).

### Resultado y Refinamiento

La IA generó un script completo con las funcionalidades básicas solicitadas, añadiendo características adicionales que mejoraron notablemente la herramienta:

- Sistema de procesamiento concurrente para verificar múltiples servidores simultáneamente
- Interfaz de línea de comandos con múltiples opciones de configuración
- Manejo apropiado de errores y excepciones
- Visualización clara de resultados con estadísticas

No fue necesario un refinamiento significativo del prompt inicial, ya que el resultado cumplió con todos los requisitos solicitados. La estructura y diseño del código fue óptimo para una herramienta educativa.

## Alcance y Limitaciones

### Alcance Real de la Aplicación

1. **Capacidades:**
   - Identificación de servidores DNS expuestos en Internet
   - Verificación de la funcionalidad real de estos servidores
   - Análisis de tiempos de respuesta y tasas de éxito
   - Soporte para procesamiento en paralelo de múltiples servidores
   - Filtrado por países y consultas personalizadas en Shodan

2. **Casos de uso:**
   - Educación sobre seguridad de servicios DNS
   - Auditorías básicas de seguridad en red
   - Investigación sobre exposición de servicios DNS
   - Práctica de conceptos de Python aplicados a ciberseguridad

### Limitaciones

1. **Uso de Shodan:**
   - **Consumo de créditos**: Cada consulta a Shodan consume créditos de la cuenta. Por defecto, una cuenta gratuita tiene limitaciones significativas.
   - **Limitación de resultados**: La API gratuita de Shodan solo permite acceder a un subconjunto de los resultados totales.
   - **Velocidad de consulta**: Existen límites de tasa para las consultas a la API.

2. **Técnicas:**
   - La herramienta solo implementa verificaciones básicas, no pruebas avanzadas como recursividad o amplificación.
   - No gestiona resolución de nombres PTR o otros tipos de registros DNS.
   - El análisis se limita a verificar si el servidor responde, no evalúa la seguridad de la configuración.

3. **Optimización:**
   - Para maximizar los créditos de Shodan, se recomienda:
     - Usar filtros específicos por país o región
     - Limitar el número de resultados procesados con el parámetro `-m`
     - Guardar resultados previos para reutilizarlos con la opción `-f`

## Consideraciones Éticas

1. Esta herramienta está diseñada exclusivamente con fines educativos y de investigación defensiva.

2. El uso de la herramienta debe realizarse:
   - Solo en entornos autorizados o en Internet con fines de investigación legítima
   - Respetando las políticas de uso de Shodan
   - De manera responsable, sin causar interrupciones en servicios

3. La información obtenida con esta herramienta debe tratarse con confidencialidad y no debe utilizarse para actividades maliciosas.

## Próximos Pasos

Para expandir esta herramienta, se podrían implementar funcionalidades avanzadas como:

1. **Verificación de recursividad**: Determinar si un servidor permite consultas recursivas, lo que podría convertirlo en un potencial vector de ataque.

2. **Detección de amplificación DNS**: Analizar si el servidor puede ser utilizado para ataques de amplificación DNS.

3. **Paginación en Shodan**: Implementar la navegación por múltiples páginas de resultados para obtener conjuntos de datos más completos.

4. **Integración con listas negras**: Cruzar los resultados con bases de datos de IPs maliciosas o comprometidas.

5. **Generación de informes avanzados**: Crear reportes detallados en diversos formatos (PDF, HTML, JSON).
