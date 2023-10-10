# Herramienta de Conversión de IoCs a CSV

Esta es una herramienta simple escrita en Python para convertir un archivo de Indicadores de Compromiso (IoCs) en un formato específico a un archivo CSV para facilitar su análisis y procesamiento.

**Recuerda que debes cambiar el valor de la variable API_KEY por tu api key de virustotal**

## Autor

**Nombre del Autor:** Javier Matilla Martín aka m4t1

## Uso

Asegúrate de tener Python 3 instalado en tu sistema antes de utilizar esta herramienta.

1. Clona el repositorio o descarga el archivo `IoC_to_csv.py` directamente en tu sistema.

2. Ejecuta el script `IoC_to_csv.py` en la línea de comandos, especificando el archivo de entrada que contiene los IoCs que deseas convertir:

   ```bash
   python3 IoC_to_csv.py <fichero_ioc>
   ```
Por ejemplo:
   ```bash
   python3 IoC_to_csv.py iocs.txt
   ```
Esto generará un archivo CSV llamado iocs.csv que contiene los IoCs en un formato estructurado.

## Formato de Entrada
El archivo de entrada debe seguir un formato específico con cada IoC en una línea separada. Puedes incluir diferentes tipos de IoCs, como direcciones IP, URL, nombres de dominio, hashes, etc.

Asegúrate de que el archivo de entrada siga el formato correcto para obtener resultados precisos en el archivo CSV generado.
