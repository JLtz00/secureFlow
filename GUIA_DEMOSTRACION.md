# Guia de demostracion de SecureFlow

Esta guia permite mostrar SecureFlow analizando un archivo individual y un
proyecto Flask multiarchivo. Todos los ejemplos usan el frontend de produccion
`python-ast`, que es el valor predeterminado.

## Preparacion

Ejecutar los comandos desde la raiz del repositorio:

```bash
cd /home/lorenzo/UNSA/2026A/compiladores/secureFlow
make test
```

El resultado esperado de las pruebas es `failed=0`.

## Demostracion recomendada

### 1. Mostrar una vulnerabilidad dentro de un archivo

Primero se puede abrir
`data/flask_dataset/flask_multistep_query.py`. El dato se obtiene mediante
`request.form.get`, la consulta se arma en varias asignaciones y finalmente
llega a `cursor.execute`.

```bash
make scan-demo-file
```

SecureFlow debe informar:

- un archivo y dos funciones analizadas;
- cobertura del AST y construcciones aproximadas o ignoradas;
- una vulnerabilidad `PY.FLASK.SQLI` de severidad alta;
- el flujo `request.form.get -> query -> cursor.execute`;
- el archivo, la funcion y la linea del sumidero SQL.

### 2. Mostrar analisis interprocedural y multiarchivo

El proyecto vulnerable separa el flujo entre `routes.py`, `services.py` y
`repository.py`:

```bash
make scan-demo
```

El scanner analiza la carpeta completa, enlaza las llamadas y encuentra el
sumidero en `repository.py`, aunque la entrada Flask se origina en `routes.py`.
Este ejemplo demuestra que SecureFlow no se limita a buscar texto dentro de un
solo archivo.

### 3. Mostrar que una consulta parametrizada no se reporta

```bash
make scan-demo-safe
```

Este proyecto transporta el mismo tipo de entrada Flask, pero utiliza un
parametro separado de la consulta SQL. El resultado esperado es:
`NO SE DETECTARON VULNERABILIDADES`.

La conclusion correcta es que no se encontraron flujos vulnerables dentro del
alcance modelado y de la cobertura reportada. No debe afirmarse que cualquier
proyecto sin hallazgos es universalmente seguro.

## Analizar codigo propio

Un archivo Python:

```bash
./secureflow scan /ruta/al/archivo.py
```

Una carpeta o proyecto Flask:

```bash
./secureflow scan /ruta/al/proyecto
```

Para un proyecto multiarchivo se debe pasar la carpeta raiz. Analizar solamente
`routes.py` no permite ver un sumidero que se encuentra en `repository.py`.
Si la carpeta contiene pruebas que no forman parte del codigo desplegable,
pueden excluirse explicitamente:

```bash
./secureflow scan /ruta/al/proyecto --exclude tests
```

El lanzador `./secureflow` funciona directamente desde el repositorio y no
requiere instalar el paquete. Si SecureFlow fue instalado con
`pip install -e .`, tambien puede utilizarse sin el prefijo `./`:

```bash
secureflow scan /ruta/al/proyecto
```

## Formatos de salida

La salida predeterminada es `text`, adecuada para terminal y exposiciones.

```bash
# JSON para procesamiento automatico
./secureflow scan /ruta/al/proyecto --format json

# SARIF para herramientas de CI/CD
./secureflow scan /ruta/al/proyecto \
  --format sarif -o reports/secureflow.sarif
```

Para hacer fallar un pipeline cuando existan hallazgos:

```bash
./secureflow scan /ruta/al/proyecto --fail-on-findings
```

En ese modo, el proceso retorna codigo `1` cuando detecta una vulnerabilidad.

## Como explicar la salida

- `Archivos analizados`: archivos Python procesados respecto del total hallado.
- `Funciones analizadas`: funciones y modulos incluidos en el analisis.
- `Cobertura del AST`: nodos soportados o aproximados respecto del total.
- `Nodos aproximados`: construcciones conservadas mediante una representacion
  simplificada en el IR.
- `Nodos ignorados`: construcciones que el frontend no pudo bajar al IR.
- `Llamadas internas sin enlace`: funciones o metodos del proyecto que no
  pudieron conectarse con un resumen interprocedural.
- `APIs externas conservadoras`: bibliotecas o metodos dinamicos cuyo retorno
  conserva el taint de sus argumentos. No son errores de enlace.
- `Flujo`: recorrido desde la fuente Flask hasta el sumidero SQL.

Si hay errores, nodos ignorados o llamadas internas sin enlace, SecureFlow los
muestra para impedir que la ausencia de hallazgos se interprete silenciosamente
como seguridad total.

## Guion oral breve

1. "SecureFlow recibe un archivo o una carpeta de codigo Python/Flask."
2. "El frontend convierte Python real al IR usado por el analizador."
3. "El motor propaga datos no confiables desde `request` entre asignaciones,
   funciones y archivos."
4. "Cuando ese dato llega a una ejecucion SQL no parametrizada, reporta la
   ubicacion y el flujo completo."
5. "Tambien informa su cobertura y limitaciones para que un resultado sin
   hallazgos no sea una promesa falsa."
