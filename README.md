# SecureFlow

**A Compiler-Integrated Taint Analysis Framework for SQL Injection Detection in Python-Based Government Systems**

SecureFlow es un framework académico de análisis estático que integra *taint analysis* directamente dentro de un pipeline de compilación construido desde cero. Su objetivo es detectar y corregir automáticamente vulnerabilidades de inyección SQL en sistemas Python, con énfasis en portales gubernamentales.

## Estado implementado

Sprint 01 y Sprint 02 ya tienen una base ejecutable del pipeline:

- `lexer.py`: convierte codigo Python en tokens con tipo, valor, linea y columna. Incluye `INDENT`, `DEDENT`, strings multilinea, f-strings, comentarios omitidos y recuperacion con `ERROR`.
- `ast_nodes.py`: define el AST propio de SecureFlow, sin usar el modulo `ast` de Python.
- `parser.py`: parser recursivo descendente LL para funciones, asignaciones, `if`, `while`, `for`, `return`, llamadas y expresiones binarias.
- `ast_visualizer.py`: imprime el arbol para explicar como el codigo fuente se transforma en estructura analizable.
- `test_lexer.py` y `test_parser.py`: pruebas del comportamiento principal del lexer y parser.

Demo completa para clase:

```bash
python3 demo_secureflow.py
```

Demo solo del arbol AST:

```bash
python3 ast_visualizer.py
```

La salida muestra una fuente potencial (`request.args.get`), propagacion por variables y un sink potencial (`cursor.execute`). Esto prepara el terreno para el Sprint 03, donde el analisis semantico marcara simbolos contaminados.

---

## Motivación

Los sistemas gubernamentales que manejan datos sensibles —padrón electoral, registros de identidad, sistemas tributarios— son objetivos frecuentes de ataques de inyección SQL. Las herramientas existentes (linters, scanners de SAST) operan de forma superficial y no modelan el flujo real de datos a través del programa.

SecureFlow aborda este problema integrando el análisis de taint como una fase formal del pipeline de compilación, lo que permite rastrear datos no confiables desde su fuente hasta el punto de vulnerabilidad con precisión de flujo de datos.

---

## Características principales

**Detección precisa mediante análisis de flujo**
El motor recorre el Grafo de Flujo de Control (CFG) con un algoritmo Worklist forward, propagando la contaminación instrucción por instrucción en lugar de usar heurísticas superficiales.

**Análisis interprocedural**
SecureFlow construye resúmenes de función para propagar taint a través de llamadas entre funciones, resolviendo la limitación más citada en la literatura de análisis estático.

**Traza completa fuente → sumidero**
Los reportes muestran el camino exacto que recorre el dato contaminado, no solo la línea donde ocurre la vulnerabilidad.

**Generación de código endurecido**
El sistema no solo detecta: genera automáticamente una versión corregida del código usando consultas parametrizadas.

---

## Arquitectura del pipeline

```
Código Python (.py)
        │
┌───────▼────────┐
│   FASE 1       │  Lexer — Tokenización con regex maestra
│   Analizador   │  Manejo de INDENT/DEDENT, f-strings
│   Léxico       │
└───────┬────────┘
        │  secuencia de tokens
┌───────▼────────┐
│   FASE 2       │  Parser — Descenso recursivo predictivo LL(k)
│   Analizador   │  Construcción de AST propio (sin módulo ast)
│   Sintáctico   │
└───────┬────────┘
        │  AST
┌───────▼────────┐
│   FASE 3       │  Semántico — Tabla de símbolos con ámbitos anidados
│   Análisis     │  Pre-marcado de taint + inferencia de tipo
│   Semántico    │
└───────┬────────┘
        │  AST + tabla de símbolos
┌───────▼────────┐
│   FASE 4       │  IR — Código de Tres Direcciones (TAC)
│   Generación   │  Patrón Visitor sobre el AST
│   de IR        │
└───────┬────────┘
        │  lista de instrucciones TAC
┌───────▼────────┐
│   FASE 5       │  CFG — Bloques básicos (algoritmo de líderes)
│   Construcción │  Aristas de control: JUMP / BRANCH / fall-through
│   del CFG      │
└───────┬────────┘
        │  CFG con bloques básicos
┌───────▼────────┐
│   FASE 6       │  Taint Analysis
│   Motor de     │  Algoritmo Worklist (forward)
│   Taint        │  Análisis interprocedural con resúmenes de función
│                │  Traza completa source → sink
└───────┬────────┘
        │
┌───────▼────────┐
│   SALIDA       │  Reporter: consola ANSI + JSON para CI/CD
│   FINAL        │  Hardener: código Python corregido automáticamente
└────────────────┘
```

---

## Contribuciones sobre el estado del arte

### 1. Análisis interprocedural básico

La mayoría de herramientas existentes pierden el rastro del taint cuando un dato pasa por una función. SecureFlow construye resúmenes de función para propagar correctamente:

```python
# Ambas funciones son analizadas en conjunto
def get_input():
    return request.form.get("usuario")   # fuente de taint

def login():
    usuario = get_input()                # taint propagado entre funciones
    cursor.execute("SELECT * WHERE u='" + usuario + "'")  # SINK detectado
```

### 2. Traza completa del flujo de datos

```
[!] SQL_INJECTION detectado en login()
    ├── FUENTE  línea 3:  usuario = request.form.get("usuario")
    ├── FLUJO   línea 7:  query = "SELECT..." + usuario
    ├── FLUJO   línea 8:  query = query + "'"
    └── SINK    línea 9:  cursor.execute(query)  ← VULNERABLE
```

### 3. Generación de código endurecido

```python
# Código original (vulnerable):
cursor.execute("SELECT * WHERE u='" + usuario + "'")

# Código generado por SecureFlow (seguro):
cursor.execute("SELECT * WHERE u=?", (usuario,))
```

---

## Estructura del repositorio

```
secureflow/
├── main.py                         # CLI + orquestador del pipeline
├── analyzer/
│   ├── lexer.py                    # Fase 1: Tokenizador
│   ├── parser.py                   # Fase 2: Parser LL(k) + AST
│   ├── semantic.py                 # Fase 3: Tabla de símbolos
│   ├── ir.py                       # Definición de TAC, bloques, CFG
│   ├── ir_gen.py                   # Fase 4: Generador de IR
│   ├── cfg_builder.py              # Fase 5: Constructor del CFG
│   ├── taint_engine.py             # Fase 6: Motor de taint + worklist
│   ├── interprocedural.py          # Resúmenes de función
│   ├── sources_sinks.py            # Catálogo de fuentes, sinks y sanitizadores
│   └── reporter.py                 # Salida ANSI + JSON + traza
├── codegen/
│   └── hardener.py                 # Generación de código seguro
├── examples/
│   ├── vulnerable_login.py         # Caso: autenticación vulnerable
│   ├── vulnerable_dni.py           # Caso: consulta por DNI
│   ├── vulnerable_interprocedural.py  # Caso: flujo entre funciones
│   └── safe_login.py               # Referencia: versión segura
└── tests/
    ├── test_lexer.py
    ├── test_parser.py
    ├── test_semantic.py
    ├── test_ir_gen.py
    ├── test_taint.py
    └── test_interprocedural.py
```

---

## Uso

```bash
# Analizar un archivo
python main.py examples/vulnerable_login.py

# Guardar reporte en JSON (útil para CI/CD)
python main.py examples/vulnerable_login.py --output json --save report.json

# Generar versión endurecida del código
python main.py examples/vulnerable_login.py --harden --out safe_login.py
```

---

## Ejemplo de salida

```
SecureFlow v1.0 — Análisis de seguridad estático
══════════════════════════════════════════════════

[FASE 1] Análisis léxico        ✓  47 tokens
[FASE 2] Análisis sintáctico    ✓  AST: 12 nodos
[FASE 3] Análisis semántico     ✓  8 símbolos, 2 marcados como tainted
[FASE 4] Generación de IR       ✓  31 instrucciones TAC
[FASE 5] Construcción del CFG   ✓  5 bloques básicos
[FASE 6] Motor de taint         ✓  Worklist convergió en 3 iteraciones

══════════════════════════════════════════════════
⚠  VULNERABILIDADES DETECTADAS: 1
══════════════════════════════════════════════════

[SQL_INJECTION] en función login() — vulnerable_login.py
  ├── FUENTE  línea  3  usuario = request.form.get("usuario")
  ├── FLUJO   línea  7  query = "SELECT * FROM users WHERE u='" + usuario
  └── SINK    línea  8  cursor.execute(query)

Generando código endurecido → safe_login.py ✓
```

---

## Limitaciones actuales

- El parser cubre un subconjunto de Python 3 suficiente para los patrones de acceso a base de datos más comunes. Construcciones avanzadas (decoradores complejos, comprehensions anidadas, metaclases) no están contempladas en esta versión.
- El análisis interprocedural es de una sola pasada; llamadas recursivas no se modelan.
- El endurecimiento automático cubre el patrón de concatenación de cadenas hacia `execute()`. Otros patrones de construcción de queries requieren intervención manual.

---

## Contexto académico

Este proyecto fue desarrollado como trabajo final del curso de Compiladores. Las vulnerabilidades de los casos de prueba están basadas en patrones documentados en portales gubernamentales peruanos (RENIEC, padrón electoral), con el fin de validar el sistema en un contexto aplicado real.

**Referencias principales**

- Livshits & Lam (2005). *Finding Security Vulnerabilities in Java Applications with Static Analysis.* USENIX Security.
- Newsome & Song (2005). *Dynamic Taint Analysis for Automatic Detection, Analysis, and Signature Generation of Exploits on Commodity Software.* NDSS.
- OWASP. *SQL Injection Prevention Cheat Sheet.*

---

## Licencia

MIT License — uso académico y de investigación libre.
