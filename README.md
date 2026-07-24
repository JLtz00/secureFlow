# SecureFlow

**A Compiler-Integrated Taint Analysis Framework for SQL Injection Detection in Python-Based Government Systems**

SecureFlow es un framework académico de análisis estático que integra *taint analysis* directamente dentro de un pipeline de compilación construido desde cero. Su objetivo es detectar y corregir automáticamente vulnerabilidades de inyección SQL en sistemas Python, con énfasis en portales gubernamentales.

## Estado implementado

SecureFlow ya tiene una base ejecutable de extremo a extremo:

- `analyzer/lexer.py`: convierte codigo Python en tokens con tipo, valor, linea y columna. Incluye `INDENT`, `DEDENT`, strings multilinea, f-strings, comentarios omitidos y recuperacion con `ERROR`.
- `analyzer/ast_nodes.py`: define el AST propio de SecureFlow, sin usar el modulo `ast` de Python.
- `analyzer/parser.py`: parser recursivo descendente LL para funciones, asignaciones, `if`, `while`, `for`, `return`, llamadas y expresiones binarias.
- `analyzer/python_ast_frontend.py`: frontend de produccion basado en `ast` de Python; reporta nodos soportados, aproximados e ignorados.
- `analyzer/ast_visualizer.py`: imprime el arbol para explicar como el codigo fuente se transforma en estructura analizable.
- `analyzer/symbols.py`, `analyzer/scope.py` y `analyzer/semantic.py`: construyen tabla de simbolos, scopes, resolucion de nombres, tipos simples y taint inicial.
- `analyzer/ir.py` y `analyzer/ir_generator.py`: definen y generan codigo de tres direcciones.
- `analyzer/cfg_builder.py` y `analyzer/cfg_visualizer.py`: construyen y muestran bloques basicos mediante el algoritmo de lideres.
- `analyzer/taint_engine.py`: ejecuta analisis de taint forward con Worklist sobre el CFG.
- `analyzer/interprocedural.py`: construye resumenes sensibles a parametros para propagar taint entre llamadas.
- `analyzer/project_scanner.py`: escanea proyectos Flask multiarchivo, resuelve imports, aliases, metodos ligados y dependencias inyectadas por constructor, y expone telemetria de cobertura.
- `analyzer/framework_profiles.py`: modela Flask, DB-API, SQLite, PostgreSQL, MySQL y SQLAlchemy, con extension TOML.
- `tools/secureflow_scan.py`: expone un CLI con salida JSON y SARIF.
- `analyzer/hardener.py`: genera una version parametrizada para patrones simples de concatenacion SQL.
- `tests/`: contiene pruebas automatizadas de las fases implementadas.

Demo completa para clase:

```bash
make demo
```

Demo solo del arbol AST:

```bash
python3 -m analyzer.ast_visualizer
```

La demo muestra tokens, AST, scopes, simbolos, taint inicial, TAC, CFG, deteccion real de SQL Injection, traza source-to-sink, hardening automatico y escaneo Flask multiarchivo.

## Modos de ejecucion

SecureFlow tiene dos frontends:

| Modo | Frontend | Uso recomendado |
|---|---|---|
| Academico | Lexer/parser propio | Explicar fases de compiladores: tokens, AST, IR, CFG y Worklist. |
| Produccion | `python-ast` | Escanear codigo Flask real con mayor cobertura de gramatica Python. |

El scanner usa `python-ast` por defecto:

```bash
# Salida legible para una demostracion
./secureflow scan data/flask_projects/project_multifile_vulnerable

# Analizar un solo archivo
./secureflow scan data/flask_dataset/flask_multistep_query.py

# Formatos para automatizacion
./secureflow scan ./mi_proyecto --format json
./secureflow scan ./mi_proyecto --format sarif -o reports/secureflow.sarif

# Otras opciones
./secureflow scan ./mi_proyecto --exclude tests
./secureflow scan data/flask_projects/project_multifile_vulnerable --frontend custom
./secureflow scan ./mi_proyecto --models config/secureflow_models.example.toml
```

Para una exposicion breve hay tres objetivos preparados:

```bash
make scan-demo-file  # archivo vulnerable: flujo dentro de una funcion
make scan-demo       # proyecto vulnerable: flujo entre varios archivos
make scan-demo-safe  # proyecto seguro: consulta parametrizada
```

El procedimiento completo y un guion oral estan en
[`GUIA_DEMOSTRACION.md`](GUIA_DEMOSTRACION.md).

El modo produccion diferencia `OK`, `APPROXIMATED`, `PARTIAL` y
`PARSE_ERROR`. Una ejecucion sin hallazgos no oculta construcciones ignoradas:
el JSON/SARIF incluye cobertura de nodos, llamadas internas sin enlace y APIs
externas tratadas mediante propagacion conservadora.

Las sentencias sin efecto como `pass` se bajan como no-op. El enlazador
interprocedural sigue tipos construidos y dependencias inyectadas entre rutas,
controladores, servicios y repositorios. Las APIs declarativas de ORM,
colecciones y bibliotecas externas se reportan aparte y no se confunden con
fallos de enlace del proyecto.

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
secureFlow/
├── analyzer/              # Pipeline del compilador y analisis de seguridad
├── demos/                 # Demostraciones ejecutables
│   └── demo_secureflow.py
├── examples/              # Programas pequenos para demostracion
├── tests/                 # Pruebas de todas las fases
├── tools/                 # Dataset, benchmark, rendimiento e informes
├── data/
│   ├── dataset/           # 210 programas del benchmark
│   └── dataset_metadata.json
├── reports/
│   ├── benchmarks/        # Resultados por herramienta
│   ├── performance/       # Mediciones del pipeline
│   ├── tables/            # Tablas para el informe
│   ├── figures/           # Datos CSV para graficos
│   ├── final/             # Resumen consolidado
│   └── research_report.md
├── docs/
│   ├── lexer_design.md
│   └── sprints/           # Roadmap y especificaciones Sprint 01-07
└── README.md
```

---

## Uso

```bash
# Demostracion recomendada para presentacion
make demo

# Pruebas y compilacion sintactica
make validate
make test
make pytest  # opcional, requiere instalar .[dev]
make compile

# Generar nuevamente el dataset
python3 -m tools.dataset_generator

# Ejecutar benchmark y evaluacion de rendimiento
python3 -m tools.benchmark_runner
python3 -m tools.performance_evaluator

# Generar y ejecutar benchmark enfocado en Flask
python3 -m tools.flask_dataset_generator
python3 -m tools.benchmark_runner --profile flask
python3 -m tools.flask_ablation
python3 -m tools.real_baseline_runner
python3 -m tools.flask_report
python3 -m tools.final_presentation_report

# Baselines reales en entorno aislado
python3 -m venv .venv
.venv/bin/python -m pip install -e ".[prod,baselines]"
make flask-baselines-real
make final-report
make reproduce-presentation

# Escanear un proyecto Flask multiarchivo
python3 -m tools.secureflow_scan scan ./data/flask_projects/project_multifile_vulnerable
python3 -m tools.secureflow_scan scan ./data/flask_projects/project_multifile_vulnerable --format sarif -o reports/secureflow.sarif
python3 -m tools.secureflow_scan scan ./mi_proyecto --models ./secureflow-models.toml

# Regenerar tablas, CSV e informe de investigacion
python3 -m tools.visualizer
python3 -m tools.research_report

```

---

## Resultados actuales

- Validacion interna sintetica de SecureFlow: `reports/final/summary.json`.
- Validacion interna Flask de SecureFlow: `reports/flask_research_report.md`.
- Baselines reales con Bandit y Semgrep: `reports/real_baselines_report.md`.
- Reporte final para exposicion: `reports/final/presentation_report.md`.
- Salida SARIF para CI/CD: `reports/secureflow.sarif`.

Nota metodologica: `tools/benchmark_runner.py` ejecuta unicamente SecureFlow
como validacion interna. Las comparaciones empiricas usan ejecuciones reales
de Bandit y Semgrep mediante `tools/real_baseline_runner.py`. Pysa se mantiene
como referencia teorica y no tiene metricas atribuidas en este repositorio.

---

## Limitaciones actuales

- El frontend de produccion acepta la gramatica soportada por la version instalada de CPython, pero algunas construcciones se aproximan o ignoran al bajarlas al IR. El scanner las informa explicitamente.
- El analisis interprocedural distingue parametros y resuelve imports estaticos, pero no modela reflexion, monkey patching, imports dinamicos ni sensibilidad de contexto profunda.
- Los access paths conservan atributos y claves estaticas de contenedores de forma conservadora; alias dinamicos y escrituras complejas pueden requerir revision.
- El hardener LibCST soporta concatenaciones, f-strings, multiples parametros y queries construidas en varias asignaciones, pero no reescribe todos los constructores SQLAlchemy.
- La evaluacion usa datasets sinteticos y Flask semirrealistas curados. Para una publicacion formal hace falta un corpus independiente de proyectos reales con commits y ground truth revisados.

---

## Contexto académico

Este proyecto fue desarrollado como trabajo final del curso de Compiladores. El valor principal es demostrar que una cadena clasica de compilacion puede servir como base para analisis estatico de seguridad: tokenizacion, AST, tabla de simbolos, IR, CFG y analisis de flujo de datos aplicados a SQL Injection en Python/Flask.

**Referencias principales**

- Livshits & Lam (2005). *Finding Security Vulnerabilities in Java Applications with Static Analysis.* USENIX Security.
- Newsome & Song (2005). *Dynamic Taint Analysis for Automatic Detection, Analysis, and Signature Generation of Exploits on Commodity Software.* NDSS.
- OWASP. *SQL Injection Prevention Cheat Sheet.*

---

## Licencia

MIT License — uso académico y de investigación libre.
