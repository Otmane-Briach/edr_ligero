el sumary text: 
================================================
BENCHMARK COMPILACIÓN - INFORME TÉCNICO
================================================
Fecha: Sat Aug 30 09:53:17 PM CEST 2025
Sistema: edr-VMware-Virtual-Platform
Kernel: 6.14.0-27-generic
CPUs: 2 cores
Arquitectura: x86_64

CONFIGURACIÓN DEL TEST
----------------------
Muestras: 3
Iteraciones: 100 compilaciones por muestra
Compilador: gcc con -O2
Programa: test_program.c (cálculos matemáticos)

RESULTADOS DE TIEMPO
--------------------
Tiempo total sin EDR:       20.78 segundos
Tiempo total con EDR:       56.78 segundos
Overhead temporal:          173.00%

Tiempo por compilación:
  Sin EDR:                  .207 segundos
  Con EDR:                  .567 segundos

MÉTRICAS DE CPU
---------------
Componentes del EDR:
  Collector (eBPF):         0.02%
  Detector (Python):        7.61%
  Total EDR:                7.62%
  Pico máximo:              0.00%

EVALUACIÓN
----------
Overhead temporal:          ALTO
CPU del EDR:               EXCELENTE

CONCLUSIONES
------------
El overhead del 173.00% indica un impacto significativo
en el rendimiento durante tareas intensivas de compilación.
Esto es esperado en un EDR que intercepta todas las syscalls,
pero podría optimizarse mediante:
1. Filtrado más selectivo en eBPF
2. Optimización del detector Python
3. Uso de estructuras de datos más eficientes
4. Reducción de la frecuencia de muestreo

ARCHIVOS GENERADOS
------------------
Tiempos: benchmark_results/compile/*/time_*.txt
CPU: benchmark_results/compile/*/cpu_*.csv
Resumen: benchmark_results/compile/summary.txt
================================================










edr@edr-VMware-Virtual-Platform:~/Desktop/mini-edr-ebpf$ ./benchmark.sh 

=========================================
BENCHMARK COMPILACIÓN - OVERHEAD DEL EDR
=========================================
Compilando programa C de prueba
=========================================
Verificando dependencias...

[1/4] Limpieza inicial...
[sudo] password for edr: 

[2/4] BASELINE - Compilación sin EDR
--------------------------------------
  Muestra 1/3...
    Compilando 100 veces...
      20/100 completadas...
      40/100 completadas...
      60/100 completadas...
      80/100 completadas...
      100/100 completadas...
    Tiempo total: 21.16 segundos
    Tiempo por compilación: 0.212 segundos
  Muestra 2/3...
    Compilando 100 veces...
      20/100 completadas...
      40/100 completadas...
      60/100 completadas...
      80/100 completadas...
      100/100 completadas...
    Tiempo total: 20.40 segundos
    Tiempo por compilación: 0.204 segundos
  Muestra 3/3...
    Compilando 100 veces...
      20/100 completadas...
      40/100 completadas...
      60/100 completadas...
      80/100 completadas...
      100/100 completadas...
    Tiempo total: 20.79 segundos
    Tiempo por compilación: 0.208 segundos

[3/4] TEST - Compilación con EDR
---------------------------------
  Muestra 1/3...
    Iniciando EDR...
    PIDs: Collector=30469, Detector=30470
    Compilando 100 veces...
      20/100 completadas...
      40/100 completadas...
      60/100 completadas...
      80/100 completadas...
      100/100 completadas...
    Tiempo total: 55.38 segundos
    Tiempo por compilación: 0.554 segundos
    CPU promedio - Collector: 0.03%, Detector: 6.81%
    Deteniendo EDR...
  Muestra 2/3...
    Iniciando EDR...
    PIDs: Collector=31604, Detector=31605
    Compilando 100 veces...
      20/100 completadas...
      40/100 completadas...
      60/100 completadas...
      80/100 completadas...
      100/100 completadas...
    Tiempo total: 57.98 segundos
    Tiempo por compilación: 0.580 segundos
    CPU promedio - Collector: 0.01%, Detector: 8.10%
    Deteniendo EDR...
  Muestra 3/3...
    Iniciando EDR...
    PIDs: Collector=32771, Detector=32772
    Compilando 100 veces...
      20/100 completadas...
      40/100 completadas...
      60/100 completadas...
      80/100 completadas...
      100/100 completadas...
    Tiempo total: 57.00 segundos
    Tiempo por compilación: 0.570 segundos
    CPU promedio - Collector: 0.02%, Detector: 8.00%
    Deteniendo EDR...

[4/4] ANÁLISIS DE RESULTADOS
=========================================
TIEMPOS DE COMPILACIÓN:
------------------------
Total sin EDR:              20.78 segundos
Total con EDR:              56.78 segundos
Por compilación sin EDR:    0.207 segundos
Por compilación con EDR:    0.567 segundos
OVERHEAD TEMPORAL:          173.00%

USO DE CPU DEL EDR:
-------------------
Collector (eBPF):           0.02%
Detector (Python):          7.61%
TOTAL EDR:                  7.62%
PICO MÁXIMO:                0.00%


=========================================
✓ BENCHMARK COMPILACIÓN COMPLETADO
=========================================
Resumen guardado en: benchmark_results/compile/summary.txt

Overhead detectado: 173.00%
Próximo paso: 4_benchmark_io.sh
edr@edr-VMware-Virtual-Platform:~/Desktop/mini-edr-ebpf$ 


