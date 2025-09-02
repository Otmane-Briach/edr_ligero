# eBPF-EDR

**Recopilador ligero de eventos del kernel basado en eBPF para EDR en Linux**

Este proyecto implementa un sistema de **detección y respuesta para endpoints (EDR)** orientado a la identificación de ransomware y malware en sistemas Linux. Se apoya en **eBPF** para monitorizar llamadas críticas al sistema con bajo impacto en el rendimiento.

---

## ✨ Características
- Monitorización en tiempo real de syscalls críticas (`execve`, `openat`, `write`, `unlink`, `chmod`, `connect`, etc.)
- Detección **estática** por hash SHA-256 de binarios conocidos
- Detección **dinámica** basada en heurísticas y scoring de comportamiento
- Persistencia de eventos en **SQLite** para análisis forense
- Integración con **Grafana** para visualización en tiempo real
- Respuesta activa (suspender o terminar procesos sospechosos)

---

## ⚙️ Requisitos
- Linux con soporte **eBPF** (kernel 5.x+)
- **Python 3** con BCC (BPF Compiler Collection)
- **SQLite** para almacenamiento
- **Grafana** para dashboards opcionales

---

## 🚀 Uso
```bash
git clone https://github.com/tuusuario/edr-ebpf.git
cd edr-ebpf
sudo -v && sudo python3 collector.py 2>/tmp/edr.err | python3 hash_detection_detector.py > ~/Desktop/mini-edr-ebp/edr_alerts.log 2>&1
