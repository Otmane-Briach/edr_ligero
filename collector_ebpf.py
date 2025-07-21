#!/usr/bin/env python3
#!/usr/bin/env python3
"""
collector.py - eBPF-based event collector y hash detection

# funcionalidades:
# - Carga programa eBPF para monitorizar syscalls: execve, openat, write (>=1 KB)
# - Captura metadatos (PID, PPID, UID/GID, comando, ruta, flags) y los emite en JSON
# - Para execve: calcula y compara SHA‑256 contra base local/MalwareBazaar y termina procesos maliciosos
# - Para openat: decodifica flags (RDONLY, CREAT, TRUNC, etc.)  
# - Para write: acumula contadores de operaciones y bytes, con debug cada 100 eventos  
# - Filtra ruido (p.ej. escrituras de tee o cat)  
# - Soporta CLI: --verbose, --download-hashes, --no-hash, --dry-kill  
# - Gestiona SIGINT/SIGTERM para limpieza de eBPF y estadísticas finales  
"""


from bcc import BPF
import json
import time
import argparse
import sys
import signal
import os

# Importar hash detection
try:
    from hash_detection_collector import HashDetectionEngine
    HASH_DETECTION_AVAILABLE = True
except ImportError:
    print("WARNING: hash_detection_collector.py not found. Hash detection disabled.", file=sys.stderr)
    HASH_DETECTION_AVAILABLE = False

b = None
hash_engine = None

def signal_handler(sig, frame):
    """Manejo de señales"""
    print("\nRecibida señal de parada, limpiando...", file=sys.stderr)
    if b:
        try:
            b.cleanup()
        except:
            pass
    if hash_engine:
        stats = hash_engine.get_statistics()
        print("\nHASH DETECTION STATISTICS:", file=sys.stderr)
        print(f"   Files scanned: {stats['files_scanned']}", file=sys.stderr)
        print(f"   Malware detected: {stats['malware_detected']}", file=sys.stderr)
        print(f"   Detection rate: {stats['detection_rate']:.2f}%", file=sys.stderr)
        print(f"   Database size: {stats['hash_database_size']}", file=sys.stderr)
    sys.exit(0)

BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 type;
    char comm[TASK_COMM_LEN];
    char filename[256];
    u32 flags;
};

BPF_PERF_OUTPUT(events);

static __always_inline u32 get_ppid(void) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task) return 0;
    struct task_struct *parent;
    bpf_probe_read_kernel(&parent, sizeof(parent), &task->real_parent);
    if (!parent) return 0;
    u32 ppid;
    bpf_probe_read_kernel(&ppid, sizeof(ppid), &parent->tgid);
    return ppid;
}

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 0;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.type = 1;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->flags;
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), (void*)args->filename);
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_write) {
    struct event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    // filtro >1KB
    if (args->count < 1024) return 0;
    data.type = 2;
    data.pid = pid_tgid >> 32;
    data.ppid = get_ppid();
    data.flags = args->count;
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = uid_gid & 0xFFFFFFFF;
    data.gid = uid_gid >> 32;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.filename[0] = '\0';
    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

TYPE_STR = {0: "EXEC", 1: "OPEN", 2: "WRITE"}
write_event_count = 0
total_write_bytes = 0

def terminate_malicious_process(pid, malware_info):
    """Terminar proceso malicioso"""
    try:
        proc_stat = f"/proc/{pid}/status"
        if os.path.exists(proc_stat):
            with open(proc_stat) as f:
                if "Uid:\t0\t" in f.read():
                    print(f"SEGURIDAD: NO terminando proceso root PID {pid}", file=sys.stderr)
                    return
        print(f"TERMINANDO PROCESO MALICIOSO PID {pid}", file=sys.stderr)
        os.kill(pid, 9)
    except Exception as e:
        print(f"Error terminando proceso {pid}: {e}", file=sys.stderr)

def decode_open_flags(flags):
    """Decodificar flags de open()"""
    if flags == 0: return "RDONLY"
    O_WRONLY, O_RDWR, O_CREAT, O_TRUNC, O_APPEND, O_EXCL = 0x1,0x2,0x40,0x200,0x400,0x80
    modes = []
    m = flags & 0x3
    modes.append({0:"RDONLY",O_WRONLY:"WRONLY",O_RDWR:"RDWR"}.get(m,"RDONLY"))
    for bit, name in ((O_CREAT,"CREAT"),(O_TRUNC,"TRUNC"),(O_APPEND,"APPEND"),(O_EXCL,"EXCL")):
        if flags & bit: modes.append(name)
    return "|".join(modes)

def handle_event(cpu, data, size):
    """Procesar eventos + JSON compacto y filtro de ruido"""
    global hash_engine, write_event_count, total_write_bytes
    try:
        event = b["events"].event(data)
        comm = event.comm.decode(errors='ignore').rstrip('\x00')
        filename = event.filename.decode(errors='ignore').rstrip('\x00')
        output = {
            "timestamp": time.time(),
            "pid": event.pid,
            "ppid": event.ppid,
            "uid": event.uid,
            "gid": event.gid,
            "type": TYPE_STR.get(event.type,"UNKNOWN"),
            "comm": comm
        }

        if event.type == 0:  # EXEC
            output["path"] = filename
            if hash_engine and HASH_DETECTION_AVAILABLE:
                res = hash_engine.scan_process_binary(event.pid, comm, filename)
                if res.get("malicious"):
                    output.update({
                        "MALWARE_DETECTED": True,
                        "hash": res["hash"],
                        "malware_info": res["malware_info"],
                        "scan_method": res.get("scan_method")
                    })
                    terminate_malicious_process(event.pid, res["malware_info"])
                elif res.get("scanned"):
                    output.update({"hash": res["hash"], "scan_clean": True, "scan_method": res.get("scan_method")})

        elif event.type == 1:  # OPEN
            output["path"] = filename
            output["flags"] = event.flags
            output["flags_decoded"] = decode_open_flags(event.flags)

        elif event.type == 2:  # WRITE
            bytes_written = event.flags
            output["bytes_written"] = bytes_written
            write_event_count += 1
            total_write_bytes += bytes_written
            if write_event_count % 100 == 0:
                print(f"DEBUG COLLECTOR: {write_event_count} events, {total_write_bytes} bytes", file=sys.stderr)

        # 1) filtro ruido de pipeline
        if event.type == 2 and comm in ("tee","cat"):
            return

        # 2) JSON compacto
        try:
            j = json.dumps(output, separators=(",",":"))
            print(j, flush=True)
            if event.type == 2:
                print(f"DEBUG JSON WRITE: {j[:100]}...", file=sys.stderr)
        except BrokenPipeError:
            sys.exit(0)
        except Exception as e:
            print(f"ERROR JSON output: {e}", file=sys.stderr)
    except Exception as e:
        if "WRITE" in str(e):
            print(f"ERROR procesando WRITE: {e}", file=sys.stderr)

def main():
    global b, hash_engine
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGPIPE, signal.SIG_DFL)

    p = argparse.ArgumentParser()
    p.add_argument("-v","--verbose", action="store_true")
    p.add_argument("--no-hash", action="store_true")
    p.add_argument("--download-hashes", action="store_true")
    p.add_argument("--hash-only-samples", action="store_true")
    p.add_argument("--dry-kill", action="store_true")
    args = p.parse_args()

    if args.verbose:
        print("🚀 EDR Collector WRITE CORREGIDO iniciando...", file=sys.stderr)

    if not args.no_hash and HASH_DETECTION_AVAILABLE:
        hash_engine = HashDetectionEngine()
        hash_engine.setup_database(download_real=(args.download_hashes and not args.hash_only_samples))

    try:
        if args.verbose:
            print("Compilando eBPF...", file=sys.stderr)
        b = BPF(text=BPF_PROGRAM)
        b["events"].open_perf_buffer(handle_event)

        if args.verbose:
            print("Monitorizando syscalls...", file=sys.stderr)
        while True:
            b.perf_buffer_poll()
    except Exception as e:
        print(f"Error fatal: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        if b:
            try: b.cleanup()
            except: pass
        if args.verbose:
            print(f"\n Estadísticas WRITE: {write_event_count} eventos, {total_write_bytes} bytes", file=sys.stderr)

if __name__=="__main__":
    main()
