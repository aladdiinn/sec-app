import time
try:
    with open("/proc/stat") as f: t1 = f.readline().split()
    time.sleep(0.3)
    with open("/proc/stat") as f: t2 = f.readline().split()
    idle1, total1 = int(t1[4]), sum(int(x) for x in t1[1:])
    idle2, total2 = int(t2[4]), sum(int(x) for x in t2[1:])
    dt = total2 - total1
    di = idle2 - idle1
    print("idle1:", idle1, "total1:", total1)
    print("idle2:", idle2, "total2:", total2)
    print("dt:", dt, "di:", di)
    print("cpu:", round((1 - di/dt) * 100, 1) if dt else 0)
except Exception as e:
    print("Err:", e)
