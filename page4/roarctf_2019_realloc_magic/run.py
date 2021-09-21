import subprocess 

while True:
    p = subprocess.run(["python3", "wp_pwn.py"])
    if p.returncode == 1:
        # 1 means error, 0 means success
        continue
    break


