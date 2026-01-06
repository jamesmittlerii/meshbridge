#!/usr/bin/env python3
import time
import os
import sys
import subprocess

def get_mtime(path):
    try:
        return os.stat(path).st_mtime
    except OSError:
        return 0

def main():
    if len(sys.argv) < 2:
        print("usage: ./watch.py <file_to_watch> <command...>")
        print("Example: ./watch.py decode.py ./decode.py --host ...")
        sys.exit(1)

    watch_file = sys.argv[1]
    command = sys.argv[2:]

    if not command:
        print("Error: No command provided.")
        sys.exit(1)

    # Smart inference: if command starts with arguments (flags), assume we want to run the watched file
    if command[0].startswith('-'):
        if watch_file.endswith('.py'):
            # Prepend python interpreter and script path
            command = [sys.executable, watch_file] + command
        elif os.access(watch_file, os.X_OK):
            # Prepend ./ for executable files
            command = [f"./{watch_file}"] + command

    print(f"Watching {watch_file} for changes...")
    print(f"Command: {' '.join(command)}")

    last_mtime = get_mtime(watch_file)
    process = subprocess.Popen(command)

    try:
        while True:
            time.sleep(1)
            current_mtime = get_mtime(watch_file)
            
            if current_mtime != last_mtime:
                print(f"\n[watch] File {watch_file} changed, restarting...")
                last_mtime = current_mtime
                
                # Kill previous process
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                
                # Restart process
                process = subprocess.Popen(command)
                
            # Check if process died
            if process.poll() is not None:
                # Optional: Uncomment to auto-restart on crash even without file change
                pass
                
    except KeyboardInterrupt:
        print("\n[watch] Stopping...")
        process.terminate()
        sys.exit(0)

if __name__ == "__main__":
    main()
