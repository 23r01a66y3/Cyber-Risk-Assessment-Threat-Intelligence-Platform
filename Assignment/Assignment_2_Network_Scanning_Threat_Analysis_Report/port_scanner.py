import subprocess

class PortScanner:
    def __init__(self, target):
        self.target = target

    def basic_scan(self):
        print(f"Running basic scan on {self.target}...")
        return self._run_command(["nmap", self.target])

    def version_scan(self):
        print(f"Running service and version detection on {self.target}...")
        return self._run_command(["nmap", "-sV", self.target])

    def full_scan(self):
        print(f"Running full port scan on {self.target}... This will take time.")
        return self._run_command(["nmap", "-p-", self.target])

    def _run_command(self, cmd):
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
            return result.stdout
        except subprocess.CalledProcessError as e:
            return f"Error executing scan: {e.stderr}"
        except FileNotFoundError:
             return "Error: nmap is not installed or not found in system PATH."
