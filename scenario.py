SCENARIO_FILE = "scenario.txt"

def set_attack(name):
    with open(SCENARIO_FILE, "w") as f:
        f.write(name)


def get_attack():
    try:
        with open(SCENARIO_FILE, "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        return "NORMAL"