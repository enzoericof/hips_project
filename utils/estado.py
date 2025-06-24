import json
import os

STATE_FILE = '/home/kali/hips_project/config/estado.json'

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    with open(STATE_FILE, 'r') as f:
        return json.load(f)

def save_state(state):
    with open(STATE_FILE, 'w') as f:
        json.dump(state, f, indent=2)

def already_alerted(category, key):
    state = load_state()
    return key in state.get(category, [])

def mark_alerted(category, key):
    state = load_state()
    if category not in state:
        state[category] = []
    if key not in state[category]:
        state[category].append(key)
    save_state(state)
