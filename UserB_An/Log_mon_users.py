import pygetwindow as gw
import time
from datetime import datetime


def print_active_window_title():
    last_active_window_title = None
    while True:
        try:
            active_window = gw.getActiveWindow()
            if active_window.title != last_active_window_title:
                current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                print(f"Active window title: {active_window.title} | Accessed at: {current_time}")
                last_active_window_title = active_window.title

                # Check if the active window title contains certain keywords
                if "settings" in active_window.title.lower() or "user" in active_window.title.lower():
                    print(f"Alert! User is trying to access settings or change user information at {current_time}")
        except Exception as e:
            print(f"An error occurred: {e}")

        time.sleep(1)  # delay for 1 second

if __name__ == "__main__":
    print_active_window_title()
