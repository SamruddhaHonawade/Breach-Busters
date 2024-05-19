import tkinter as tk

def login():
    username = entry_username.get()
    password = entry_password.get()
    
    # Add your login logic here
    
    if username == "admin" and password == "password":
        label_result.config(text="Login successful", fg="green")
    else:
        label_result.config(text="Login failed", fg="red")

# Create the main window
window = tk.Tk()
window.title("Login")

# Create the username label and entry
label_username = tk.Label(window, text="Username:")
label_username.pack()
entry_username = tk.Entry(window)
entry_username.pack()

# Create the password label and entry
label_password = tk.Label(window, text="Password:")
label_password.pack()
entry_password = tk.Entry(window, show="*")
entry_password.pack()

# Create the login button
button_login = tk.Button(window, text="Login", command=login)
button_login.pack()

# Create the result label
label_result = tk.Label(window, text="")
label_result.pack()

# Start the main loop
window.mainloop()
