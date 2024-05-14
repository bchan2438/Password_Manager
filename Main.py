from cryptography.fernet import Fernet
import pandas as pd
import os
import tkinter as tk

def get_key():
    key_file = 'encryption_key.txt'
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, 'wb') as f:
            f.write(key)
    return key

def encrypt(password, cipher):
    encrypted = cipher.encrypt(password.encode()).decode('ascii')
    return encrypted

def decrypt(encrypted, cipher):
    decrypted = cipher.decrypt(encrypted.encode()).decode()
    return decrypted

def account_creation(username, password, confirm_password, feedback_text):
    feedback_text.delete(1.0, tk.END)  # Clear previous feedback
    if password.get() == confirm_password.get():
        if len(password.get()) < 6:  # Example: Minimum password length requirement
            feedback_text.insert(tk.END, "Password should be at least 6 characters long.")
        else:
            cipher = initialize_database()[1]
            encrypted_password = encrypt(password.get(), cipher)
            df.loc[len(df)] = [username.get(), encrypted_password]
            feedback_text.insert(tk.END, 'Account created successfully!')
            df.to_csv('Database.csv', index=False)
            # Clear input fields after successful account creation
            username.delete(0, tk.END)
            password.delete(0, tk.END)
            confirm_password.delete(0, tk.END)
    else:
        feedback_text.insert(tk.END, 'Passwords do not match. Please try again.')

def sign_in(username, password, feedback_text):
    feedback_text.delete(1.0, tk.END)  # Clear previous feedback
    filtered_df = df[df['Username'] == username.get()]

    if not filtered_df.empty:
        encrypted_password = filtered_df.iloc[0]['Password']
        decrypted_password = decrypt(encrypted_password, initialize_database()[1])

        if password.get() == decrypted_password:
            feedback_text.insert(tk.END, 'Success! Congrats on logging in')
            username.delete(0, tk.END)
            password.delete(0, tk.END)
        else:
            feedback_text.insert(tk.END, 'Incorrect password. Please try again')
            password.delete(0, tk.END)
    else:
        feedback_text.insert(tk.END, 'Username not found.')
        username.delete(0, tk.END)

def initialize_database():
    try:
        key = get_key()
        cipher = Fernet(key)
        df = pd.read_csv('Database.csv')
    except FileNotFoundError:
        print("Database file not found. Creating a new one...")
        df = pd.DataFrame(columns=['Username', 'Password'])
    except pd.errors.EmptyDataError:
        print("Database file is empty or corrupted. Creating a new one...")
        df = pd.DataFrame(columns=['Username', 'Password'])
    return df, cipher

def toggle_visibility(input_frame, action):
    # Toggle the visibility of input boxes based on action (Sign in or Create account)
    if action == "Sign in":
        input_frame.grid_forget()
    elif action == "Create account":
        input_frame.grid(row=1, column=0, columnspan=2)

def account_button_click(username, password, confirm_password, feedback_text):
    account_creation(username, password, confirm_password, feedback_text)

def sign_button_click(username, password, feedback_text):
    sign_in(username, password, feedback_text)

# Create the main application window
window = tk.Tk()

# Initialize database and cipher
df, cipher = initialize_database()

# Username Entry
username_label = tk.Label(window, text="Username:")
username_label.grid(row=0, column=0)
username = tk.Entry(window)
username.grid(row=0, column=1)

# Password Entry
pass_label = tk.Label(window, text="Password:")
pass_label.grid(row=1, column=0)
password = tk.Entry(window, show="*")
password.grid(row=1, column=1)

# Confirm Password Entry
confirm_pass_label = tk.Label(window, text="Confirm Password:")
confirm_pass_label.grid(row=2, column=0)
confirm_password = tk.Entry(window, show="*")
confirm_password.grid(row=2, column=1)

# Feedback Text
feedback_text = tk.Text(window, height=5, width=50)
feedback_text.grid(row=3, column=0, columnspan=2)

# Frame for input boxes
input_frame = tk.Frame(window)

# Account Creation Button
account_button = tk.Button(window, text="Create account", command=lambda: account_button_click(username, password, confirm_password, feedback_text))
account_button.grid(row=4, column=0)

# Sign In Button
sign_in_button = tk.Button(window, text="Sign In", command=lambda: sign_button_click(username, password, feedback_text))
sign_in_button.grid(row=4, column=1)

# Start the Tkinter event loop
window.mainloop()
