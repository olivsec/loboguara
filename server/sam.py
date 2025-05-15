import psycopg2
import bcrypt
import getpass

# Database configuration – update as needed
DB_HOST = 'localhost'
DB_PORT = 5432
DB_NAME = 'guaradb'
DB_USER = 'guarauser'
DB_PASSWORD = 'your_password'

def connect_db():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD
    )

def create_superadmin():
    username = input("Enter new username: ").strip()
    email = input("Enter email address: ").strip()
    password = getpass.getpass("Enter password: ").strip()

    password_hash = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        conn = connect_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, email))
        if cur.fetchone():
            print("Error: A user with this username or email already exists.")
        else:
            cur.execute("""
                INSERT INTO users (username, email, password, is_admin, is_superadmin)
                VALUES (%s, %s, %s, TRUE, TRUE)
            """, (username, email, password_hash))
            conn.commit()
            print("Superadmin user created successfully.")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error creating superadmin: {e}")

def change_superadmin_password():
    username = input("Enter the superadmin username: ").strip()
    new_password = getpass.getpass("Enter new password: ").strip()
    password_hash = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    try:
        conn = connect_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s AND is_superadmin = TRUE", (username,))
        if cur.fetchone():
            cur.execute("UPDATE users SET password = %s WHERE username = %s", (password_hash, username))
            conn.commit()
            print("Password updated successfully.")
        else:
            print("User not found or is not a superadmin.")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error changing password: {e}")

def promote_to_superadmin():
    username = input("Enter the username to promote: ").strip()

    try:
        conn = connect_db()
        cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username = %s", (username,))
        if cur.fetchone():
            cur.execute("""
                UPDATE users SET is_admin = TRUE, is_superadmin = TRUE
                WHERE username = %s
            """, (username,))
            conn.commit()
            print("User successfully promoted to superadmin.")
        else:
            print("User not found.")
        cur.close()
        conn.close()
    except Exception as e:
        print(f"Error promoting user: {e}")

def show_menu():
    print("\nSelect an option:")
    print("1. Create a new superadmin user")
    print("2. Change the password of an existing superadmin")
    print("3. Promote an existing user to superadmin")
    choice = input("Your choice (1/2/3): ").strip()

    if choice == '1':
        create_superadmin()
    elif choice == '2':
        change_superadmin_password()
    elif choice == '3':
        promote_to_superadmin()
    else:
        print("Invalid option selected.")

if __name__ == "__main__":
    show_menu()
