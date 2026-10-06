import os
from werkzeug.security import check_password_hash, generate_password_hash
import mysql.connector
import random
import uuid
from datetime import datetime, timedelta
from dotenv import load_dotenv
from faker import Faker

load_dotenv()
fake = Faker()

db_config = {
    
    'host': os.getenv('DB_HOST', 'localhost'),
    'user': os.getenv('DB_USER', 'root'),
    'password': os.getenv('DB_PASSWORD'),
    'database': os.getenv('DB_NAME', 'secure_file_system'),
}

def seed_database():
    if not db_config['password']:
     print("Database password is not set in environment variables.")
     return

    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()

    print("🧹 Wiping old test data (Admin table left completely untouched)...")

    # 1. Clean up old user data safely
    cursor.execute("SET FOREIGN_KEY_CHECKS = 0;")
    cursor.execute("TRUNCATE TABLE file_shares;")
    cursor.execute("TRUNCATE TABLE audit_log;")
    cursor.execute("TRUNCATE TABLE file;")
    cursor.execute("TRUNCATE TABLE user;")  # Safely wipes standard users
    cursor.execute("SET FOREIGN_KEY_CHECKS = 1;")
    conn.commit()

    print("✅ Wiped old user, file, share, and audit log records.")

    # 2. Seed Mock Users matching your EXACT schema
    user_ids = []
    statuses = ['active', 'active', 'active', 'pending'] # realistic user status spread
    roles = ['user', 'user', 'user', 'user']

    for i in range(8):
        email = fake.unique.email()
        raw_password = "pbkdf2:7777" # Example hash
        password_hash = generate_password_hash(raw_password)
        role = roles[i % len(roles)]
        status = statuses[i % len(statuses)]

        # Inserting into user table with your schema columns
        cursor.execute(
            """
            INSERT INTO user (email, password_hash, role, status) 
            VALUES (%s, %s, %s, %s)
            """,
            (email, password_hash, role, status)
        )
        user_ids.append(cursor.lastrowid)

    print(f"✅ Created {len(user_ids)} fresh mock users with u_id primary keys.")

    # 3. Seed Mock Files
    file_extensions = ['.pdf', '.docx', '.png', '.jpg', '.txt', '.xlsx']
    file_ids = []

    for _ in range(20):
        original_name = fake.word().capitalize() + random.choice(file_extensions)
        stored_uuid_name = f"{uuid.uuid4().hex}_{original_name}"
        owner_id = random.choice(user_ids)
        upload_date = fake.date_time_between(start_date='-30d', end_date='now')

        cursor.execute(
            """
            INSERT INTO file (f_name, f_path, owner_id, upload_date) 
            VALUES (%s, %s, %s, %s)
            """,
            (original_name, stored_uuid_name, owner_id, upload_date)
        )
        file_ids.append((cursor.lastrowid))

    print(f"✅ Created {len(file_ids)} mock file entries.")

    # 4. Seed Mock File Shares
    share_count = 0
    for f_id in file_ids:
        if random.random() < 0.4:
            cursor.execute("SELECT owner_id, upload_date FROM file WHERE f_id = %s", (f_id,))
            owner_id, upload_date = cursor.fetchone()
            recipient_id = random.choice([u for u in user_ids if u != owner_id])
            share_date = upload_date + timedelta(hours=random.randint(1, 24))

            cursor.execute(
                """
                INSERT INTO file_shares (file_id, shared_by, shared_with, created_at)
                VALUES (%s, %s, %s, %s)
                """,
                (f_id, owner_id, recipient_id, share_date)
            )
            share_count += 1

    print(f"✅ Created {share_count} mock file shares.")

    # 5. Seed Mock Audit Logs
    actions = ['LOGIN', 'FILE_UPLOAD', 'FILE_DOWNLOAD', 'FILE_SHARE']

    for _ in range(40):
      actor_id = random.choice(user_ids)
      action_type = random.choice(actions)
      log_time = fake.date_time_between(start_date='-30d', end_date='now')
      ip_addr = fake.ipv4()
      detail = f'Action {action_type} executed by user {actor_id}'
      chosen_file_id = random.choice(file_ids) if file_ids else None

      cursor.execute(
          """
            INSERT INTO audit_log 
            (actor_id, actor_type, action_type, detail, action_timestamp, file_id, ip_address, success)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
          (
              actor_id,
              'user',
              action_type,
              detail,
              log_time,
              chosen_file_id,
              ip_addr,
              True,
          ),
      )

    print("✅ Created 40 mock audit log entries.")

    conn.commit()
    cursor.close()
    conn.close()
    print("🚀 Database seeding complete! Your Admin table remains completely untouched.")

if __name__ == '__main__':
    # seed_database()
    print("seeding is disabled. database is locked with current 8 users.")