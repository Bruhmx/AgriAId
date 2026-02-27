# db_migrate.py
from db_config import get_db


def run_migration():
    print("🔄 Running database migration...")

    db = get_db()
    cursor = db.cursor()

    # Check if table exists
    cursor.execute("""
        SELECT COUNT(*) as count 
        FROM information_schema.tables 
        WHERE table_name = 'diagnosis_history'
    """)

    if cursor.fetchone()[0] == 0:
        print("❌ Table 'diagnosis_history' doesn't exist!")
        print("Creating table...")

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS diagnosis_history (
                id INT AUTO_INCREMENT PRIMARY KEY,
                user_id INT NOT NULL,
                image_path VARCHAR(255),
                image_filename VARCHAR(255),
                crop VARCHAR(50) NOT NULL,
                disease_detected VARCHAR(100) NOT NULL,
                confidence DECIMAL(5,2) NOT NULL,
                symptoms TEXT,
                recommendations TEXT,
                final_confidence_level VARCHAR(50),
                expert_answers JSON,
                expert_summary JSON,
                for_training BOOLEAN DEFAULT TRUE,
                training_used BOOLEAN DEFAULT FALSE,
                image_processed BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
                INDEX idx_user_id (user_id),
                INDEX idx_created_at (created_at),
                INDEX idx_for_training (for_training),
                INDEX idx_training_used (training_used)
            )
        """)
        print("✅ Table created successfully!")

    # Add missing columns
    columns_to_add = [
        ('image_filename', 'VARCHAR(255) AFTER image_path'),
        ('final_confidence_level', 'VARCHAR(50) AFTER recommendations'),
        ('expert_answers', 'JSON AFTER final_confidence_level'),
        ('expert_summary', 'JSON AFTER expert_answers'),
        ('for_training', 'BOOLEAN DEFAULT TRUE'),
        ('training_used', 'BOOLEAN DEFAULT FALSE'),
        ('image_processed', 'BOOLEAN DEFAULT FALSE')
    ]

    for column_name, column_def in columns_to_add:
        cursor.execute(f"""
            SELECT COUNT(*) as count 
            FROM information_schema.columns 
            WHERE table_name = 'diagnosis_history' 
            AND column_name = '{column_name}'
        """)

        if cursor.fetchone()[0] == 0:
            print(f"➕ Adding column: {column_name}")
            cursor.execute(f"ALTER TABLE diagnosis_history ADD COLUMN {column_name} {column_def}")

    db.commit()
    cursor.close()
    db.close()

    print("✅ Migration complete!")


if __name__ == "__main__":
    run_migration()