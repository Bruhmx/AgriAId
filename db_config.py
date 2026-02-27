# db_config.py
import psycopg2
from psycopg2 import pool
import os
from dotenv import load_dotenv
from contextlib import contextmanager

load_dotenv()

# Initialize connection_pool as None first
connection_pool = None


def init_db_pool():
    """Initialize the database connection pool"""
    global connection_pool

    try:
        # Get database URL from Render environment
        database_url = os.getenv("DATABASE_URL")
        
        if not database_url:
            # Fallback for local development
            database_url = os.getenv("LOCAL_DATABASE_URL", 
                "postgresql://postgres:password@localhost:5432/agriaid")
        
        # Create connection pool
        connection_pool = psycopg2.pool.SimpleConnectionPool(
            minconn=1,
            maxconn=5,  # Small pool for free tier
            dsn=database_url,
            sslmode='require'  # Render requires SSL
        )
        
        print(f"✅ PostgreSQL connection pool created successfully")
        return True

    except Exception as e:
        print(f"❌ Failed to create connection pool: {e}")
        import traceback
        traceback.print_exc()
        connection_pool = None
        return False


# Initialize the pool when module is imported
init_db_pool()


def get_db():
    """Get a database connection from the pool"""
    global connection_pool

    if connection_pool is None:
        print("⚠️ Connection pool not initialized, attempting to reinitialize...")
        if not init_db_pool():
            raise Exception("Database connection pool not initialized")

    try:
        connection = connection_pool.getconn()
        return connection
    except Exception as e:
        print(f"❌ Error getting database connection from pool: {e}")
        # Try to reinitialize and get connection again
        if init_db_pool():
            return connection_pool.getconn()
        raise


def return_db(connection):
    """Return connection to the pool"""
    global connection_pool
    if connection_pool and connection:
        connection_pool.putconn(connection)


@contextmanager
def get_db_cursor():
    """Context manager for database connections - automatically closes"""
    db = None
    cur = None
    try:
        db = get_db()
        cur = db.cursor()
        yield cur
        db.commit()
    except Exception as e:
        if db:
            db.rollback()
        raise e
    finally:
        if cur:
            try:
                cur.close()
            except:
                pass
        if db:
            try:
                return_db(db)
            except:
                pass


@contextmanager
def get_db_cursor_readonly():
    """Context manager for read-only operations"""
    db = None
    cur = None
    try:
        db = get_db()
        cur = db.cursor()
        yield cur
    finally:
        if cur:
            try:
                cur.close()
            except:
                pass
        if db:
            try:
                return_db(db)
            except:
                pass


def get_pool_info():
    """Get information about the connection pool"""
    global connection_pool

    if connection_pool is None:
        return {"status": "not_initialized"}

    try:
        return {
            "status": "active",
            "min_connections": getattr(connection_pool, 'minconn', 'unknown'),
            "max_connections": getattr(connection_pool, 'maxconn', 'unknown'),
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}