# db_config.py
import mysql.connector
from mysql.connector import pooling
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
        # Create connection pool configuration - REDUCED POOL SIZE
        db_config = {
            "host": os.getenv("DB_HOST", "localhost"),
            "user": os.getenv("DB_USER", "root"),
            "password": os.getenv("DB_PASSWORD", ""),
            "database": os.getenv("DB_NAME", "agriaid"),
            "port": int(os.getenv("DB_PORT", 3306)),
            "pool_name": "agriaid_pool",
            "pool_size": 5,  # REDUCED FROM 30 TO 5
            "pool_reset_session": True,
            "autocommit": False,  # CHANGED TO False - better control
            "use_pure": True,
            "buffered": True,
            "connection_timeout": 30,  # ADDED timeout
        }

        # Create connection pool
        connection_pool = pooling.MySQLConnectionPool(**db_config)
        print(f"✅ Database connection pool created successfully")
        print(f"   Pool name: {db_config['pool_name']}")
        print(f"   Pool size: {db_config['pool_size']}")
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
        # Try to reinitialize pool
        print("⚠️ Connection pool not initialized, attempting to reinitialize...")
        if not init_db_pool():
            raise Exception("Database connection pool not initialized")

    try:
        connection = connection_pool.get_connection()
        # REMOVED the print statement - too noisy
        return connection
    except Exception as e:
        print(f"❌ Error getting database connection from pool: {e}")
        # Try to reinitialize and get connection again
        if init_db_pool():
            return connection_pool.get_connection()
        raise


# ========== NEW: CONTEXT MANAGER ==========
@contextmanager
def get_db_cursor():
    """Context manager for database connections - automatically closes"""
    db = None
    cur = None
    try:
        db = get_db()
        cur = db.cursor(dictionary=True)
        yield cur
        db.commit()
    except Exception as e:
        if db:
            db.rollback()
        raise e
    finally:
        # ALWAYS close cursor and connection
        if cur:
            try:
                cur.close()
            except:
                pass
        if db:
            try:
                db.close()  # Returns connection to pool
            except:
                pass


# ========== NEW: SIMPLE CURSOR (without commit) ==========
@contextmanager
def get_db_cursor_readonly():
    """Context manager for read-only operations"""
    db = None
    cur = None
    try:
        db = get_db()
        cur = db.cursor(dictionary_name=True)
        yield cur
    finally:
        if cur:
            try:
                cur.close()
            except:
                pass
        if db:
            try:
                db.close()
            except:
                pass


def get_pool_info():
    """Get information about the connection pool"""
    global connection_pool

    if connection_pool is None:
        return {"status": "not_initialized", "pool": None}

    try:
        # Get available attributes safely
        info = {
            "status": "active",
            "pool_name": getattr(connection_pool, 'pool_name', 'unknown'),
            "pool_size": getattr(connection_pool, 'pool_size', 'unknown'),
        }

        # Try to get pool stats if available
        try:
            # This might work in some versions
            if hasattr(connection_pool, '_cnx_queue'):
                info["connections_in_use"] = len(connection_pool._cnx_queue)
            if hasattr(connection_pool, '_cnx_avail'):
                info["connections_available"] = len(connection_pool._cnx_avail)
        except:
            pass

        return info

    except Exception as e:
        return {"status": "error", "error": str(e)}