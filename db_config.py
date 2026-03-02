# db_config.py
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor
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
        # Get the DATABASE_URL from environment (Render provides this automatically)
        database_url = os.getenv("DATABASE_URL")
        
        if database_url:
            # If DATABASE_URL exists (Render provides this), use it
            # Note: Render's PostgreSQL DATABASE_URL might need modification
            # Sometimes it starts with postgres:// but psycopg2 needs postgresql://
            if database_url.startswith("postgres://"):
                database_url = database_url.replace("postgres://", "postgresql://", 1)
            
            # Create connection pool with DATABASE_URL
            connection_pool = pool.SimpleConnectionPool(
                minconn=1,
                maxconn=15,  # Reduced pool size for PostgreSQL
                dsn=database_url,
                connect_timeout=30
            )
        else:
            # Fallback to individual parameters if DATABASE_URL doesn't exist
            db_config = {
                "host": os.getenv("DB_HOST", "localhost"),
                "user": os.getenv("DB_USER", "postgres"),
                "password": os.getenv("DB_PASSWORD", ""),
                "database": os.getenv("DB_NAME", "agriaid"),
                "port": int(os.getenv("DB_PORT", 5432)),
                "connect_timeout": 30,
            }
            
            connection_pool = pool.SimpleConnectionPool(
                minconn=1,
                maxconn=15,
                **db_config
            )
        
        print(f"✅ PostgreSQL connection pool created successfully")
        print(f"   Pool size: 15")
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
        connection = connection_pool.getconn()
        return connection
    except Exception as e:
        print(f"❌ Error getting database connection from pool: {e}")
        # Try to reinitialize and get connection again
        if init_db_pool():
            return connection_pool.getconn()
        raise


def return_db(connection):
    """Return a connection to the pool"""
    global connection_pool
    if connection_pool and connection:
        try:
            connection_pool.putconn(connection)
        except Exception as e:
            print(f"❌ Error returning connection to pool: {e}")


# ========== CONTEXT MANAGERS ==========
@contextmanager
def get_db_cursor():
    """Context manager for database connections - automatically returns connection to pool"""
    db = None
    cur = None
    try:
        db = get_db()
        cur = db.cursor(cursor_factory=RealDictCursor)
        yield cur
        db.commit()
    except Exception as e:
        if db:
            db.rollback()
        raise e
    finally:
        # ALWAYS close cursor and return connection to pool
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
        cur = db.cursor(cursor_factory=RealDictCursor)
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
        return {"status": "not_initialized", "pool": None}

    try:
        # Get pool info
        info = {
            "status": "active",
            "min_connections": getattr(connection_pool, '_minconn', 'unknown'),
            "max_connections": getattr(connection_pool, '_maxconn', 'unknown'),
            "closed": getattr(connection_pool, '_closed', 'unknown'),
        }

        # Try to get connection counts
        if hasattr(connection_pool, '_pool'):
            info["connections_in_use"] = len(connection_pool._pool)
            info["connections_available"] = connection_pool._maxconn - len(connection_pool._pool)

        return info

    except Exception as e:
        return {"status": "error", "error": str(e)}