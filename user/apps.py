import os
import sys
from django.apps import AppConfig
from django.db import connections
from django.core.management.color import color_style
from django.conf import settings
import threading


class UserConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'user'
    
    def ready(self):
        # Only run database check in the main thread and avoid multiple runs
        if not hasattr(self, '_startup_run') and not threading.current_thread().name.startswith('Thread-'):
            self._startup_run = True
            # Only show messages when running the server, not during migrations
            if 'runserver' in sys.argv:
                self.check_database_connection()
    
    def check_database_connection(self):
        style = color_style()
        db_config = settings.DATABASES['default']
        
        # Get database info
        db_engine = db_config.get('ENGINE', '')
        db_name = db_config.get('NAME', '')
        db_user = db_config.get('USER', '')
        db_host = db_config.get('HOST', '')
        db_port = db_config.get('PORT', '')
        
        # Determine database type
        if 'postgresql' in db_engine:
            db_type = "PostgreSQL"
        elif 'sqlite' in db_engine:
            db_type = "SQLite"
        elif 'mysql' in db_engine:
            db_type = "MySQL"
        else:
            db_type = "Unknown"
        
        try:
            # Test database connection
            db_conn = connections['default']
            with db_conn.cursor() as cursor:
                if 'postgresql' in db_engine:
                    cursor.execute("SELECT version();")
                    version = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT current_database();")
                    current_db = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT current_user;")
                    current_user = cursor.fetchone()[0]
                    
                    # Beautiful PostgreSQL success message
                    print("\n" + "🟢" * 60)
                    print(style.SUCCESS("🚀 ZEFE SOLANA MOBILE BACKEND - STARTED SUCCESSFULLY! 🚀"))
                    print("🟢" * 60)
                    print(style.SUCCESS(f"✅ Database Type: {db_type}"))
                    print(style.SUCCESS(f"✅ Database Name: {current_db}"))
                    print(style.SUCCESS(f"✅ Connected as: {current_user}"))
                    print(style.SUCCESS(f"✅ Host: {db_host}:{db_port}"))
                    print(style.SUCCESS(f"✅ Version: {version.split(',')[0]}"))
                    print(style.SUCCESS("🔐 JWT Authentication: ENABLED"))
                    print(style.SUCCESS("🌐 CORS: CONFIGURED"))
                    print(style.SUCCESS("💰 Ready for Wallet Authentication!"))
                    print("🟢" * 60)
                    
                    # Show environment variables used
                    print(style.HTTP_INFO("📋 Environment Configuration:"))
                    print(f"   DB_ENGINE: {os.getenv('DB_ENGINE') or 'Default (PostgreSQL)'}")
                    print(f"   DB_NAME: {os.getenv('POSTGRES_DB') or os.getenv('DB_NAME') or 'Default (zefe_db)'}")
                    print(f"   DB_USER: {os.getenv('POSTGRES_USER') or os.getenv('DB_USER') or 'Default (postgres)'}")
                    print(f"   DB_HOST: {os.getenv('DB_HOST') or 'Default (localhost)'}")
                    print(f"   DB_PORT: {os.getenv('DB_PORT') or 'Default (5432)'}")
                    print("🟢" * 60 + "\n")
                    
                elif 'sqlite' in db_engine:
                    cursor.execute("SELECT sqlite_version();")
                    version = cursor.fetchone()[0]
                    
                    print("\n" + "🟡" * 60)
                    print(style.WARNING("🚀 ZEFE SOLANA MOBILE BACKEND - STARTED (SQLite) 🚀"))
                    print("🟡" * 60)
                    print(style.WARNING(f"⚠️  Database Type: {db_type}"))
                    print(style.WARNING(f"⚠️  Database File: {db_name}"))
                    print(style.WARNING(f"⚠️  SQLite Version: {version}"))
                    print(style.WARNING("💡 Consider using PostgreSQL for production"))
                    print("🟡" * 60 + "\n")
                    
                else:
                    # Generic database success
                    print("\n" + "🔵" * 60)
                    print(style.HTTP_INFO(f"🚀 ZEFE SOLANA MOBILE BACKEND - STARTED ({db_type}) 🚀"))
                    print("🔵" * 60)
                    print(style.HTTP_INFO(f"✅ Database: {db_name}"))
                    print(style.HTTP_INFO(f"✅ Host: {db_host}:{db_port}"))
                    print("🔵" * 60 + "\n")
                    
        except Exception as e:
            # Database connection failed
            print("\n" + "🔴" * 60)
            print(style.ERROR("❌ ZEFE SOLANA MOBILE BACKEND - DATABASE CONNECTION FAILED! ❌"))
            print("🔴" * 60)
            print(style.ERROR(f"❌ Database Type: {db_type}"))
            print(style.ERROR(f"❌ Database Name: {db_name}"))
            print(style.ERROR(f"❌ Host: {db_host}:{db_port}"))
            print(style.ERROR(f"❌ Error: {str(e)}"))
            print(style.ERROR("💡 Please check your database configuration and make sure the database is running"))
            print("🔴" * 60 + "\n")
