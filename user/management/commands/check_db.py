import os
from django.core.management.base import BaseCommand
from django.db import connections
from django.core.management.color import color_style
from django.conf import settings

class Command(BaseCommand):
    help = 'Check database connection status with environment variables'

    def handle(self, *args, **options):
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
        
        self.stdout.write("=" * 70)
        self.stdout.write(style.HTTP_INFO("🔍 ZEFE SOLANA MOBILE BACKEND - DATABASE CONFIGURATION CHECK"))
        self.stdout.write("=" * 70)
        
        # Show environment variables
        self.stdout.write(style.HTTP_INFO("📋 Environment Variables:"))
        self.stdout.write(f"   DB_ENGINE: {os.getenv('DB_ENGINE') or 'Not Set (using default)'}")
        self.stdout.write(f"   DB_NAME: {os.getenv('DB_NAME') or 'Not Set'}")
        self.stdout.write(f"   POSTGRES_DB: {os.getenv('POSTGRES_DB') or 'Not Set'}")
        self.stdout.write(f"   DB_USER: {os.getenv('DB_USER') or 'Not Set'}")
        self.stdout.write(f"   POSTGRES_USER: {os.getenv('POSTGRES_USER') or 'Not Set'}")
        self.stdout.write(f"   DB_HOST: {os.getenv('DB_HOST') or 'Not Set (using default)'}")
        self.stdout.write(f"   DB_PORT: {os.getenv('DB_PORT') or 'Not Set (using default)'}")
        
        self.stdout.write("-" * 70)
        
        # Show actual database configuration
        self.stdout.write(style.HTTP_INFO("⚙️  Actual Database Configuration:"))
        self.stdout.write(f"   Database Type: {db_type}")
        self.stdout.write(f"   Engine: {db_engine}")
        self.stdout.write(f"   Name: {db_name}")
        self.stdout.write(f"   User: {db_user}")
        self.stdout.write(f"   Host: {db_host}")
        self.stdout.write(f"   Port: {db_port}")
        
        self.stdout.write("-" * 70)
        
        # Test database connection
        try:
            db_conn = connections['default']
            with db_conn.cursor() as cursor:
                if 'postgresql' in db_engine:
                    cursor.execute("SELECT version();")
                    version = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT current_database();")
                    current_db = cursor.fetchone()[0]
                    
                    cursor.execute("SELECT current_user;")
                    current_user = cursor.fetchone()[0]
                    
                    self.stdout.write(style.SUCCESS("✅ PostgreSQL Connection: SUCCESSFUL"))
                    self.stdout.write(style.SUCCESS(f"✅ Connected Database: {current_db}"))
                    self.stdout.write(style.SUCCESS(f"✅ Connected User: {current_user}"))
                    self.stdout.write(style.SUCCESS(f"✅ Version: {version.split(',')[0]}"))
                    
                elif 'sqlite' in db_engine:
                    cursor.execute("SELECT sqlite_version();")
                    version = cursor.fetchone()[0]
                    
                    self.stdout.write(style.WARNING("⚠️  SQLite Connection: SUCCESSFUL"))
                    self.stdout.write(style.WARNING(f"⚠️  Database File: {db_name}"))
                    self.stdout.write(style.WARNING(f"⚠️  SQLite Version: {version}"))
                    
                else:
                    cursor.execute("SELECT 1")
                    result = cursor.fetchone()
                    
                    if result:
                        self.stdout.write(style.SUCCESS(f"✅ {db_type} Connection: SUCCESSFUL"))
                    
        except Exception as e:
            self.stdout.write(style.ERROR("❌ Database Connection: FAILED"))
            self.stdout.write(style.ERROR(f"❌ Error: {str(e)}"))
            
            # Provide helpful suggestions
            if 'postgresql' in db_engine:
                self.stdout.write(style.WARNING("\n💡 PostgreSQL Connection Tips:"))
                self.stdout.write("   1. Make sure PostgreSQL is running")
                self.stdout.write("   2. Check your .env file for correct credentials")
                self.stdout.write("   3. Verify the database exists: CREATE DATABASE zefe_db;")
                self.stdout.write("   4. Check if the user has proper permissions")
        
        self.stdout.write("=" * 70)