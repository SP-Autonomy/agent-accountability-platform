#!/usr/bin/env python3
"""
AIAAP Tenant Bootstrap Script
================================
Provisions a new tenant API key in the AIAAP database.

Usage:
  python saas/scripts/bootstrap_tenant.py --tenant-id acme --description "Acme Corp"

Output:
  AIAAP_TENANT_ID=acme
  AIAAP_API_KEY=<generated plain-text key>   ← copy this; it is NOT stored

The plain-text key is printed ONCE and never stored. Only the bcrypt hash
is persisted in the tenant_api_keys table. If you lose the key, generate a new one.

Requirements:
  pip install bcrypt sqlalchemy psycopg2-binary
  DATABASE_URL env var pointing to the AIAAP postgres instance.
"""

import argparse
import os
import secrets
import sys

try:
    import bcrypt
except ImportError:
    print("ERROR: bcrypt is required. Install with: pip install bcrypt", file=sys.stderr)
    sys.exit(1)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker


def main():
    parser = argparse.ArgumentParser(
        description="Bootstrap an AIAAP tenant API key",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("--tenant-id", required=True, help="Tenant identifier (e.g. 'acme')")
    parser.add_argument("--description", default="", help="Human-readable description")
    parser.add_argument(
        "--database-url",
        default=os.getenv("DATABASE_URL", "postgresql://aiaap:aiaap@localhost:5432/aiaap"),
        help="SQLAlchemy database URL (default: DATABASE_URL env var)",
    )
    args = parser.parse_args()

    # Generate a cryptographically secure random key
    plain_key = secrets.token_urlsafe(32)

    # Hash with bcrypt (cost factor 12 - good balance for API key verification)
    key_hash = bcrypt.hashpw(plain_key.encode(), bcrypt.gensalt(rounds=12)).decode()

    # Connect to database and insert
    engine = create_engine(args.database_url)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        # Ensure table exists (create if first run)
        from saas.services.shared.models import Base, TenantApiKey
        Base.metadata.create_all(engine)

        record = TenantApiKey(
            tenant_id=args.tenant_id,
            key_hash=key_hash,
            description=args.description or f"API key for {args.tenant_id}",
            active=True,
        )
        db.add(record)
        db.commit()

        print(f"\n✅ Tenant '{args.tenant_id}' provisioned successfully.")
        print("\nSet these environment variables on your connectors:\n")
        print(f"  AIAAP_TENANT_ID={args.tenant_id}")
        print(f"  AIAAP_API_KEY={plain_key}")
        print("\n⚠️  This key will NOT be shown again. Store it securely (e.g. AWS Secrets Manager).")
        print(f"\nKey ID: {record.id} | Description: {record.description}")

    except Exception as exc:
        db.rollback()
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
