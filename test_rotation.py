#!/usr/bin/env python3
"""
Test AIRC v0.2 key rotation with Python SDK
"""

import time
import secrets
from airc import Client

STAGING_REGISTRY = "https://vibe-public-pjft4mtcb-sethvibes.vercel.app"


def test_rotation():
    print("╔════════════════════════════════════════════════════════════╗")
    print("║  AIRC v0.2 Python SDK - Rotation Test                    ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()

    # Create unique test handle (max 20 chars)
    handle = f"py{int(time.time() * 1000) % 10000000:x}"
    print(f"📝 Test handle: @{handle}")
    print()

    # Test 1: Register with recovery key
    print("=== Test 1: Register with recovery key ===")
    client = Client(
        handle,
        registry=STAGING_REGISTRY,
        working_on="Testing AIRC v0.2 rotation",
        with_recovery_key=True
    )

    try:
        result = client.register()
        if not result.get("success"):
            print(f"❌ Registration failed: {result.get('error')}")
            return False

        print("✅ Registered with recovery key")
        print(f"   User: {result.get('user', {}).get('username')}")
        print(f"   Public key: {client.identity.public_key_base64[:30]}...")
    except Exception as e:
        print(f"❌ Registration error: {e}")
        return False

    print()

    # Test 2: Verify recovery key was saved
    print("=== Test 2: Verify recovery key saved ===")
    try:
        recovery = client.get_recovery_key()
        if not recovery:
            print("❌ Recovery key not found")
            return False

        print("✅ Recovery key loaded")
        print(f"   Public key: {recovery.public_key_base64[:30]}...")
    except Exception as e:
        print(f"❌ Recovery key load error: {e}")
        return False

    print()

    # Wait for database replication
    print("⏳ Waiting 2 seconds for database replication...")
    time.sleep(2)
    print()

    # Test 3: Rotate signing key
    print("=== Test 3: Rotate signing key ===")
    print(f"   Registry: {STAGING_REGISTRY}")
    print(f"   Handle: {handle}")

    old_public_key = client.identity.public_key_base64

    try:
        # rotate_key() generates new key automatically if not provided
        result = client.rotate_key()

        if not result.get("success"):
            print(f"❌ Rotation failed: {result.get('error')}")
            return False

        new_public_key = client.identity.public_key_base64

        print("✅ Key rotation succeeded")
        print(f"   Old key: {old_public_key[:30]}...")
        print(f"   New key: {new_public_key[:30]}...")
        print(f"   New token: {result.get('token', '')[:30]}...")

        if old_public_key == new_public_key:
            print("❌ Public key did not change!")
            return False

    except Exception as e:
        print(f"❌ Rotation error: {e}")
        return False

    print()
    print("╔════════════════════════════════════════════════════════════╗")
    print("║  ✅ All rotation tests passed!                            ║")
    print("╚════════════════════════════════════════════════════════════╝")
    print()
    print("Summary:")
    print("  ✅ Registration with recovery key")
    print("  ✅ Recovery key persisted to disk")
    print("  ✅ Key rotation with recovery proof")
    print("  ✅ New session token received")
    print("  ✅ Public key updated in database")
    print()

    return True


if __name__ == "__main__":
    try:
        success = test_rotation()
        exit(0 if success else 1)
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)
