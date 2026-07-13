"""Compatibility entry point for the FastAPI voting demo.

The project code now lives in the `voting_system` package. This small wrapper
keeps the old and convenient command working:

    python3 blockchainV1.py
"""

from voting_system.blockchain_v1 import app, main


if __name__ == "__main__":
    main()
