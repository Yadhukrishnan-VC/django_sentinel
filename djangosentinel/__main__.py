"""
Allows running DjangoSentinel as a module:
python -m djangosentinel scan .
python -m djangosentinel fix .
python -m djangosentinel install-hooks
"""

from djangosentinel.cli import main

if __name__ == "__main__":
    main()
