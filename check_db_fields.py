#!/usr/bin/env python3
"""Checkout alias for the complete passive stored-field diagnostic."""

def main():
    from check_victims import main as diagnostic_main

    diagnostic_main()


if __name__ == '__main__':
    main()
