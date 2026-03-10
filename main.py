import sys

def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python main.py analyze <file>")
        print("  python main.py run <file>")
        return

    command = sys.argv[1]
    target = sys.argv[2]

    if command == "analyze":
        print(f"[ANALYZE] Target: {target}")
    elif command == "run":
        print(f"[RUN] Target: {target}")
    else:
        print("Unknown command.")

if __name__ == "__main__":
    main()