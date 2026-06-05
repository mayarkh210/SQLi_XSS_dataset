from attack_generator_tool import AttackGenerator
import time

gen = AttackGenerator()

print("🔍 Real-time Payload Monitor (Press Ctrl+C to stop)\n")

try:
    while True:
        attack = gen.generate_random_attack("high")
        print(f"[{attack['type']}] → {attack['payload'][:120]}")
        if len(attack['payload']) > 120:
            print("   ... (truncated)")
        print("-" * 100)
        time.sleep(1.2)
except KeyboardInterrupt:
    print("\n\nMonitoring stopped.")