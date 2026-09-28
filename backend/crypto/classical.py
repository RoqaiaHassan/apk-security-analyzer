class CaesarCipher:
    @staticmethod
    def encrypt(text: str, shift: int = 3) -> str:
        result = []
        for char in text:
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                result.append(chr((ord(char) - start + shift) % 26 + start))
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def decrypt(text: str, shift: int = 3) -> str:
        return CaesarCipher.encrypt(text, -shift)


class VigenereCipher:
    @staticmethod
    def _format_key(text: str, key: str) -> str:
        key = key.upper()
        if not key:
            key = "KEY"
        formatted = []
        key_idx = 0
        for char in text:
            if char.isalpha():
                formatted.append(key[key_idx % len(key)])
                key_idx += 1
            else:
                formatted.append(char)
        return "".join(formatted)

    @staticmethod
    def encrypt(text: str, key: str) -> str:
        if not key:
            return text
        formatted_key = VigenereCipher._format_key(text, key)
        result = []
        for i, char in enumerate(text):
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                shift = ord(formatted_key[i].upper()) - ord('A')
                result.append(chr((ord(char) - start + shift) % 26 + start))
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def decrypt(text: str, key: str) -> str:
        if not key:
            return text
        formatted_key = VigenereCipher._format_key(text, key)
        result = []
        for i, char in enumerate(text):
            if char.isalpha():
                start = ord('A') if char.isupper() else ord('a')
                shift = ord(formatted_key[i].upper()) - ord('A')
                result.append(chr((ord(char) - start - shift + 26) % 26 + start))
            else:
                result.append(char)
        return "".join(result)


class MonoalphabeticCipher:
    DEFAULT_KEY = "QWERTYUIOPASDFGHJKLZXCVBNM"

    @staticmethod
    def _build_key(key: str = DEFAULT_KEY) -> str:
        seen = set()
        result = []
        for char in (key or MonoalphabeticCipher.DEFAULT_KEY).upper():
            if char.isalpha() and char not in seen:
                seen.add(char)
                result.append(char)
        for char in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            if char not in seen:
                seen.add(char)
                result.append(char)
        return "".join(result)

    @staticmethod
    def encrypt(text: str, key: str = DEFAULT_KEY) -> str:
        key = MonoalphabeticCipher._build_key(key)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        sub_map = {alphabet[i]: key[i] for i in range(26)}
        sub_map_lower = {alphabet[i].lower(): key[i].lower() for i in range(26)}

        result = []
        for char in text:
            if char.isupper() and char in sub_map:
                result.append(sub_map[char])
            elif char.islower() and char in sub_map_lower:
                result.append(sub_map_lower[char])
            else:
                result.append(char)
        return "".join(result)

    @staticmethod
    def decrypt(text: str, key: str = DEFAULT_KEY) -> str:
        key = MonoalphabeticCipher._build_key(key)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        reverse_map = {key[i]: alphabet[i] for i in range(26)}
        reverse_map_lower = {key[i].lower(): alphabet[i].lower() for i in range(26)}

        result = []
        for char in text:
            if char.isupper() and char in reverse_map:
                result.append(reverse_map[char])
            elif char.islower() and char in reverse_map_lower:
                result.append(reverse_map_lower[char])
            else:
                result.append(char)
        return "".join(result)
