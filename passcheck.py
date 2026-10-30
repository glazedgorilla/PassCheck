import hashlib
import math
import secrets
import string
import urllib.request

# ============================================================
# PART 1: SETTINGS
# ============================================================

COMMON = ["password", "123456", "12345678", "qwerty", "abc123", "111111", "iloveyou",
          "admin", "welcome", "letmein", "monkey", "dragon", "passw0rd", "password1",
          "password123", "admin123", "india123", "krishna"]

SEQUENCES = ["abcdefghijklmnopqrstuvwxyz", "0123456789", "qwertyuiopasdfghjklzxcvbnm"]

GUESSES_PER_SECOND = 10_000_000_000   # a fast attacker: 10 billion guesses every second
LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"]

# Characters used for suggestions (confusing ones like 0, O, 1, l, I are left out)
UPPER = "ABCDEFGHJKLMNPQRSTUVWXYZ"
LOWER = "abcdefghijkmnopqrstuvwxyz"
DIGITS = "23456789"
SYMBOLS = "!@#$%^&*-_+=?"
EVERYTHING = UPPER + LOWER + DIGITS + SYMBOLS
LOOKALIKE = {"a": "@", "s": "$", "i": "!", "o": "0", "e": "3"}

# An attacker can guess your original word and our tricks fairly easily,
# so we only give ourselves credit for 20 bits for the part that came from you.
BASE_GUESS_BITS = 20


# ============================================================
# PART 2: CHECKING (strength and crack time)
# ============================================================

def analyse(password):
    tips = []
    common = False

    # STEP 1: how many different characters could each position be?
    pool = 0
    if any(c.islower() for c in password):
        pool += 26
    if any(c.isupper() for c in password):
        pool += 26
    if any(c.isdigit() for c in password):
        pool += 10
    if any(not c.isalnum() for c in password):
        pool += 32

    # STEP 2: "bits" = how hard it is to guess. Bigger number = harder.
    bits = len(password) * math.log2(pool)

    # STEP 3: lower the score for weak habits
    if len(set(password)) < len(password) / 2:
        bits *= 0.6
        tips.append("Avoid repeating the same characters.")

    lower = password.lower()
    has_sequence = False
    for sequence in SEQUENCES:
        for i in range(len(sequence) - 2):
            if sequence[i:i + 3] in lower:
                has_sequence = True
    if has_sequence:
        bits *= 0.7
        tips.append("Avoid sequences like abc, 123 or qwerty.")

    # Undo look-alike tricks, so p@ssw0rd is treated like password
    swaps = {"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "@": "a", "$": "s"}
    plain = lower
    for fake, real in swaps.items():
        plain = plain.replace(fake, real)

    is_common = lower in COMMON or plain in COMMON
    contains_common = any(len(word) >= 5 and word in plain for word in COMMON)

    if is_common:
        bits = min(bits, 10)
        common = True
        tips.insert(0, "This is one of the most common passwords. Attackers try it first.")
    elif contains_common:
        bits *= 0.5
        tips.append("It contains a very common word. Swapping letters for numbers does not fool attackers.")

    # STEP 4: simple advice
    if len(password) < 12:
        tips.append("Use at least 12 characters. Length matters more than symbols.")
    if not any(c.isupper() for c in password) or not any(c.islower() for c in password):
        tips.append("Mix uppercase and lowercase letters.")
    if not any(c.isdigit() for c in password):
        tips.append("Add some numbers.")
    if all(c.isalnum() for c in password):
        tips.append("Add a symbol such as ! or #.")
    if len(password) < 20:
        tips.append("Better idea: a passphrase of 4 or more random words, like “river-lamp-orbit-seven”.")

    # STEP 5: rating from 0 (very weak) to 4 (very strong)
    level = level_from_bits(bits)

    # STEP 6: turn bits into seconds. 2 ** bits = total possible guesses.
    # An attacker finds it on average halfway through, so divide by 2.
    seconds = bits_to_seconds(bits)
    return level, seconds, tips, common


def level_from_bits(bits):
    if bits >= 80:
        return 4
    if bits >= 60:
        return 3
    if bits >= 40:
        return 2
    if bits >= 28:
        return 1
    return 0


def bits_to_seconds(bits):
    return (2 ** bits) / GUESSES_PER_SECOND / 2


def human_time(seconds):
    if seconds < 1:
        return "instantly"
    if seconds < 60:
        return f"{round(seconds)} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{round(minutes)} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{round(hours)} hours"
    days = hours / 24
    if days < 365:
        return f"{round(days)} days"
    years = days / 365
    if years < 1_000_000:
        return f"{round(years):,} years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:.1f} million years"
    if years < 1_000_000_000_000:
        return f"{years / 1_000_000_000:.1f} billion years"
    return "longer than the age of the universe"


def about(time_text):
    # adds the word "about" only when the time is a number, e.g. "about 8 years"
    return "about " + time_text if time_text[0].isdigit() else time_text


# ============================================================
# PART 3: BREACH CHECK (private, using only 5 characters)
# ============================================================

def check_breach(password):
    # Make a SHA-1 hash: a one-way scrambled code of the password
    hashed = hashlib.sha1(password.encode()).hexdigest().upper()
    first_five = hashed[:5]     # this part is sent to the internet
    the_rest = hashed[5:]       # this part NEVER leaves your computer

    url = "https://api.pwnedpasswords.com/range/" + first_five
    request = urllib.request.Request(url, headers={"User-Agent": "PassCheck-learning"})
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            text = response.read().decode()
    except Exception:
        return None   # no internet or service down

    # The reply is a list of lines like  "0018A45C4D1DEF81644B54AB7F969B88D65:3"
    # (the rest of a leaked hash : how many times it was leaked)
    for line in text.splitlines():
        leaked_hash, count = line.split(":")
        if leaked_hash == the_rest:
            return int(count)
    return 0


# ============================================================
# PART 4: SUGGESTIONS (stronger versions of your own password)
# ============================================================

used_bits = 0   # counts how much real randomness we add


def pick(pool):
    # secrets is Python's safe random generator (random is NOT safe for passwords)
    global used_bits
    used_bits += math.log2(len(pool))
    return secrets.choice(pool)


def random_chars(count, pool):
    return "".join(pick(pool) for _ in range(count))


def cap_first(text):
    return text[:1].upper() + text[1:]


def swap_letters(text):
    # Swap up to 2 letters for look-alike symbols (a -> @, s -> $, ...)
    spots = [i for i, c in enumerate(text) if c.lower() in LOOKALIKE]
    letters = list(text)
    for _ in range(2):
        if spots:
            chosen = secrets.choice(spots)
            spots.remove(chosen)
            letters[chosen] = LOOKALIKE[letters[chosen].lower()]
    return "".join(letters)


def add_missing(text):
    # Add any kind of character that is missing
    if not any(c.islower() for c in text):
        text += pick(LOWER)
    if not any(c.isupper() for c in text):
        text += pick(UPPER)
    if not any(c.isdigit() for c in text):
        text += pick(DIGITS)
    if not any(c in SYMBOLS for c in text):
        text += pick(SYMBOLS)
    return text


def strengthen(text):
    text = add_missing(text)
    # Keep adding random characters until it is long enough and strong enough
    while (len(text) < 16 or used_bits + BASE_GUESS_BITS < 60) and len(text) < 26:
        text += random_chars(2, EVERYTHING)
    return text


def make_variants(password):
    global used_bits
    base = password.strip()
    middle = len(base) // 2

    styles = [
        ("Your password with look-alike symbols and a random ending",
         lambda: strengthen(cap_first(swap_letters(base)) + random_chars(4, DIGITS + SYMBOLS))),
        ("Your password wrapped in a random start and end",
         lambda: strengthen(random_chars(3, UPPER + DIGITS) + "-" + cap_first(base) + "-" + random_chars(3, LOWER + SYMBOLS))),
        ("Your password split in the middle with random characters",
         lambda: strengthen(cap_first(base[:middle]) + random_chars(3, DIGITS + SYMBOLS) + base[middle:] + random_chars(3, EVERYTHING))),
    ]

    results = []
    for label, make in styles:
        used_bits = 0
        text = make()
        results.append((label, text, used_bits + BASE_GUESS_BITS))
    return results


def make_random():
    global used_bits
    used_bits = 0
    chars = [pick(UPPER), pick(LOWER), pick(DIGITS), pick(SYMBOLS)]   # at least one of each kind
    while len(chars) < 16:
        chars.append(pick(EVERYTHING))
    secrets.SystemRandom().shuffle(chars)                              # so the first four are not predictable
    return "".join(chars), used_bits


def show_suggestions(password, level, common):
    if len(password.strip()) < 3 or level >= 4:
        print("\nNo suggestions needed. This password is already very strong.")
        return

    if common:
        print("\nThis password is one of the most common in the world, so versions built on it")
        print("are still easy to guess. Starting fresh is better. Fully random ideas:")
        options = []
        for _ in range(3):
            text, bits = make_random()
            options.append(("Fully random", text, bits))
    else:
        print("\nStronger versions of your password:")
        options = make_variants(password)
        text, bits = make_random()
        options.append(("Fully random (safest)", text, bits))

    for number, (label, text, bits) in enumerate(options, start=1):
        level = level_from_bits(bits)
        print(f"\n  {number}. {text}")
        print(f"     {label}")
        print(f"     {LABELS[level]} - could be cracked in {about(human_time(bits_to_seconds(bits)))}")

    print("\nNote: versions built from your own password are easier to remember,")
    print("but a fully random one is safer. Do not reuse the same pattern on other accounts.")


# ============================================================
# PART 5: THE PROGRAM
# ============================================================

while True:
    password = input("\nEnter a password to check (or press Enter to quit): ")
    if password == "":
        break

    level, seconds, tips, common = analyse(password)

    print("\nStrength:   ", LABELS[level])
    print("Crack time: ", about(human_time(seconds)))

    if tips:
        print("\nHow to improve it:")
        for tip in tips[:4]:
            print("  -", tip)

    print("\nChecking breach database...")
    found = check_breach(password)
    if found is None:
        print("Could not reach the breach service. Check your internet.")
    elif found > 0:
        print(f"Found in {found:,} breaches. Do not use this password anywhere.")
    else:
        print("Not found in known breaches.")

    show_suggestions(password, level, common)
