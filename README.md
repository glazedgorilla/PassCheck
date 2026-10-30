# PassCheck
Credential Safety &amp; Exposure Auditor with Resilient Password Recommendations

# PassCheck

**See how fast your password falls, then fix it.**

PassCheck is a free, browser-based tool that tells you how strong a password really is, whether it has appeared in a known data breach, and how to make it stronger without starting from scratch.

**Live demo:** https://vikaskumar1705.github.io/PassCheck/

## The problem

People choose passwords they can remember, such as names, birth years and simple tricks like `@` for `a`. Attackers try these first. When one website is breached, the leaked password is often tried on email, social media and payment apps, because many people reuse it. Most password checkers only say "weak" and stop, leaving people with no idea what to change.

## What PassCheck does

1. **Crack-time estimate:** shows how long an attacker would need to guess the password, with a strength meter and specific tips.
2. **Breach check:** checks whether the password has appeared in real data leaks, using the Have I Been Pwned Pwned Passwords service.
3. **Smart suggestions:** builds stronger versions from the password you typed, so the result still feels familiar. A fully random option is also offered.

## How it works

### Strength and crack time
The score is based on four things:

- **Length and variety:** longer passwords with lowercase, uppercase, numbers and symbols score higher.
- **Repeats and patterns:** repeated characters and sequences like `123` or `qwerty` lower the score.
- **Common words:** very common passwords and words are penalised, even when letters are swapped for symbols (for example `a` to `@`).
- **Known breaches:** a leaked password is flagged however strong it looks.

Crack time assumes an attacker making 10 billion guesses per second. It is an estimate, not a guarantee.

### Private breach check (k-anonymity)
Your password never leaves your device.

1. Your browser hashes the password with SHA-1.
2. Only the **first 5 characters** of the hash are sent to the Have I Been Pwned service.
3. The service returns every leaked hash that starts with those 5 characters.
4. Your browser checks the rest of the hash against that list locally.

SHA-1 is used here only because the breach database is indexed that way, not to protect passwords.

### Suggestions
Suggestions are generated in your browser with the Web Crypto secure random generator. Versions built from your own password keep a recognisable base and add look-alike symbols and random characters. Because an attacker could guess the original word, the strength estimate counts only the random characters that were added. Fully random suggestions are the safest option.

## Tech stack

- HTML, CSS and JavaScript (a single `index.html` file)
- Web Crypto API (SHA-1 hashing and secure random numbers)
- Have I Been Pwned Pwned Passwords API (range search)
- No server, no database, nothing stored

## Run it locally

Download `index.html` and open it in any modern browser. The breach check needs an internet connection.

## Limitations

- Crack times are estimates for a fast offline attack.
- The breach check needs internet and covers only known leaks.
- Suggestions built from your own password are easier to remember, but fully random ones are safer.
- PassCheck does not replace a password manager or two-step login. The best habit is a different password for every site.

## Roadmap

- Browser extension for sign-up forms
- Hindi and regional languages
- Smarter pattern detection
- Email breach check

## Author

Jalaj goel, B.Tech 1st year. Built for a cybersecurity hackathon.
