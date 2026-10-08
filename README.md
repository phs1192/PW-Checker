# PW-Checker

![Tests](https://github.com/phs1192/PW-Checker/actions/workflows/tests.yml/badge.svg)

A small command-line tool that rates how strong a password is.
It is a learning project to understand **why** some passwords are weak and how attackers think.

The password is analysed locally. It is never stored, logged or sent anywhere.

## Features

- **Entropy estimate** based on length and character variety
- **Common-password check** against a bundled list of widely used passwords
- **Pattern detection** for repeated characters (`aaa`) and sequences (`1234`, `abcd`, `qwertz`)
- **Concrete tips** on how to improve the password
- No external dependencies - Python 3.9+ is enough

## Usage

```bash
# Ask for the password securely (input is not shown)
python pw_checker.py

# Or pass it directly (it may end up in your shell history!)
python pw_checker.py "Sommer2024"
```

Example output:

```
Rating:  fair
Entropy: 59.5 bits
 - Use at least 12 characters - length matters most.
 - Add symbols such as ! ? # %.
```

## How it works

**Entropy** measures how hard a password is to guess. For a randomly chosen password:

```
entropy (bits) = length * log2(pool size)
```

The *pool size* is the number of different characters an attacker must try per position:
26 lowercase + 26 uppercase + 10 digits + 32 symbols. Every extra bit doubles the
guessing effort.

| Entropy | Rating |
|---------|--------|
| < 28 bits | very weak |
| < 36 bits | weak |
| < 60 bits | fair |
| < 80 bits | strong |
| >= 80 bits | very strong |

This is a model, not a guarantee. Real passwords are rarely random, so the tool lowers
the score by 25 % for repeats and for sequences, and caps it for known common passwords,
because attackers try those first (dictionary attack).

## Limitations

- The entropy estimate assumes random characters. Clever human patterns (names, dates,
  `Summer2024!`) can be weaker than the number suggests.
- The bundled word list is small. Real attackers use lists with millions of entries.
- Use a password manager and a unique password per account.

## Tests

```bash
python -m unittest -v
```

The tests also run automatically on every push via GitHub Actions.

## License

MIT - see [LICENSE](LICENSE).
