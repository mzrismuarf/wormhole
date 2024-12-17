
# WormHole

Shortcut to the core. WormHole is your personal portal to any system. It bypasses all those pesky redirects and dives straight into the heart of a network.

![](https://github.com/mzrismuarf/wormhole/blob/main/image/image.png)

## Installation



```bash
  git clone https://github.com/mzrismuarf/wormhole
  cd my-project
  pip install -r requirements.txt
```
    
## Run WormHole


```bash
  python3 brute.py -h
```
## Usage/Examples

```bash
usage: brute.py [-h] -t TARGET (-u USERNAME_FILE | -U SINGLE_USERNAME) (-p PASSWORD_FILE | -P SINGLE_PASSWORD)
brute.py: error: the following arguments are required: -t/--target

```
- Username tunggal, password tunggal:
```bash
python brute.py -t redacted.com -U admin -P password123

```
- Username dari file, password tunggal:
```bash
python brute.py -t redacted.com -u username.txt -P password123

```
- Username tunggal, password dari file:
```bash
python brute.py -t redacted.com -U admin -p password.txt
```
- Username dan password dari file:
```bash
python brute.py -t redacted.com -u username.txt -p password.txt
```
