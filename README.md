# hcb.pl - a tool for brute-forcing camera login credentials

hcb.pl is a Perl-based command-line tool for performing brute-force attacks against login credentials of network cameras. It takes a list of IP addresses and a list of login/password combinations, and then attempts to log in to each camera using each combination until successful.

## Usage

```bash
perl hcb.pl [OPTIONS...]
```

## Options

- `--help`, `-h`: Show help message
- `--targets-file`, `-tf`: Input file path with targets list
- `--combo-file`, `-cf`: Input file path with login:password combos
- `--logins-file`, `-lf`: Input file path with logins
- `--passwords-file`, `-pf`: Input file path with passwords
- `--results-file`, `-r`: Results file path
- `--threads`, `-t`: Number of parallel connections
- `--generate-login-combo`, `-glc`: Generate login:login combo list
- `--timeout`, `-to`: Timeout for connection to target in seconds
- `--proxy`, `-p`: Proxy address in format socks5://127.0.0.1:9050
- `--debug`, `-d`: Enable additional logging

## Dependencies

- Perl 5.10 or higher
- List::Util
- File::Slurp
- Coro
- Coro::Select
- Coro::Channel
- URI
- LWP::UserAgent
- LWP::Protocol::socks
- Term::ProgressBar
- Getopt::Args

Install modules command :
```bash
sudo cpan List::Util File::Slurp Coro Coro::Select Coro::Channel URI LWP::UserAgent LWP::Protocol::socks Term::ProgressBar Getopt::Args Data::Dumper
```

## How to Use

1. Prepare the targets file

The targets file should contain a list of IP addresses, one per line.

```
192.168.0.1
192.168.0.2
192.168.0.3
```

2. Prepare the login/password combinations

The login/password combinations can be provided in two ways: as a file with login:password pairs, or as two separate files with logins and passwords.

```
# Combo file
admin:password
root:12345
user:letmein

# Logins file
admin
root
user

# Passwords file
password
12345
letmein
```

3. Run the tool

```bash
perl hcb.pl --targets-file targets.txt --combo-file combos.txt --threads 10
```

This command will start the tool with 10 parallel connections, using the `targets.txt` file as the list of IP addresses, and the `combos.txt` file as the list of login/password combinations.

## Notes

- This tool is intended for educational and testing purposes only. Do not use it for illegal purposes or against systems without permission.