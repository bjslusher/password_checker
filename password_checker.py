import requests
import hashlib


def request_api_data(first_five):
    url = f"https://api.pwnedpasswords.com/range/{first_five}"
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(f"Error fetching {res.status_code}. Check API and try again")
    return res


def get_password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    sha1password = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first_five, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first_five)
    return get_password_leaks_count(response, tail)


def main():
    password_to_check = input("Enter a password to begin search: ")
    count = pwned_api_check(password_to_check)
    if count:
        print(f"\n{password_to_check} was found {count} times... Might be time to change your password!!!")
    else:
        print(f"\n{password_to_check} was not found in the PWNED Database.  Great Work, Carry on!")
    return "Done!"


main()
