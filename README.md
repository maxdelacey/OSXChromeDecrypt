# OSXChromeDecrypt
Decrypt Google Chrome and Chromium Passwords offline.

Must be run on Linux or MacOS.

These are the passwords saved via the "Would you like to remember this password" popup when you login to a website.

Great for if you want to export all of your passwords with one command, as oppposed to manually selecting each one through Chrome's UI.

You can obtain the safe storage key through a variety of methods. One method is to exfiltrate the users keychain database, usually located in ```~/Library/keychains/login.keychain-db```

Once you have the keychain, it can be decrypted with https://github.com/gaddie-3/chainbreaker as long as you know the credentials for the user to which the keychain belongs.

Alternatively, you can run the below command on MacOS to retrieve the Chrome Safe Storage key:

```security find-generic-password -ga Chrome```

## Usage: 

```
usage: ChromePasswords.py [-h] -p PASSWORD -i LOGIN_DATA

optional arguments:
  -h, --help            show this help message and exit

required arguments:
  -p PASSWORD, --safe-storage-password PASSWORD
  -i LOGIN_DATA, --login-data-filepath LOGIN_DATA
 
```
