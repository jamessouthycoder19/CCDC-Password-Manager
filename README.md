
# RIT CCDC's Password-Manager

  

This Password Manager was created by James Southcott for the RIT CCDC Team to attempt to "un-gamify" our tools.

  This repository used to be a part of github.com/ccdc-rit/password-manager, however all of its functionality has been moved to the Death Star (coming soon), so I moved this repository to my personal repo.

## Features

  

Features Android 9.0 (Pie) Disk Encryption Scheme, learned in CSEC-467.

- Master Password is fed into KDF function. This generates Key Encryption Key (KEK)

- KEK is used to decrypt Disk Encryption Key (DEK).

- DEK is used to decrypt Passwords

  

Benefits

- Simple encryption scheme keeps technical debt low

- Decrypted DEK only ever exists in memory when at least 1 user is logged into the Password Manager

- Changing the Master Password only requires decrypting and re-encrypting the DEK, instead of every password

  

Drawbacks

- Theretically, if Red Team had access to the memory of the Password Manager, they would be able to extract the DEK and use this to decrypt Passwords. Even changing the master password would not prevent this.

	- The team decided that this threat was outside of our threat profile.

  

Alternatives

- The iOS disk encryption scheme was also considered, as it is significantly more robust than this implementation
	- Multiple differnt classes of keys for password encryption
	- No DEK/KEK so changing password prevents compromised key)
	- Asymmetric writing to encrypted passwords for certain key classes
- 2 main reasons why this wasn't used
	- The number of features increase complexity to the point that will make development difficult for our small team
	- Keeping the "Change Master Password" option a computationally inexpensive operation is very important, because the server will be deployed in a **very** resource constrained environment.

  

## For Developers

  

Windows

```

GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o windows.exe

```

Linux

```

GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o linux

```

  

To tell git not to track any changes to the password_manager.db file

```

git update-index --assume-unchanged password_manager.db

```

And to undo it

```

git update-index --no-assume-unchanged password_manager.db

```