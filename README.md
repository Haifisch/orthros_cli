# Orthros CLI
Command line interface for the Orthros Messenger

Orthros is a crypto messenger that bases itself mainly on the RSA cryptosystem for message encryption, using AES for other on-device encryption purposes.


## Install
```bash
npm install -g orthros
```

## Usage

```
Orthros Messenger v1.0.4
Command line options;
./orthros send [Recieving UUID] "[Message]" - Sends supplied message to UUID, put message in quotes.
./orthros check - Checks for messages in queue
./orthros read [Message ID] - Decrypts and reads message for ID
./orthros delete [Message ID] - Deletes a message given it's ID
./orthros whoami - Prints your Orthros ID
```

## Changelog
### v1.0.4
- Use one-time use key for message delete identity protectiona
- API available at api.orthros.ninja, documentation coming soon.

Copyright (c) 2015 Dylan "Haifisch" Laws
