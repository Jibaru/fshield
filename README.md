# File shield

File transformer and encryptor/decryptor

## Usage

### Generate a 16-bits password

```
$ ./fshield -t gen
serb02me3ydGHflT
```

### Encrypt a file (for example, a video)

```
$ ./fshield -t enc -s video.mp4 -o encrypted.txt -k serb02me3ydGHflT
```

### Decrypt a file (for example, a video)

```
$ ./fshield -t dec -s encrypted.txt -o video_dec.mp4 -k serb02me3ydGHflT
```

## Flags

- -t: the type of the usage, could be gen (to generate a new password), enc (to encrypt), dec (to decrypt)
- -s: the path of the source. On encrypt is the path of the file to encrypt. On decrypt is the path of the encrypted file.
- -o: the path of the output. On encrypt is the path of the output encrypted file. On decrypt is the path of the output decrypted file.
- -k: the password to encrypt or decrypt

## Use Cases

- Upload personal files (like backups) on cloud
- Protect personal and important shared files
