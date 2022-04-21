# File-Encryptor
A very powerful cli file/folder encryptor 

Decrypt:
-of        changes the output file
-i         ignores all warnings
-replace   replaces the input file
-load      decrypts the file than allows you to veiw the encrypted file without saving it
-pass      provide a string password which is later turned in to a secure b64 encoded key
-info      displays extra information about the decrypted file
-help/?    displays this message

Encrypt:
-of        changes the output file
-i         ignores all warnings
-replace   replaces the input file
-pass      provide a string password which is later turned in to a secure b64 encoded key
-hash      Utilise the hashing algorithm to generate a 32 long b64 encoded key which can be used with this tool
-key       provide a base64 encoded 32 long key
-archive   Compresses input file to reduce file size
-info      displays extra information about the encrypted file
-help/?    displays this message
