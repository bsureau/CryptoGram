#### Presentation:
CryptoGram is an encrypted messaging system that mimics the SSL protocol to create a fully secure communication channel between two machines (following a client/server architecture).

Implementation : 
- The client connects to the server,
- The server accepts the connection, generates a RSA key pair and transmits the public key to the client,
- The client retrieves the public key sent by the server. Then it creates a DES key and transmits it to the server after encrypting it with the public key, 
- The server receives the encrypted DES key and decrypts it with its private key,
- Each party now has the DES key that will be used to encrypt messages during communication. 

The application was developed in Java. 

#### Use :
From your device, by placing yourself at the root of the /CryptoGram project, start the server by executing the following commands: 
```
cd src
java app.Server
```
Proceed in the same way to launch the client from a new terminal window: 
```
cd src
java app.Client
```

You can now speak freely!

#### Credits
SUREAU Benjamin & NICOT Bryan