# Online-Bank
Proof of Concept using HTTPS and secure HTML/SQL/JavaScript practices according to OWASP reccommendations

Use the following command in a terminal to install dependencies:

```npm i express mysql client-sessions body-parser xss-filters helmet-csp dompurify xml2js bcrypt owasp-password-strength-test```


To set up the database, use the following commands in MySQL:

```CREATE DATABASE test;
USE test;
CREATE TABLE users (idUsers INT(11) NOT NULL AUTO_INCREMENT, username VARCHAR(128) NOT NULL, password VARCHAR(60) NOT NULL, firstname VARCHAR(45) NOT NULL, lastname VARCHAR(45) NOT NULL, address VARCHAR(55) NOT NULL, PRIMARY KEY (idUsers), UNIQUE (username));
CREATE TABLE accounts (idAcc CHAR(36) NOT NULL, idUsers INT(11) NOT NULL, balance DECIMAL(20, 2) NOT NULL, accountname VARCHAR(35) NOT NULL DEFAULT 'New Account', PRIMARY KEY (idAcc), FOREIGN KEY (idUsers) REFERENCES users(idUsers));
CREATE TRIGGER insertidacc BEFORE INSERT ON accounts FOR EACH ROW SET new.idAcc = UUID();
GRANT ALL PRIVILEGES ON test.* TO 'bank'@'localhost' IDENTIFIED BY 'test.bank.pass';
```


To start the server, in a terminal type:

```nodemon bank.js```

In your favorite browser, go to the following url:

```https://localhost:3000/```

Certificates were generated using the following commands:

```openssl req -new -x509 -days 365 -keyout cakey.pem -out cacert.pem```

Passphrase : two.fish.attended.greatest.gym
  
```openssl genrsa -out serverkey.pem 4096```

```openssl req -new -sha256 -key serverkey.pem -out servercsr.pem```

Challenge : hw3.pass
  
```openssl x509 -req -days 365 -in servercsr.pem -CA cacert.pem -CAkey cakey.pem -CAcreateserial -out servercert.pem```

