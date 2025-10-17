
# tatou
A web platform for pdf watermarking. This project is intended for pedagogical use, and contain security vulnerabilities. Do not deploy on an open network.


## Instructions


The following instructions are meant for a bash terminal on a Linux machine. If you are using something else, you will need to adapt them.


To clone the repo, you can simply run:


```bash
git clone https://github.com/Patricia3167/tatou.git
```


### Deploy


From the root of the directory:


# Create a file to set environment variables like passwords:
cp sample.env .env


# Edit .env and insert:


# Database
MARIADB_ROOT_PASSWORD=Hörby98!
MARIADB_USER=user
MARIADB_PASSWORD=Nacka01!


# Flags / secrets
FLAG_1=f6b180ae790335e1a78f8040de86be1f270e65ce
FLAG_2=21f2d86f4e011cf27248b220d4a75975171b024d
SERVER_KEY_PASSPHRASE=Hörby98@


# Container paths
CLIENT_KEYS_DIR=/app/pki
SERVER_KEYS_DIR=/home/lab/server_keys
SERVER_PUBLIC_KEY_PATH=/home/lab/server_keys/server_pub.asc
SERVER_PRIVATE_KEY_PATH=/home/lab/server_keys/server_priv.asc


HOST_SERVER_KEYS=/home/lab/server_keys 


# Rebuild the docker image and deploy the containers
docker compose up --build -d


# Test if the API is up
http -v :5000/healthz


# Open your browser at 127.0.0.1:5000 to check if the website is up.
```
# Run our tests
docker compose exec server pytest

# Run coverage analysis
docker compose exec server pytest --cov=src
