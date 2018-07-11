# Secure Update framework Using blockchain for IoT devices 

## About this framework
### Abst
In recent years, the Internet of Things (IoT) equipment has become widespread, and its vulnerability is also clarified.
Attacks that exploit the vulnerability of IoT devices for stepping stones of distributed denial of service attacks and illegal mining have also been confirmed.
Therefore, a secure software update that can fix vulnerabilities and improve functions is required.
In this research, based on the existing framework, we have proposed and developed a secure update framework for IoT devices utilizing the blockchain.
By using the blockchain, the tamper-resistant and low-cost framework can be realized.
In addition, this framework makes it possible to secondary use of data stored in blocks and load balancing of servers.   

### Overview   
<img width="500" alt="2017-09-25 10 22 39" src="https://user-images.githubusercontent.com/26764885/42016489-ad053658-7ae6-11e8-92b1-9e9aa696ec5d.png">    

### Program
- blockchain.py   
   blocchain node.   
- IoT_dev.py   
   Client to request to Access Point for version check.   
- Access_point.py   
   Server to response from IoT devices.   
   And, Client to request to server for version check.
- server.py   
   Server to response from access point.  

## Usage
Git clone and run the prograam.   
```
$ python server.py    
$ python Access_point.py [IP address](ex 0.0.0.0)
$ python IoT_dev.py [IP address](ex 0.0.0.0)  
```

## Installation for blockchain function

1. Make sure [Python 3.6+](https://www.python.org/downloads/) is installed. 
2. Install [pipenv](https://github.com/kennethreitz/pipenv). 

```
$ pip install pipenv 
```

3. Create a _virtual environment_ and specify the Python version to use. 

```
$ pipenv --python=python3.6
```

4. Install requirements.  

```
$ pipenv install 
``` 

5. Run the server:
    * `$ pipenv run python blockchain.py` 
    * `$ pipenv run python blockchain.py -p 5001`
    * `$ pipenv run python blockchain.py --port 5002`

## Preparation   
Make certificate for SSL connection between Acceess point and blockchain node.   
```
$ openssl genrsa -aes128 2048 > server_secret.key   
$ openssl req -new -key server_secret.key > server_pub.csr   
$ openssl x509 -in server_pub.csr -days 365000 -req -signkey server_secret.key > cert.crt   
```
## Licence
[MIT License](https://github.com/ertlnagoya/blockchain/blob/master/LICENSE)

## Author
* [Keigo Nagara](https://github.com/KeigoNagara)   
* [Yutaka Matsubara](https://github.com/YutakaMatsubara)    

## Reference
https://github.com/dvf/blockchain

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

