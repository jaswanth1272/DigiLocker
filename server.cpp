#include <bits/stdc++.h>
#include <fstream>
#include<string>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/aes.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

struct clientDetails
{
	int port;
	int client_id;
	string username;
};

struct client{
	int nsfd;
	RSA* rsa;
};

RSA* generateRSAKeyPair(int bits) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    // Set public exponent
    BN_set_word(e, RSA_F4);

    // Generate key pair
    RSA_generate_key_ex(rsa, bits, e, NULL);

    BN_free(e);
    return rsa;
}

/*// Function to compute SHA-256 hash of a message
void sha256Hash(const unsigned char* message, size_t messageLength, unsigned char* hash) {
    SHA256_CTX sha256Context;
    SHA256_Init(&sha256Context);
    SHA256_Update(&sha256Context, message, messageLength);
    SHA256_Final(hash, &sha256Context);
}*/
string sha256Hash(const string& message) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256Context;

    SHA256_Init(&sha256Context);
    SHA256_Update(&sha256Context, message.c_str(), message.length());
    SHA256_Final(hash, &sha256Context);

    stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int rsaEncrypt(const unsigned char* plaintext, int plaintextLen, unsigned char* encrypted, RSA* rsaPublicKey) {
    return RSA_public_encrypt(plaintextLen, plaintext, encrypted, rsaPublicKey, RSA_PKCS1_PADDING);
}

int rsaDecrypt(const unsigned char* encrypted, int encryptedLen, unsigned char* decrypted, RSA* rsaPrivateKey) {
    return RSA_private_decrypt(encryptedLen, encrypted, decrypted, rsaPrivateKey, RSA_PKCS1_PADDING);
}

string rsaPublicDecrypt(const unsigned char *encrypted, int encryptedLen, RSA *rsa)
{
    unsigned char *decrypted = new unsigned char[RSA_size(rsa)]; // Allocate memory
    int decryptedLen = RSA_public_decrypt(encryptedLen, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
    if (decryptedLen == -1)
    {
        // Error handling
        delete[] decrypted; // Don't forget to free memory
        return "";          // Return empty string indicating failure
    }
    string DecryptedText(reinterpret_cast<const char *>(decrypted), decryptedLen);
    delete[] decrypted; // Free memory
    return DecryptedText;
}

char* printHex(const BIGNUM* bn, const char* label) {
    char* hex = BN_bn2hex(bn);
    cout << label << ": " << hex << endl;
    return hex;
}

void printRSAKeyDetails(RSA *rsa) {
    const BIGNUM *n, *e, *d;

    RSA_get0_key(rsa, &n, &e, &d);
    cout << "Modulus (n): " << BN_bn2hex(n) << endl;
    cout << "Public Exponent (e): " << BN_bn2hex(e) << endl;
    if (d) {
        cout << "Private Exponent (d): " << BN_bn2hex(d) << endl;
    }
}

RSA* setRSAAttributes(const char* pubN, const char* pubE) {
    RSA* rsa = RSA_new();
    BIGNUM* n = NULL, * e = NULL;

    // Convert pubN and pubE from char* to BIGNUM*
    BN_hex2bn(&n, pubN);
    BN_hex2bn(&e, pubE);

    // Set RSA public key attributes
    RSA_set0_key(rsa, n, e, NULL);

    return rsa;
}

//AES Encryption and Decryption
// AES encryption function for an integer
void aesEncryptInt(const unsigned char key[],int number, unsigned char* ciphertext) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);

    unsigned char plaintext[sizeof(number)];
    memcpy(plaintext, &number, sizeof(number));

    AES_encrypt(plaintext, ciphertext, &aesKey);
}

// AES decryption function for an integer
int aesDecryptInt(const unsigned char key[],const unsigned char* ciphertext) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key, 128, &aesKey);

    unsigned char decryptedtext[AES_BLOCK_SIZE];
    AES_decrypt(ciphertext, decryptedtext, &aesKey);

    int decryptedNumber;
    memcpy(&decryptedNumber, decryptedtext, sizeof(decryptedNumber));
    
    return decryptedNumber;
}

void aesEncrypt(const unsigned char key[], unsigned char plaintext[], unsigned char* ciphertext) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);

    AES_encrypt(plaintext, ciphertext, &aesKey);
}

string aesDecrypt(const unsigned char key[], const unsigned char* ciphertext) {
    AES_KEY aesKey;
    AES_set_decrypt_key(key, 128, &aesKey);

    unsigned char decryptedtext[AES_BLOCK_SIZE];
    AES_decrypt(ciphertext, decryptedtext, &aesKey);
    
    return string((char*)decryptedtext);
}

map<string, string> user_pass;
map<string,pair<int,int>> user_identity;
map<string,int> server_ports;

vector<int> ports={8000,8001,8002,8003,8004,8005,8006,8007,8008,8009,8010};
queue<int> ports_available;
set<int> ports_inuse;

map<string,RSA*> user_keys;
unsigned char decryptedKey[2048] = {0};

/*void receiveFileOverSocket(SSL* ssl, const string& filename) {
    ofstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "Error opening file: " << filename << endl;
        return;
    }

    char buffer[1024];
    int bytesReceived = 0;
    while ((bytesReceived = SSL_read(ssl, buffer, sizeof(buffer))) > 0) {
        file.write(buffer, bytesReceived);
    }

    file.close();
}

void  receivepdf(int clientfd)
{
	SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_server_method());
    SSL* ssl = SSL_new(ctx);

    // Perform SSL handshake
    SSL_set_fd(ssl, clientfd);
    if (SSL_accept(ssl) != 1) {
        cerr << "Error performing SSL handshake" << endl;
        return 1;
    }

    // Receive PDF file over the socket
    receiveFileOverSocket(ssl, "/path/to/received.pdf");

    // Clean up SSL and socket connections
    SSL_shutdown(ssl);
    close(clientfd);
    SSL_CTX_free(ctx);
}*/

void* handleClient(void* args)
{
	clientDetails cd=*(clientDetails*)args;
	cout<<cd.port<<" "<<cd.client_id<<" "<<cd.username<<endl;
	
	int ssfd = socket(AF_INET, SOCK_STREAM, 0);
    if (ssfd == -1) {
        cerr << "Error creating socket." << endl;
        return NULL;
    }
	cout<<"sfd is "<<ssfd<<endl;
	
    struct sockaddr_in my_address1, client_address;
    socklen_t client_address_len = sizeof(client_address);

    memset(&my_address1, 0, sizeof(my_address1));
    my_address1.sin_family = AF_INET;
    my_address1.sin_addr.s_addr = inet_addr("127.0.0.0");
    my_address1.sin_port = htons(cd.port);

	cout<<"hii"<<endl;
	
    int reuse = 1;
    if (setsockopt(ssfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        cerr << "Error setting SO_REUSEADDR." << endl;
        close(ssfd);
        return NULL;
    }

	cout<<"H111"<<endl;

    if (bind(ssfd, (struct sockaddr*)&my_address1, sizeof(my_address1)) == -1) {
        cerr << "Error binding socket." << endl;
        close(ssfd);
        return NULL;
    }

	cout<<"h222"<<endl;

    if (listen(ssfd, 3) == -1) {
        cerr << "Error listening on socket." << endl;
        close(ssfd);
        return NULL;
    }
    
    cout<<"h33"<<endl;

    int ncsfd = accept(ssfd, (struct sockaddr*)&client_address, &client_address_len);
    if (ncsfd == -1) {
        cerr << "Error accepting connection." << endl;
        close(ssfd);
        return NULL;
    }
    
    cout<<"ncsfd is : "<<ncsfd<<endl; 
    
    int cid;
    recv(ncsfd,&cid,sizeof(cid),0);
    cout<<cid<<" "<<cd.client_id<<endl;
    if (cid!=cd.client_id)
    {
    	cout<<"Invalid user"<<endl;
    }
    else
    {
    	string val="valid";
    	send(ncsfd,val.c_str(),val.length(),0);
    	cout<<"hello"<<endl;
    	
		char pdf[100],details[1000];
		int n=recv(ncsfd,pdf,sizeof(pdf),0);
		pdf[n]='\0';
		cout<<pdf<<endl;
		
		string filePath=cd.username+"/"+string(pdf)+".txt";
		ifstream file(filePath);
		if(file.good())
		{
			cout<<"file exists"<<endl;
			string msg = "yes";
			send(ncsfd, msg.c_str(), msg.length(),0);
		}
		else
		{
			cout<<"file not exists"<<endl;
			string msg = "no";
			send(ncsfd, msg.c_str(), msg.length(),0);
			
			int p=server_ports[string((char*)pdf)];
		
			int dsfd = socket(AF_INET, SOCK_STREAM, 0);

			struct sockaddr_in serv_address;
			memset(&serv_address, 0, sizeof(serv_address));
			serv_address.sin_family = AF_INET;
			serv_address.sin_addr.s_addr = inet_addr("127.0.0.4");
			serv_address.sin_port = htons(p);

			connect(dsfd, (struct sockaddr*)&serv_address, sizeof(serv_address));
			
			char dpubN[2048], dpubE[2048];

			recv(dsfd, dpubN, sizeof(dpubN), 0);
			cout << dpubN << endl << endl;

			recv(dsfd, dpubE, sizeof(dpubE), 0);
			cout << dpubE << endl << endl;
			
			RSA* rsaDoc = setRSAAttributes(dpubN, dpubE);
			
			unsigned char encryptedUsername[2048]={0};
			
			cout<<"Encrypting username and sending to docServer..."<<endl;
			sleep(1);
			
			int encryptedUsernameLen = rsaEncrypt((const unsigned char*)(cd.username.c_str()), cd.username.length(), encryptedUsername, rsaDoc);

			if (encryptedUsernameLen == -1) {
				cerr << "Encryption failed" << endl;
				RSA_free(rsaDoc);
				close(dsfd);
				
			}
	
			//encryptedUsername[encryptedUsernameLen]='\0';
			sleep(1);
			
			cout<<"Encrypted username is ..."<<endl;
			
			cout<<encryptedUsernameLen<<"   "<<encryptedUsername<<endl;
			
			send(dsfd,encryptedUsername,encryptedUsernameLen,0);
			
			/*char usr_pin[100];
			
			n = recv(ncsfd,usr_pin, sizeof(usr_pin), 0);
			usr_pin[n]='\0';
			cout<<"received pin is "<<usr_pin<<endl;*/
			
			// Receive and decrypt port
			unsigned char encryptedPin[AES_BLOCK_SIZE];
			int n = recv(ncsfd, encryptedPin, 10000, 0);
			cout<<"Size recieved is : "<<n<<endl;
			if (n < 0) {
				cerr << "Error receiving decryptedPort\n";
				return NULL;
			}
			encryptedPin[n] = '\0'; // Ensure null-termination
			
			cout<<"EncryptedPin is : "<<encryptedPin<<endl;
			sleep(1);
			cout<<"Decryption of Pin from client is going on ... "<<endl;
			sleep(1);
			string pin;
			pin = aesDecrypt(decryptedKey, (unsigned char*)encryptedPin);
			
			sleep(1);
			
			cout << "Decrypted pin: " << pin << endl;
			
			unsigned char encryptedUserPin[2048]={0};
			
			cout<<"Encrypting userPin and sending to docServer..."<<endl;
			sleep(1);
			
			int encryptedUserPinLen = rsaEncrypt((const unsigned char*)(pin.c_str()), pin.length(), encryptedUserPin, rsaDoc);

			if (encryptedUserPinLen == -1) {
				cerr << "Encryption failed" << endl;
				RSA_free(rsaDoc);
				close(dsfd);
				
			}
	
			
			sleep(1);
			
			cout<<"Encrypted userPin is ..."<<endl;
			
			cout<<encryptedUserPinLen<<"   "<<encryptedUserPin<<endl;
			
			send(dsfd,encryptedUserPin,encryptedUserPinLen,0);

			
			char pin_flag[2100];
			n=recv(dsfd, pin_flag,sizeof(pin_flag),0);
			cout<<pin_flag<<endl;
			pin_flag[n]='\0';
			
			char msgerr[100] = "wrong pin";
			if(strcmp(msgerr,pin_flag)==0)
			{
				cout<<msgerr<<endl;
			}
			else
			{
				cout<<"details "<<pin_flag<<endl;
				
				string d1 = "";
				int f1=0;
				string eh1 = "";
				for(int i=0;i<n;i++)
				{
					if(pin_flag[i]==',' and f1==0)
					{
						f1=1;
						continue;
					}
					if(f1==0){
						d1+=pin_flag[i];
					}
					else{
						eh1+=pin_flag[i];
					}
				}
				
				cout<<d1<<" "<<eh1<<endl;

				string hash = sha256Hash(d1);
				string h1 = rsaPublicDecrypt((const unsigned char*)eh1.c_str(),eh1.length(),rsaDoc);
				
				cout<<hash<<endl;
				
				
				if(hash!=h1)
				{
					cout<<"invalid data"<<endl;
				}
				
				else
				{
					string fileCreate="touch "+filePath;
					system(fileCreate.c_str());
					const char* buff = d1.c_str();
					
					cout<<strlen(buff)<<" "<<buff<<endl;
					int fd=open(filePath.c_str(),O_WRONLY);
					write(fd,buff,d1.length());
				}
			}
			
		}
		
    }
	return NULL;
}
void onSuccessfullLogin(int nsfd,string username, RSA* rsa)
{
	
	char encryptedKey[2048] = {0}; // Adjust size as needed
    int len = recv(nsfd, encryptedKey, sizeof(encryptedKey), 0);
    encryptedKey[len] = '\0';

    cout << "Received encrypted Key: " << encryptedKey << endl;

    
    int keyLen = len; // Use the actual length received
    int decryptedKeyLen = rsaDecrypt((const unsigned char*)encryptedKey, keyLen, decryptedKey, rsa);

    if (decryptedKeyLen == -1) {
        cerr << "Decryption failed" << endl;
        RSA_free(rsa);
        close(nsfd);
        return;
    }

    cout << "Decrypted key: ";
    for (int i = 0; i < decryptedKeyLen; ++i) {
        printf("%02x", decryptedKey[i]);
    }
    cout << endl;	

	sleep(1);

	int cur_port=ports_available.front();
	ports_available.pop();
	
	ports_inuse.insert(cur_port);
	
	cout<<"port assigned : "<<cur_port<<endl;

	unsigned char ciphertextPort[AES_BLOCK_SIZE];

    aesEncryptInt(decryptedKey, cur_port, ciphertextPort);
    
    sleep(1);
    
    cout<<"Encrypted Port is : "<<ciphertextPort<<endl;
    
    send(nsfd, ciphertextPort,strlen((char*)ciphertextPort),0);
	
	sleep(1);
	int cur_identity=rand();
	cout<<"Identity assigned : "<<cur_identity<<endl;
	
	unsigned char ciphertextIdentity[AES_BLOCK_SIZE];

    aesEncryptInt(decryptedKey, cur_identity, ciphertextIdentity);
    
    sleep(1);
    
    cout<<"Encrypted Identity is : "<<ciphertextIdentity<<endl;
    
    send(nsfd, ciphertextIdentity,strlen((char*)ciphertextIdentity),0);

    close(nsfd);
    
    pthread_t tid;
    clientDetails dt;
    dt.port=cur_port;
    dt.client_id=cur_identity;
    dt.username=username;
    pthread_create(&tid,NULL,handleClient,&dt);
   	while (true);

}
void handleSignUp(int nsfd, RSA* rsa)
{
	char username[1000];
    int len = recv(nsfd, username, sizeof(username), 0);
    if (len <= 0) {
        cerr << "Error receiving username." << endl;
        RSA_free(rsa);
        close(nsfd);
        return;
    }
    username[len] = '\0'; // Null terminate the received data
    cout << "Username: " << username << endl;
    

    // Decryption
    unsigned char decryptedUser[2048] = {0};
    int usernameLen = len; // Use the actual length received
    int decryptedLen = rsaDecrypt((const unsigned char*)username, usernameLen, decryptedUser, rsa);
    if (decryptedLen == -1) {
        cerr << "Decryption failed" << endl;
        RSA_free(rsa);
        close(nsfd);
        return;
    }
    cout << "Decrypted username: " << decryptedUser << endl;
    
    sleep(2);
    
    char pubN[2048], pubE[2048];

    recv(nsfd, pubN, sizeof(pubN), 0);
    cout <<"N of client : "<< pubN << endl << endl;

    recv(nsfd, pubE, sizeof(pubE), 0);
    cout <<"e of client : "<< pubE << endl << endl;
    
    RSA* rsaClient = setRSAAttributes(pubN, pubE);
    
    user_keys[string((char*)decryptedUser)]=rsaClient;

	sleep(1);

    char hashedPassword[5000]; // Adjust the size if needed
    int encryptedDataLen = recv(nsfd, hashedPassword, sizeof(hashedPassword), 0);
    if (encryptedDataLen <= 0) {
        cerr << "Error receiving hashed password." << endl;
        RSA_free(rsa);
        close(nsfd);
        return;
    }
    hashedPassword[encryptedDataLen] = '\0'; // Null terminate the received data
    cout << "Encrypted hashed password received: " << hashedPassword << endl;

    // Decrypt the received data
    unsigned char decryptedPass[2048] = {0}; // Adjust the size if needed
    int decryptedPassLen = rsaDecrypt((const unsigned char*)hashedPassword, encryptedDataLen, decryptedPass, rsa);
    if (decryptedPassLen == -1) {
        cerr << "Decryption failed" << endl;
        RSA_free(rsa);
        close(nsfd);
        return;
    }
    decryptedPass[decryptedPassLen] = '\0'; // Null terminate the decrypted password
    cout << "Decrypted password: " << decryptedPass << endl;

    user_pass[string((char*)decryptedUser)] = string((char*)decryptedPass);
    cout << "Stored in map: " << user_pass[string((char*)decryptedUser)] << endl;
    
    cout<<"User successfully registered"<<endl;
    
    string user=string((char*)decryptedUser);
    string folderCreate="mkdir "+user;
	system(folderCreate.c_str());
	
	string cmd="touch "+user+"/password.txt";
	system(cmd.c_str());
	
	string password=string((char*)decryptedPass);
	string password_file=user+"/password.txt";
	int fd=open(password_file.c_str(),O_WRONLY);
	cout<<"password is "<<password<<endl;
	write(fd,password.c_str(),password.length());
	
	onSuccessfullLogin(nsfd,user,rsa);
}

void handleSignIn(int nsfd, RSA* rsa)
{
	char username[1000];
    int len = recv(nsfd, username, sizeof(username), 0);
    if (len <= 0) {
        cerr << "Error receiving username." << endl;
        RSA_free(rsa);
        close(nsfd);
        return;
    }
    username[len] = '\0'; // Null terminate the received data
    cout << "Username: " << username << endl;
    
    // Decryption
    unsigned char decryptedUser[2048] = {0};
    int usernameLen = len; // Use the actual length received
    int decryptedLen = rsaDecrypt((const unsigned char*)username, usernameLen, decryptedUser, rsa);
    if (decryptedLen == -1) {
        cerr << "Decryption failed" << endl;
        RSA_free(rsa);
        close(nsfd);
        return;
    }
    cout << "Decrypted username: " << decryptedUser << endl;
    
    sleep(2);
    
    char pubN[2048], pubE[2048];

    recv(nsfd, pubN, sizeof(pubN), 0);
    cout <<"N of client : "<< pubN << endl << endl;

    recv(nsfd, pubE, sizeof(pubE), 0);
    cout <<"e of client : "<< pubE << endl << endl;
    
    RSA* rsaClient = setRSAAttributes(pubN, pubE);
    
    user_keys[string((char*)decryptedUser)]=rsaClient;

	sleep(1);

    char hashedPassword[5000]; // Adjust the size if needed
    int encryptedDataLen = recv(nsfd, hashedPassword, sizeof(hashedPassword), 0);
    if (encryptedDataLen <= 0) {
        cerr << "Error receiving hashed password." << endl;
        RSA_free(rsa);
        close(nsfd);
        return;
    }
    hashedPassword[encryptedDataLen] = '\0'; // Null terminate the received data
    cout << "Encrypted hashed password received: " << hashedPassword << endl;

    // Decrypt the received data
    unsigned char decryptedPass[2048] = {0}; // Adjust the size if needed
    int decryptedPassLen = rsaDecrypt((const unsigned char*)hashedPassword, encryptedDataLen, decryptedPass, rsa);
    if (decryptedPassLen == -1) {
        cerr << "Decryption failed" << endl;
        RSA_free(rsa);
        close(nsfd);
        return;
    }
    decryptedPass[decryptedPassLen] = '\0'; // Null terminate the decrypted password
    cout << "Decrypted password: " << decryptedPass << endl;

    string user=string((char*)decryptedUser);
    
    string command = "stat .";
    int status = system(command.c_str());
    if (status==0)
    {
		string path=user+"/password.txt";
		
		int fd=open(path.c_str(),O_RDONLY);
	   	char password[1000];
	   	int n=read(fd,password,sizeof(password));
	   	password[n]='\0';
	   	
	   	string password_str=string((char*)password);
	   	
	   	string password_got=string((char*)decryptedPass);
	   	
	   	if (password_str==password_got)
	    {
	    	cout<<"Valid user"<<endl;
	    	onSuccessfullLogin(nsfd,user,rsa);
	   	}
	   	else
	   	{
	   		cout<<"Invalid User"<<endl;	
	   	}
   	}
   	else
   	{
   		cout<<"User does not exist"<<endl;
	}
}

void* multipleClients(void* args)
{
	struct client details=*(client*)args;
	RSA* rsa=details.rsa;
	int nsfd=details.nsfd;

	const BIGNUM *n = NULL, *e = NULL, *d = NULL;
    RSA_get0_key(rsa, &n, &e, &d);
    char* pubN = printHex(n, "Public key (n)");
    char* pubE = printHex(e, "Public key (e)");

    send(nsfd, pubN, strlen(pubN), 0);
    sleep(1);
    send(nsfd, pubE, strlen(pubE), 0);
    
    int action;
    int actionlen = recv(nsfd, &action, sizeof(action), 0);
    
    if(action==1)
    {
    	handleSignIn(nsfd, rsa);
    }
    else
    {
    	handleSignUp(nsfd, rsa);
    }
	RSA_free(rsa);
	close(nsfd);

}

int main() {
	srand(time(0));
	
	server_ports["aadhar"]=10000;
	server_ports["license"]=10001;

	for (auto port: ports)
	{
		ports_available.push(port);
	}
	
    int sfd1 = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd1 == -1) {
        cerr << "Error creating socket." << endl;
        return -1;
    }

    struct sockaddr_in my_address1, client_address;
    socklen_t client_address_len = sizeof(client_address);

    memset(&my_address1, 0, sizeof(my_address1));
    my_address1.sin_family = AF_INET;
    my_address1.sin_addr.s_addr = inet_addr("127.0.0.4");
    my_address1.sin_port = htons(8081);

    int reuse = 1;
    if (setsockopt(sfd1, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        cerr << "Error setting SO_REUSEADDR." << endl;
        close(sfd1);
        return -1;
    }

    if (bind(sfd1, (struct sockaddr*)&my_address1, sizeof(my_address1)) == -1) {
        cerr << "Error binding socket." << endl;
        close(sfd1);
        return -1;
    }

    if (listen(sfd1, 3) == -1) {
        cerr << "Error listening on socket." << endl;
        close(sfd1);
        return -1;
    }
    
    RSA* rsa = generateRSAKeyPair(2048);
    
    sleep(1);
    
	while (true)
	{
		int nsfd = accept(sfd1, (struct sockaddr*)&client_address, &client_address_len);
		if (nsfd == -1) {
		    cerr << "Error accepting connection." << endl;
		    close(sfd1);
		    return -1;
		}
		
		struct client req_details;
		req_details.nsfd=nsfd;
		req_details.rsa=rsa;
		
		pthread_t id;
		pthread_create(&id, NULL, multipleClients, &req_details);
		
    }
	close(sfd1);
    return 0;
}
