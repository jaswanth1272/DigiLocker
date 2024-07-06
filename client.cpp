#include <bits/stdc++.h>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/aes.h>

using namespace std;

RSA* rsa_client;

RSA* generateRSAKeyPair(int bits) {
    RSA* rsa = RSA_new();
    BIGNUM* e = BN_new();

    // Set public exponent
    BN_set_word(e, RSA_F4);

    // Generate key pair
    RSA_generate_key_ex(rsa, bits, e, NULL);

    BN_free(e);
    return rsa;
}

int rsaEncrypt(const unsigned char* plaintext, int plaintextLen, unsigned char* encrypted, RSA* rsaPublicKey) {
    return RSA_public_encrypt(plaintextLen, plaintext, encrypted, rsaPublicKey, RSA_PKCS1_PADDING);
}

int rsaDecrypt(const unsigned char* encrypted, int encryptedLen, unsigned char* decrypted, RSA* rsaPrivateKey) {
    return RSA_private_decrypt(encryptedLen, encrypted, decrypted, rsaPrivateKey, RSA_PKCS1_PADDING);
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

//AES Encryption and Decryption
void aesEncryptInt(const unsigned char key[], int number, unsigned char* ciphertext) {
    AES_KEY aesKey;
    AES_set_encrypt_key(key, 128, &aesKey);

    unsigned char plaintext[sizeof(number)];
    memcpy(plaintext, &number, sizeof(number));

    AES_encrypt(plaintext, ciphertext, &aesKey);
}

// AES decryption function for an integer
int aesDecryptInt(const unsigned char key[], const unsigned char* ciphertext) {
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

void hashString(string toHashString, int sfd, RSA* rsaServer) {
    EVP_MD_CTX* mdctx;
    const EVP_MD* md;
    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;
    const char* input_string = toHashString.c_str();

    OpenSSL_add_all_digests();

    md = EVP_get_digestbyname("sha256");
    if (md == NULL) {
        fprintf(stderr, "Unknown message digest\n");
        return;
    }

    mdctx = EVP_MD_CTX_new();
    if (mdctx == NULL) {
        fprintf(stderr, "Failed to create message digest context\n");
        return;
    }

    if (1 != EVP_DigestInit_ex(mdctx, md, NULL)) {
        fprintf(stderr, "Failed to initialize message digest\n");
        return;
    }

    if (1 != EVP_DigestUpdate(mdctx, input_string, strlen(input_string))) {
        fprintf(stderr, "Failed to update message digest\n");
        return;
    }

    if (1 != EVP_DigestFinal_ex(mdctx, md_value, &md_len)) {
        fprintf(stderr, "Failed to finalize message digest\n");
        return;
    }

    EVP_MD_CTX_free(mdctx);

    printf("Hashed string: ");
    for (int i = 0; i < md_len; i++) {
        printf("%02x", md_value[i]);
    }
    printf("\n");

    const unsigned char* plainPass = md_value;
    int plainPassLen = md_len;
    
    // Convert hashed password to a string representation
    stringstream ss;
    for (int i = 0; i < md_len; i++) {
        ss << hex << setw(2) << setfill('0') << (int)plainPass[i];
    }
    string hashedPasswordString = ss.str();
    
    // Encrypt the hashed password string
    unsigned char encryptedPass[2048] = {0};
    int encryptedPassLen = rsaEncrypt((const unsigned char*)hashedPasswordString.c_str(), hashedPasswordString.length(), encryptedPass, rsaServer);

    //unsigned char encryptedPass[2048] = {0};
    //int encryptedPassLen = rsaEncrypt(plainPass, plainPassLen, encryptedPass, rsaServer);

    if (encryptedPassLen == -1) {
        cerr << "Encryption failed" << endl;
        RSA_free(rsaServer);
        close(sfd);
        return;
    }

	//encryptedPass[encryptedPassLen]='\0';	
	
	cout<<encryptedPassLen<<"    "<<encryptedPass<<endl;
	
    send(sfd, encryptedPass, encryptedPassLen, 0);
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

RSA* createMyKeys(int sfd)
{
	RSA* rsa = generateRSAKeyPair(2048);
    const BIGNUM *n = NULL, *e = NULL, *d = NULL;
    RSA_get0_key(rsa, &n, &e, &d);

    char* pubN = printHex(n, "Public key (n)");
    char* pubE = printHex(e, "Public key (e)");

    send(sfd, pubN, strlen(pubN), 0);
 
    sleep(1);
    
    send(sfd, pubE, strlen(pubE), 0);
    
    return rsa;
}


unsigned char key[32]; // Assuming a 256-bit key for AES-256
void generate_symmetricKey(RSA* rsaServer, int sfd) {
    

    if (RAND_bytes(key, sizeof(key)) != 1) {
        cerr << "Error generating random bytes for key\n";
        return;
    }

    // Now 'key' contains the generated symmetric key
    cout << "Generated key: ";
    for (int i = 0; i < sizeof(key); ++i) {
        printf("%02x", key[i]);
    }
    cout << endl;

    unsigned char encryptedKey[2048] = {0}; // Adjust size as needed
    int encryptedKeyLen = rsaEncrypt((const unsigned char*)(key), sizeof(key), encryptedKey, rsaServer);

    encryptedKey[encryptedKeyLen] = '\0';

    cout << "Encrypted Key Length: " << encryptedKeyLen << endl;
    cout << "Encrypted Key: ";
    for (int i = 0; i < encryptedKeyLen; ++i) {
        printf("%02x", encryptedKey[i]);
    }
    cout << endl;

    if (encryptedKeyLen == -1) {
        cerr << "Encryption failed" << endl;
        return;
    }

    send(sfd, encryptedKey, encryptedKeyLen, 0);
}

void onSuccess(int sfd)
{
	int port, id;
	unsigned char encryptedPort[AES_BLOCK_SIZE]; // Allocate memory for decryptedPort
    
    cout << "key is : ";
    for (int i = 0; i < 32; ++i) {
        printf("%02x", key[i]);
    }
    cout << endl;	

	// Receive and decrypt port
	int n = recv(sfd, encryptedPort, 10000, 0);
	cout<<"Size recieved is : "<<n<<endl;
	if (n < 0) {
		cerr << "Error receiving decryptedPort\n";
		return;
	}
	encryptedPort[n] = '\0'; // Ensure null-termination
	
	cout<<"EncryptedPort is : "<<encryptedPort<<endl;
	sleep(1);
	cout<<"Decryption is going on ... "<<endl;
	port = aesDecryptInt(key, (unsigned char*)encryptedPort);
	
	sleep(1);
	
	cout << "Decrypted port: " << port << endl;

	unsigned char encryptedIdentity[AES_BLOCK_SIZE]; // Allocate memory for decryptedPort
    
    cout << "key is : ";
    for (int i = 0; i < 32; ++i) {
        printf("%02x", key[i]);
    }
    cout << endl;	

	// Receive and decrypt port
	n = recv(sfd, encryptedIdentity, 10000, 0);
	cout<<"Size recieved is : "<<n<<endl;
	if (n < 0) {
		cerr << "Error receiving decryptedPort\n";
		return;
	}
	encryptedIdentity[n] = '\0'; // Ensure null-termination
	
	cout<<"EncryptedIdentity is : "<<encryptedIdentity<<endl;
	sleep(1);
	cout<<"Decryption is going on ... "<<endl;
	id = aesDecryptInt(key, (unsigned char*)encryptedIdentity);
	
	sleep(1);
	
	cout << "Decrypted identity: " << id << endl;
	
	cout<<"port is : "<<port<<endl;
	cout<<"Id is : "<<id<<endl; 
	
	close(sfd);
	
	int csfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in serv_address;
    memset(&serv_address, 0, sizeof(serv_address));
    serv_address.sin_family = AF_INET;
    serv_address.sin_addr.s_addr = inet_addr("127.0.0.0");
    serv_address.sin_port = htons(port);
	
	sleep(1);

    connect(csfd, (struct sockaddr*)&serv_address, sizeof(serv_address));
    
    cout<<"csfd is : "<<csfd<<endl;
    send(csfd,&id,sizeof(id),0);
    
    char validation[100];
    n=recv(csfd,validation,sizeof(validation),0);
    validation[n]='\0';
    cout<<validation<<endl;
    
	if (strcmp(validation,"valid")==0)
	{
		cout<<"Valid User"<<endl;

		string pdfName;
		cout<<"Enter the name of the pdf you want to store"<<endl;
		cin>>pdfName;
		sleep(1);
		send(csfd,pdfName.c_str(),pdfName.length(),0);
		
		char msg[100];
		n = recv(csfd,msg, sizeof(msg),0);
		msg[n]='\0';
		cout<<"msg is : "<<msg<<endl;
		
		char msgerr[100] = "no";
		if(strcmp(msg,msgerr)==0)
		{
			cout<<"enter citizen pin"<<endl;
			string pin;
			cin>>pin;
			
			unsigned char ciphertextPin[AES_BLOCK_SIZE];

			aesEncrypt(key, (unsigned char*)pin.c_str(), ciphertextPin);
			
			sleep(1);
			
			cout<<"Encrypted Pin is : "<<ciphertextPin<<endl;
			
			send(csfd, ciphertextPin,strlen((char*)ciphertextPin),0);
			//send(csfd,pin.c_str(),pin.length(),0);
		}
		
    }
}


void onSignIn(int sfd,char pubE[], char pubN[], int action)
{
	string username, password;
    cout << "Enter the username" << endl;
    cin >> username;
    cout << "Enter the password" << endl;
    cin >> password;

    RSA* rsaServer = setRSAAttributes(pubN, pubE);

    // Encryption
    unsigned char encryptedUsername[2048] = {0};
    int encryptedUsernameLen = rsaEncrypt((const unsigned char*)(username.c_str()), username.length(), encryptedUsername, rsaServer);

    if (encryptedUsernameLen == -1) {
        cerr << "Encryption failed" << endl;
        RSA_free(rsaServer);
        close(sfd);
        return;
    }
	
	//encryptedUsername[encryptedUsernameLen]='\0';
	
	cout<<encryptedUsernameLen<<"   "<<encryptedUsername<<endl;
	
	send(sfd, &action, sizeof(action), 0); 

	sleep(1);

    send(sfd, encryptedUsername, encryptedUsernameLen, 0);
    
    sleep(1);
    
    rsa_client=createMyKeys(sfd);
    
  	sleep(1);
    
    hashString(password, sfd, rsaServer);
    
    sleep(1);
    
    generate_symmetricKey(rsaServer, sfd);
    
    onSuccess(sfd);

    RSA_free(rsaServer);
}

int main() {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);

    struct sockaddr_in serv_address;
    memset(&serv_address, 0, sizeof(serv_address));
    serv_address.sin_family = AF_INET;
    serv_address.sin_addr.s_addr = inet_addr("127.0.0.4");
    serv_address.sin_port = htons(8081);

    connect(sfd, (struct sockaddr*)&serv_address, sizeof(serv_address));

    char pubN[2048], pubE[2048];

    recv(sfd, pubN, sizeof(pubN), 0);
    cout << pubN << endl << endl;

    recv(sfd, pubE, sizeof(pubE), 0);
    cout << pubE << endl << endl;
    
    cout<<"Type 1 for \'SignIn\' Else Type 2 for \'SignUp\'"<<endl; 
    
    int decision;
    cin>>decision;
    
    onSignIn(sfd,pubE,pubN,decision);
    
    
    
    close(sfd);
    return 0;
}
