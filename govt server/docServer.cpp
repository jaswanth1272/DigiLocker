#include <bits/stdc++.h>
#include <pthread.h>
#include <unistd.h> // Include for close() function
#include <sys/socket.h>
#include <arpa/inet.h>
#include <fcntl.h> // Include for open() function
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <pthread.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;

struct thread_input {
    int port;
    string name;
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

int rsaEncrypt(const unsigned char* plaintext, int plaintextLen, unsigned char* encrypted, RSA* rsaPublicKey) {
    return RSA_public_encrypt(plaintextLen, plaintext, encrypted, rsaPublicKey, RSA_PKCS1_PADDING);
}

int rsaDecrypt(const unsigned char* encrypted, int encryptedLen, unsigned char* decrypted, RSA* rsaPrivateKey) {
    return RSA_private_decrypt(encryptedLen, encrypted, decrypted, rsaPrivateKey, RSA_PKCS1_PADDING);
}

string rsaPrivateEncrypt(const unsigned char *plaintext, int plaintextLen, RSA *rsa)
{
    unsigned char *encrypted = new unsigned char[RSA_size(rsa)]; // Allocate memory
    int encryptedLen = RSA_private_encrypt(plaintextLen, plaintext, encrypted, rsa, RSA_PKCS1_PADDING);
    if (encryptedLen == -1)
    {
        // Error handling
        delete[] encrypted; // Don't forget to free memory
        return "";          // Return empty string indicating failure
    }
    string EncryptedText(reinterpret_cast<const char *>(encrypted), encryptedLen);
    delete[] encrypted; // Free memory
    return EncryptedText;
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

/*void sendFileOverSocket(SSL* ssl, const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file.is_open()) {
        cerr << "Error opening file: " << filename << endl;
        return;
    }

    stringstream buffer;
    buffer << file.rdbuf();
    string fileContents = buffer.str();

    SSL_write(ssl, fileContents.c_str(), fileContents.size());
    SSL_shutdown(ssl);
    file.close();
}

void sendpdf()
{
	SSL_library_init();
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_client_method());
    SSL* ssl = SSL_new(ctx);

    // Create a socket
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        cerr << "Error creating socket" << endl;
        return 1;
    }

    // Set up server address
    struct sockaddr_in serverAddr;
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(8888);  // Example port
    inet_pton(AF_INET, "127.0.0.1", &serverAddr.sin_addr);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        cerr << "Error connecting to server" << endl;
        return 1;
    }

    // Perform SSL handshake
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        cerr << "Error performing SSL handshake" << endl;
        return 1;
    }

    // Send PDF file over the socket
    sendFileOverSocket(ssl, "/path/to/example.pdf");

    // Clean up SSL and socket connections
    SSL_shutdown(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
}*/

void* server_thread(void* args) {

	RSA* rsa = generateRSAKeyPair(2048);
    const BIGNUM *n = NULL, *e = NULL, *d = NULL;
    RSA_get0_key(rsa, &n, &e, &d);
    
    
	
    thread_input* t = (thread_input*)args;
    
    cout<<t->name<<" server public key"<<endl;

    char* pubN = printHex(n, "Public key (n)");
    char* pubE = printHex(e, "Public key (e)");

    int port = t->port;
    string name = t->name;

    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1) {
        cerr << "Error creating socket." << endl;
        return NULL;
    }

    struct sockaddr_in my_address1, client_address;
    socklen_t client_address_len = sizeof(client_address);

    memset(&my_address1, 0, sizeof(my_address1));
    my_address1.sin_family = AF_INET;
    my_address1.sin_addr.s_addr = inet_addr("127.0.0.4");
    my_address1.sin_port = htons(port);

    int reuse = 1;
    if (setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) == -1) {
        cerr << "Error setting SO_REUSEADDR." << endl;
        close(sfd);
        return NULL;
    }

    if (bind(sfd, (struct sockaddr*)&my_address1, sizeof(my_address1)) == -1) {
        cerr << "Error binding socket." << endl;
        close(sfd);
        return NULL;
    }

    if (listen(sfd, 3) == -1) {
        cerr << "Error listening on socket." << endl;
        close(sfd);
        return NULL;
    }

    while (true) {
        int nsfd = accept(sfd, (struct sockaddr*)&client_address, &client_address_len);
        if (nsfd == -1) {
            cerr << "Error accepting connection." << endl;
            close(sfd);
            return NULL;
        }
        
        send(nsfd, pubN, strlen(pubN), 0);
		sleep(1);
		send(nsfd, pubE, strlen(pubE), 0);
		
		char encryptedUsername[2048] = {0}; // Adjust size as needed
		int len = recv(nsfd, encryptedUsername, sizeof(encryptedUsername), 0);
		encryptedUsername[len] = '\0';
		
		sleep(1);

		cout << "Received encrypted Username: " << encryptedUsername <<" "<<len<< endl;

		unsigned char decryptedUsername[2048] = {0};
		
		int usernameLen = len; // Use the actual length received
		int decryptedUsernameLen = rsaDecrypt((const unsigned char*)encryptedUsername, usernameLen, decryptedUsername, rsa);

		if (decryptedUsernameLen == -1) {
		    cerr << "Decryption failed" << endl;
		    RSA_free(rsa);
		    close(nsfd);
		    
		}
		sleep(1);

		cout << "Decrypted Username: ";
		for (int i = 0; i < decryptedUsernameLen; ++i) {
		    printf("%02x", decryptedUsername[i]);
		}
		cout << endl;	
		
		// Assuming decryptedUsername contains a string, print it as a string
		cout << "Decrypted Username (String): " << decryptedUsername << endl;

		sleep(1);

        /*char usr_pin[100];
    	int pin_sz = recv(nsfd, usr_pin, sizeof(usr_pin), 0);
    	cout<<pin_sz<<endl;
    	usr_pin[pin_sz]='\0';*/
    	
    	char encryptedUserPin[2048] = {0}; // Adjust size as needed
		int pinlen = recv(nsfd, encryptedUserPin, sizeof(encryptedUserPin), 0);
		encryptedUserPin[pinlen] = '\0';
		
		sleep(1);

		cout << "Received encrypted UserPin: " << encryptedUserPin <<" "<<pinlen<< endl;

		unsigned char decryptedUserPin[2048] = {0};
		
		int userPinLen = pinlen; // Use the actual length received
		int decryptedUserPinLen = rsaDecrypt((const unsigned char*)encryptedUserPin, pinlen, decryptedUserPin, rsa);

		if (decryptedUserPinLen == -1) {
		    cerr << "Decryption failed" << endl;
		    RSA_free(rsa);
		    close(nsfd);
		    
		}
		sleep(1);

		cout << "Decrypted UserPin: ";
		for (int i = 0; i < decryptedUserPinLen; ++i) {
		    printf("%02x", decryptedUserPin[i]);
		}
		cout << endl;	
		
		// Assuming decryptedUsername contains a string, print it as a string
		cout << "Decrypted UserPin (String): " << decryptedUserPin << endl;

		sleep(1);
    	
    	string pin_loc = "citizen_pin/"+string((const char*)decryptedUsername)+".txt";
    	
    	int rpfd = open(pin_loc.c_str(), O_RDONLY);
    	
    	char or_pin[100];
    	
    	int n1 = read(rpfd,or_pin,sizeof(or_pin));
    	
    	or_pin[n1-1]='\0';
    	
    	cout<<n1-1<<endl;
    	
    	if(strcmp(or_pin,(const char*)decryptedUserPin)==0)
    	{
    		 // Corrected string concatenation
    		string folder_loc = name + "/" + string((const char*)decryptedUsername) + ".txt";

	        cout << folder_loc << endl;

			// Corrected folder_loc usage and added .c_str()
	        int rfd = open(folder_loc.c_str(), O_RDONLY); 
	        
	        char details[1000];
	        
	        int n=read(rfd,details,sizeof(details));
	        details[n-1]='\0';

    		string hash = sha256Hash((string)details);
    		
    		cout<<hash<<endl;
    		
    		string h1 = rsaPrivateEncrypt((const unsigned char*)hash.c_str(),hash.length(),rsa);
    		
    		string toSend=string(details)+","+h1;
    		//cout<<"to send is "<<toSend<<endl;
	       
	        send(nsfd, toSend.c_str(),toSend.length(),0);
	        
    	}
    	else
    	{
    		string details="wrong pin";
	        
	        send(nsfd, details.c_str(),details.length(),0);
    	}
        close(nsfd); // Close client socket after communication
    }

    return NULL;
}

int main() {
    thread_input* t1 = new thread_input();
    thread_input* t2 = new thread_input();
    t1->port = 10000;
    t1->name = "aadhar";

    t2->port = 10001;
    t2->name = "license";

    pthread_t th1, th2;
    pthread_create(&th1, NULL, server_thread, t1); // Corrected function pointer and argument passing
    pthread_create(&th2, NULL, server_thread, t2);

    pthread_join(th1, NULL); // Wait for threads to finish
    pthread_join(th2, NULL);

    delete t1; // Free allocated memory
    delete t2;

    return 0;
}

