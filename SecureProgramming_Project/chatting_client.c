#include "common.h"

#define CERTFILE "client.pem"

char client_id[80];
char exit_event[80];
char *content[200];
pthread_mutex_t mutex_lock;

SSL_CTX *setup_client_ctx(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(SSLv23_method(  ));
	
	if(SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
		int_error("Error loading certificate from file");

	if(SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
		int_error("Error loading private key from file");

	return ctx;
}

void *read_t(void *data) {
	char buf[80];
	SSL *ssl = (SSL *)data;
	int nread, err, cnt = 0, i;
	
	while(1) {
		memset(buf, 0, sizeof(buf));
		for(nread = 0; nread < sizeof(buf); nread += err) {
			err = SSL_read(ssl, buf + nread, sizeof(buf) - nread);
			if(err <= 0)
				return (void *)(0);
		}
		
			
		
		if(strlen(buf) >= strlen(exit_event) && strncmp(exit_event, buf, strlen(exit_event)) == 0) {
			exit(0); 
		}
		content[cnt] = (char *)malloc(strlen(buf) + 1);
		strcpy(content[cnt++], buf);
		system("clear");
		for(i = 0; i < cnt; i++)
			fprintf(stdout, "%s\n", content[i]);

	}	
	return (void *)1;
}

int do_client_loop(SSL *ssl)
{
	int err, nwritten;
	char buf[80], input[80];
	pthread_t read_thread;
	int read_result, cnt_input;
	
	pthread_create(&read_thread, NULL, read_t, (void *)ssl);
	
	for(;;) {
		memset(buf, 0, sizeof(buf));
		memset(input, 0, sizeof(input));
		cnt_input = 0;
		while(1)  {
			input[cnt_input] = fgetc(stdin);
			if(cnt_input == 78 || input[cnt_input] == '\n')
				break;
			
			cnt_input++;
		}	
		input[cnt_input + 1] = '\0';	
		
		sprintf(buf, "%s:%s", client_id, input);
		for(nwritten = 0; nwritten < sizeof(buf); nwritten += err) {
			err = SSL_write(ssl, buf + nwritten, sizeof(buf) - nwritten);
			if(err <= 0)
				return 0;
		}
	}
	pthread_join(read_thread, (void **)&read_result);
	
	if(read_result == 0)
		return 0;
	return 1;
}

int main(int argc, char *argv[])
{
	BIO	*conn;
	SSL	*ssl;
	SSL_CTX *ctx;


	init_OpenSSL(  );
	seed_prng(  );

	ctx = setup_client_ctx(  );

	conn = BIO_new_connect(SERVER ":" PORT);

	if(!conn)
		int_error("Error creating connection BIO");

	if(BIO_do_connect(conn) <= 0)
		int_error("Error connecting to remote machine");

	if(!(ssl = SSL_new(ctx)))
		int_error("Error creating an SSL context");

	SSL_set_bio(ssl, conn, conn);

	if(SSL_connect(ssl) <= 0)
		int_error("Error connecting SSL object");

	fprintf(stderr, "SSL Connection opened\n");
	
	int i, err;
	for(i = 0; i < sizeof(client_id); i += err) {
		err = SSL_read(ssl, client_id + i, sizeof(client_id) - i);
		
		if(err <= 0) {
			fprintf(stderr, "Error in reading client_id\n");
			break; 
		}
	}

	if(err > 0) {
		fprintf(stdout, "client_id : %s\n", client_id);
		sprintf(exit_event, "%s:Exit", client_id);
	}

	if(err > 0 && do_client_loop(ssl))
		SSL_shutdown(ssl);
	else
		SSL_clear(ssl);

	fprintf(stderr, "SSL Connection closed\n");

	SSL_free(ssl);
	SSL_CTX_free(ctx);

	return 0;
}
