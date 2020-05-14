#include "common.h"

#define CERTFILE "server.pem"
#define MAX_VALUE 1000

SSL	*ssl_array[MAX_VALUE];
pthread_mutex_t lock;
int number = 0;

SSL_CTX *setup_server_ctx(void)
{
	SSL_CTX *ctx;

	ctx = SSL_CTX_new(SSLv23_method(  ));

	if(SSL_CTX_use_certificate_chain_file(ctx, CERTFILE) != 1)
		int_error("Error loading certificate from file");

	if(SSL_CTX_use_PrivateKey_file(ctx, CERTFILE, SSL_FILETYPE_PEM) != 1)
		int_error("Error loading private key from file");

	return ctx;
}

int do_server_loop(SSL *ssl)
{
	int err, nread, nwritten;
	char buf[80];

	do
	{
		fprintf(stderr, "Read is Ready!\n");

		for(nread=0;nread<sizeof(buf);nread+=err)
		{
			err = SSL_read(ssl, buf + nread, sizeof(buf) - nread);

			if(err <= 0)
				break;
		}

		fprintf(stderr, "Read from the Client\n\n");

		fprintf(stderr, "%s\n\n", buf);

		fprintf(stderr, "Write is Ready!\n");

		for (int i = 0; i < number; i++)
		{
			if(ssl_array[i] != NULL)
			{
				for (nwritten = 0; nwritten < sizeof(buf); nwritten += err)
				{
					err = SSL_write(ssl_array[i], buf + nwritten, sizeof(buf) - nwritten);

					if (err <= 0)
						return 0;
				}
			}

			if (ssl_array[i] == ssl)
			{
				char tmp[80];

				strcpy(tmp, buf);

				char *ptr = strtok(tmp, ":");
				ptr = strtok(NULL, ":");

				fprintf(stderr, "%s", ptr);

				if(!strncmp("Exit", ptr, 4))
				{
					ssl_array[i] = NULL;
					return 1;
				}
			}
		}

		fprintf(stderr, "Write is done\n");
	}
	while(err > 0);

	return (SSL_get_shutdown(ssl) & SSL_RECEIVED_SHUTDOWN) ? 1 : 0;
}

void THREAD_CC server_thread(void *arg)
{
	int err, nwritten;
	char tmp[80];

	SSL *ssl = (SSL *)arg;
#ifndef WIN32
	pthread_detach(pthread_self(  ));
#endif
	if(SSL_accept(ssl) <= 0)
		int_error("Error accepting SSL connection");

	fprintf(stderr, "SSL Connection Opened\n");

	pthread_mutex_lock(&lock);

	sprintf(tmp, "%d", number);

	for (nwritten = 0; nwritten < sizeof(tmp); nwritten += err)
	{
		err = SSL_write(ssl, tmp + nwritten, sizeof(tmp) - nwritten);
		printf("For");

		if (err <= 0)
			exit(1);
	}

	number++;

	pthread_mutex_unlock(&lock);

	fprintf(stderr, "Correct");

	if (do_server_loop(ssl))
		SSL_shutdown(ssl);
	else
		SSL_clear(ssl);

	fprintf(stderr, "SSL Connection Closed\n");

	SSL_free(ssl);

	ERR_remove_state(0);

#ifdef WIN32
	_endthread();
#endif
}

int main(int argc, char *argv[])
{
	BIO		*acc, *client;
	SSL_CTX		*ctx;
	THREAD_TYPE	tid;

	init_OpenSSL(  );
	seed_prng(  );

	ctx = setup_server_ctx(  );

	acc = BIO_new_accept(PORT);

	if(!acc)
		int_error("Error Creating Server Socket");

	if(BIO_do_accept(acc) <= 0)
		int_error("Error Binding Server Socket");

	if (pthread_mutex_init(&lock, NULL) != 0)
	{
		printf("\nmutex init failed\n");
		return 1;
	}

	for(;;)
	{
		if(BIO_do_accept(acc) <= 0)
			int_error("Error accepting connection");

		client = BIO_pop(acc);

		if(!(ssl_array[number] = SSL_new(ctx)))
			int_error("Error creating SSL context");

		SSL_set_bio(ssl_array[number], client, client);

		THREAD_CREATE(tid, (void *)server_thread, ssl_array[number]);
	}

	pthread_mutex_destroy(&lock);
	SSL_CTX_free(ctx);
	BIO_free(acc);

	return 0;
}
