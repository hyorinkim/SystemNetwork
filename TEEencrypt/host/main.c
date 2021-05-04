/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h> 
#include <fcntl.h>
#include <unistd.h> 
#include <errno.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

int main(int argc, char *argv[])//int argc,int argv[]?
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char decrypttext[64] = {0,};
	char ciphertext[64] = {0,};
	char encrypted_key[1]={0};
	char decrypted_key[1]={0};
	int len=64;

	/* Initialize a context connecting us to the TEE */
	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	/*
	 * Open a session to the "hello world" TA, the TA will print "hello
	 * world!" in the log when the session is created.
	 */
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);
	
	/*printf("argv's number %d\n",argc);
	if(argc>1){
		printf("argv[1]%s  argv[2] %s\n",argv[1],argv[2]);	
	}*/
	// input filename check

	/*
	 * Execute a function in the TA by invoking it, in this case
	 * we're incrementing a number.
	 *
	 * The value of command ID part and how the parameters are
	 * interpreted is part of the interface provided by the TA.
	 */

	/* Clear the TEEC_Operation struct */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = sizeof(plaintext);
	/*
	 * Prepare the argument. Pass a value in the first parameter,
	 * the remaining three parameters are unused.
	 */
	//-e , -d function devide need argv[0]=-e or -d argv[1]=filename
	if(strcmp(argv[1],"-e")==0){	
		printf("========================Encryption========================\n");
		printf("Read the Plaintext : ");

		int fd;//read the plaintext.txt
		char str[1024]="/root/";	
		strcat(str,argv[2]);
		if((fd = open(str, O_RDONLY)) == -1) { 
			fprintf(stderr, "plaintext.txt 파일을 open도중 오류 발생: %s\n", 	strerror(errno));
			 return -1; 
		}
	
		read(fd,plaintext,len);
		puts(plaintext);
		close(fd);	
		//read plaintext.txt

		res = TEEC_InvokeCommand(&sess,TA_TEEencrypt_CMD_RANDOMKEY_GET, &op,
					 &err_origin);//randomkey generate
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed randomkey code 0x%x origin 0x%x",
				res, err_origin);
		
		memcpy(op.params[0].tmpref.buffer, plaintext, sizeof(plaintext));//plaintext send TA
	
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENC_VALUE, &op,
					 &err_origin);//Ta calling ENC do!!
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed enc_value code 0x%x origin 0x%x",
				res, err_origin);
		memcpy(ciphertext, op.params[0].tmpref.buffer, len);//TA send and CA ciphertext receive
		printf("Ciphertext : %s\n", ciphertext);
		
		FILE *fw=fopen("/root/ciphertext.txt","w");//save ciphertext.txt
		if(0<fw){
			fputs(ciphertext,fw);
			fclose(fw);	
		}else{
			printf("fail write open\n");
		}	
		
		memcpy(op.params[0].tmpref.buffer, encrypted_key,1);
		res = TEEC_InvokeCommand(&sess,TA_TEEencrypt_CMD_RANDOMKEY_ENC, &op,
					 &err_origin);//ramdonkey encrytpion
		memcpy(encrypted_key, op.params[0].tmpref.buffer, 1);
		printf("\n ");
		//printf("encrypted_key is %s\n",encrypted_key);
	
	
		FILE *fe=fopen("/root/encryptedkey.txt","w");
	
		if(0<fe){
			fputs(encrypted_key,fe);
			fclose(fe);	
		}else{
			printf("fail write enc_key open\n");
		}
	}else if(strcmp(argv[1],"-d")==0){
		//argv[3]ciphertext.txt argv[4]encryptedkey.txt
		printf("======================Decryption==================\n");

		int fd;//read the ciphertext.txt
		char str[1024]="/root/";	
		strcat(str,argv[2]);
		if((fd = open(str, O_RDONLY)) == -1) { 
			fprintf(stderr, "chipher.txt 파일을 open도중 오류 발생: %s\n", 	strerror(errno));
			 return -1; 
		}
		
		read(fd,ciphertext,len);
		printf("read cipher text is ");
		puts(ciphertext);
		close(fd);	
		
		int fdk;//read the encryptedkeytext.txt
		char strk[1024]="/root/";	
		strcat(strk,argv[3]);
		if((fdk = open(strk, O_RDONLY)) == -1) { 
			fprintf(stderr, "encryptedkey.txt 파일을 open도중 오류 발생: %s\n", 	strerror(errno));
			 return -1; 
		}
		
		read(fdk,decrypted_key,1);//before decrypt it is encryptedkey
		close(fdk);

		//decrypted_key
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
//
		op.params[0].tmpref.buffer = decrypttext;//clean buffer
		op.params[0].tmpref.size = len;
		
		memcpy(op.params[0].tmpref.buffer, decrypted_key, 1);
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_RANDOMKEY_DEC, &op,
					 &err_origin);//ramdomkey decrypt
		
		op.params[0].tmpref.buffer = decrypttext;//clean buffer
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed random key decrypt code 0x%x origin 0x%x",
				res, err_origin);

		memcpy(op.params[0].tmpref.buffer, ciphertext, len);
		
		res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DEC_VALUE, &op,
					 &err_origin);//ciphertext decrypt
		
		if (res != TEEC_SUCCESS)
			errx(1, "TEEC_InvokeCommand failed decrypt code 0x%x origin 0x%x",
				res, err_origin);
		memcpy(decrypttext, op.params[0].tmpref.buffer, len);
		printf("DecryptedResult : %s\n", decrypttext);
		
		FILE *fdw=fopen("/root/decryptResult.txt","w");//save decryptResult.txt
		if(0<fdw){
			fputs(decrypttext,fdw);
			fclose(fdw);	
		}else{
			printf("fail write open\n");
		}	
		
	}
////////

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
