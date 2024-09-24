// RSA_bigint.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <process.h>
// #include <gmpxx.h> //for linux and mac
#include <mpir.h>


using namespace std;

#define MAX_LINE_LENGTH 1000
#define MAX_MSG_LENGTH 257

unsigned long read_from_file(char* text, FILE* file);
unsigned write_to_file(char* text, FILE* file, unsigned long len);
void print_text(char* text, unsigned long len);

void Encode(mpz_t& res, mpz_t& n, char* text, unsigned long len = 1);
void Decode(char* text, mpz_t xc, unsigned long &len );

// x is the plaintext, y is the ciphertext
void EncryptRSA(mpz_t& y, mpz_t& x, mpz_t& e, mpz_t& n);
void DecryptRSA(mpz_t& x, mpz_t& y, mpz_t& d, mpz_t& n);

//Part I
void InitializeRSA(mpz_t& p, mpz_t& q, mpz_t& n, mpz_t& phi_n, mpz_t& e, mpz_t& d, unsigned long _size);
//Part II
void Read_EncryptRSA_Write(mpz_t& p, mpz_t& q, mpz_t& n, mpz_t& phi_n, mpz_t& e, mpz_t& d, unsigned long _size);
//Part III
void Read_DecryptRSA_Write(mpz_t& p, mpz_t& q, mpz_t& n, mpz_t& phi_n, mpz_t& e, mpz_t& d, unsigned long _size);


void RSA_menu(mpz_t& p, mpz_t& q, mpz_t& n, mpz_t& phi_n, mpz_t& e, mpz_t& d, unsigned long _size) {
	int choice;
	printf("===============================================================\n");
	printf("Welcome to Arda Bugra OZER's RSA system.\n\n");
	
	printf("1) Generate parameters for RSA and write to parameters.txt\n");
	printf("2) Encrypt from plain.txt and write to cipher.txt\n");
	printf("3) Decrypt from cipher.txt and write to message.txt\n");
	
	choice = 0;

	do {
		printf("Enter your choice: ");
		scanf("%d", &choice);
		if ((choice > 3) || (choice < 1))
			printf("Invalid choice!\n");
	} while ((choice > 3) || (choice < 1));

	

	switch (choice) {
	case 1: {
		InitializeRSA(p, q, n, phi_n, e, d, _size);
		break;
	}
	case 2: {
		Read_EncryptRSA_Write(p, q, n, phi_n, e, d, _size);
		break;
	}
	case 3: {
		Read_DecryptRSA_Write(p, q, n, phi_n, e, d, _size);
		break;
	}
	default:
		printf("Wrong Input\n");
	}
}

// Proof that the system works with just integers
// without the file reading writing problems.
//int _main() {
//	
//	mpz_t x, y, n ,e,d;
//	mpz_inits(x, y, 0);
//	mpz_init_set_str(n, "14983694192651602466753619652281395214286885400373641821218331243836627246380642403484068637124429749599741698188039938232512561337890371643535395152162836656979509344635159508150531985009700340997509965072955859663900847763355192931543720219485737079620872401286999059137452223596839263198301027073140224433159620455522725594050231883164247896816616964755620033897677329352651938966027528644560140570612358548025400953482584813397640694858100556519850611892630592781567239505826615519401340830537837588607811190172995392971987871414919374171435198821216191441592753387433758175035555031344998040863193361693873772891", 10);
//	mpz_init_set_str(e, "13407807929942597099574024998205846127479365820592393377723561443721764030073593837433889375109215031468023344649181849955142883911180318518404434688050651", 10);
//	mpz_init_set_str(d, "4468514069564298920297735049961497717595485597419824360056430252202196857136201438172589172020515329417179771383957261822292921213653909640372822153179150774727797918133071222203425129343988728907284572359055124391090293402592316202974944366778049633430568607102137961835755568800728856018171546649959787385468032053107080059613446769978727196093448994057453229973799120590330793721720471703796812627804812302550466108704189383481803682797577122432435759211130076127319787801238958876503327834779056507962704422648575382262837664812817083721702899096217040732935197347944576845042632972267343382671065427767080746851", 10);
//
//	//char text[] = "ab";
//	//char text[] = "abozer!?.:12345678901234567890a";
//	//char text[] = "abcÅº↕⌐ú∙J≈F>CóÉ≥0HWΩabc";
//	char text[] = "abozer!?.:12345678901234567890Åº↕⌐ú∙J≈F>CóÉ≥0HWΩabozer!?.";
//	char ntxt[10000];
//
//	printf(text);
//	printf("\n");
//
//	unsigned long len = strlen(text);
//
//	cout << len << endl;
//
//	Encode(x, n, text, len);
//	gmp_printf("\nx=%Zd\n", x);
//
//	EncryptRSA(y, x, e, n);
//	gmp_printf("\ny=%Zd\n", y);
//
//	///*mpz_tdiv_q_ui(x, x, 256);
//	//mpz_add_ui(x, x, 3);*/
//
//	unsigned long newlen = 0;
//	//Decode(ntxt, x, newlen);
//	
//	Decode(ntxt, y, newlen);
//	printf("The length of the ciphertext is %d\nIt is:\n",newlen);
//	print_text(ntxt,newlen);
//	printf("\n");
//
//	Encode(y, n, ntxt, newlen);
//	gmp_printf("\n%Zd\n", y);
//
//	DecryptRSA(x, y, d, n);
//	//gmp_printf("\nThe x we receive from Enc then Dec is \nx=%Zd\n", x);
//	gmp_printf("\nThe x we receive from Encode -> Encrypt -> Decode -> (write/read file) -> Encode -> Decrypt is \nx=%Zd\n", x);
//
//	Decode(ntxt, x, len);
//	printf(ntxt);
//	printf("\n");
//
//
//	return 0;
//}





int main() {
	unsigned long _size = 1024;

	mpz_t p, q, phi_n, n, e, d;
	mpz_inits(p, q, phi_n, n, e, d,0);

	//mpz_init(xx);

	//Part I
	//InitializeRSA(p, q, n, phi_n, e, d, _size);
	//Part II
	//Read_EncryptRSA_Write(p, q, n, phi_n, e, d, _size);
	//Part III
	//Read_DecryptRSA_Write(p, q, n, phi_n, e, d, _size);
	
	RSA_menu(p, q, n, phi_n, e, d, _size);
		
	return 0;
}





unsigned long read_from_file(char* text, FILE* file) {
	//check if file is valid
	if (file == NULL) {
		printf("file could not be opened!!\n");
		exit(1);
	}

	long int len = -1;
	//char ch;
	do {
		text[++len] = fgetc(file);
		// Checking if character is not EOF.
		// If it is EOF stop reading.
	} while (text[len] != EOF);
	// Making last character 0;
	text[len] = 0;

	//fgets(text, 256, file);
	//len = strlen(text);
	return len;
}

unsigned write_to_file(char* text, FILE* file, unsigned long len) {
	//check if file is valid
	if (file == NULL) {
		printf("file could not be opened!!\n");
		exit(1);
	}

	//for (unsigned long i = 0; i < len; i++) {
	//	fputc(text[i], file);
	//}
	////fputc(EOF,file);
	fputs(text, file);

	return len;
}

void print_text(char* text, unsigned long len) {
	for (unsigned long int i = 0; i < len; i++) {
		printf("%c", text[i]);
	}
}

void Encode(mpz_t& res, mpz_t& n, char* text, unsigned long len) {
	//// Encode text into mpz_t so that the leftmost character is the most significant
	//mpz_set_ui(res, 0);

	//for (unsigned long int i = 0; i < len; i++) {
	//	mpz_add_ui(res, res, (unsigned)text[i]); //encode the character and add
	//	if (i < len - 1) {
	//		mpz_mul_ui(res, res, 256);
	//	}
	//}
	//mpz_mod(res, res, n);
	// 
	// UNFORTUNATELY MY CODE ABOVE DOES NOT WORK BECAUSE OF CHARACTER ENCODING PROBLEMS
	// INSTEAD WE USE THE BUILT IN FUNCTIONS

	mpz_import(res, len, 1, 1, 0, 0, text);
}

void Decode(char* text, mpz_t xc, unsigned long& len) {
	//// Decode mpz_t xc into text so that the leftmost is the most significant
	//mpz_t r; mpz_init_set_ui(r, 0);
	//mpz_t tmp; mpz_init_set(tmp, xc);
	//char rev_text[MAX_LINE_LENGTH];
	//unsigned long i = 0;
	//unsigned ch = mpz_get_ui(r);
	////the following decodes from int to string, but in reverse order, also calculates the length of the outcome string.
	//while (mpz_sgn(tmp) > 0) {
	//	mpz_mod_ui(r, tmp, 256);
	//	ch = mpz_get_ui(r);
	//	rev_text[i] = ch;
	//	mpz_tdiv_q_ui(tmp, tmp, 256);
	//	i++;
	//}
	//rev_text[i] = 0; // finish up string
	//len = i; // set len for stringlength for later use and this is returned in the function

	//for (i = 0; i < len; i++) {
	//	text[i] = rev_text[len - i - 1];
	//}
	//text[len] = 0;// last char of string 

	// UNFORTUNATELY MY CODE ABOVE DOES NOT WORK BECAUSE OF CHARACTER ENCODING PROBLEMS
	// INSTEAD WE USE THE BUILT IN FUNCTIONS

	len = mpz_sizeinbase(xc, 256);
	mpz_export(text, NULL, 1, 1, 1, 0, xc);
	text[len] = 0;

}

void EncryptRSA(mpz_t& y, mpz_t& x, mpz_t& e, mpz_t& n) {
	// x is the plaintext, y is the ciphertext
	mpz_powm(y, x, e, n);
	//gmp_printf("x=%Zd and y=%Zd", x, );
}

void DecryptRSA(mpz_t& x, mpz_t& y, mpz_t& d, mpz_t& n) {
	// x is the plaintext, y is the ciphertext
	mpz_powm(x, y, d, n);
}



void InitializeRSA(mpz_t& p, mpz_t& q, mpz_t& n, mpz_t& phi_n, mpz_t& e, mpz_t& d, unsigned long _size) {
	/// <summary>
	/// This function initializes the RSA 
	/// </summary>
	/// <param name="p"> smaller prime </param>
	/// <param name="p"> bigger prime </param>
	/// <param name="n"> p*q </param>
	/// <param name="phi_n"> (p-1) (q-1) </param>
	/// <param name="e"> public key/param>
	/// <param name="d"> rivate key</param>
	/// <param name="_size"> bit-size of the system</param>

	mpz_t r; mpz_init(r); mpz_init_set_ui(r, 325);

	gmp_randstate_t randomstate; gmp_randinit_default(randomstate);
	gmp_randseed_ui(randomstate, _getpid());

	//mpz_t p; mpz_init(p);
	//mpz_t q; mpz_init(q);
	//we are looking for primes between 2^(_size-1) and 2^(_size)
	mpz_t min_prime; mpz_init_set_ui(min_prime, 2);
	mpz_pow_ui(min_prime, min_prime, _size - 1);

	mpz_urandomb(r, randomstate, _size - 2);
	//gmp_printf("%Zd\n", r);

	mpz_add(p, min_prime, r);
	mpz_next_prime_candidate(p, p, randomstate); // find p

	mpz_urandomb(r, randomstate, _size - 2);
	mpz_add(q, p, r);// randomly move away from p
	mpz_next_prime_candidate(q, q, randomstate); // find q
	//gmp_printf("p=%Zd\nq=%Zd\n", p, q);

	// some temporary variables
	mpz_t t1; mpz_init(t1);
	mpz_t t2; mpz_init(t2);

	//phi_n = (p-1)(q-1)
	mpz_sub_ui(t1, p, 1);
	mpz_sub_ui(t2, q, 1);
	mpz_mul(phi_n, t1, t2);
	mpz_clears(t1, t2, 0);
	//n = pq
	mpz_mul(n, p, q);

	//randomly create e so that gcd(e,phi_n)=1
	
	mpz_set_ui(min_prime, 2);
	mpz_pow_ui(min_prime, min_prime, _size/2);
	mpz_urandomb(r, randomstate, _size / 4);
	mpz_add(e, min_prime, r);// randomly move away from p
	if (mpz_even_p(e)) {
		mpz_add_ui(e, e, 1);
	}
	int ok = 0;
	unsigned gcd;
	do {
		mpz_gcd(r, e, phi_n);
		if (mpz_fits_uint_p(r))
			gcd = mpz_get_ui(r);
		else continue;

		if (gcd == 1) { ok = 1; }
		else {
			mpz_add_ui(e, e, 2);
		}

	} while (!ok);
	// at this point, the required e has been created
	//mpz_set_str(e, "65537", 10);

	//d is the inverse of e mod n
	mpz_invert(d, e, phi_n);
	printf("===============================================================\n");
	gmp_printf("RSA system has been created with the following parameters:\np=%Zd\nq=%Zd\nphi_n=%Zd\nn=%Zd\ne=%Zd\nd=%Zd\n", p, q, phi_n, n, e, d);
	printf("===============================================================\n");

	// Need to output to a file named parameters.txt .
	FILE* file;
	file = fopen("parameters.txt", "w");
	//check if file is valid
	if (file == NULL) {
		printf("parameters.txt could not be opened!!\n");
		exit(1);
	}

	//We write the data to the file in decimals, p, q, phi_n, e, d are on separate lines, respectively.
	unsigned long int flag = 1;
	flag *= (unsigned long int) mpz_out_str(file, 10, p); fputc('\n', file);
	flag *= (unsigned long int) mpz_out_str(file, 10, q); fputc('\n', file);
	flag *= (unsigned long int) mpz_out_str(file, 10, phi_n); fputc('\n', file);
	flag *= (unsigned long int) mpz_out_str(file, 10, n); fputc('\n', file);
	flag *= (unsigned long int) mpz_out_str(file, 10, e); fputc('\n', file);
	flag *= (unsigned long int) mpz_out_str(file, 10, d); fputc('\n', file);

	if (flag == 0) {
		printf("There was a problem writing the parameters. Exiting!!!\n");
		exit(1);
	}
	else {
		printf("Writing the parameters complete.\n");
		printf("===============================================================\n");
	}
	fclose(file);

}

void Read_EncryptRSA_Write(mpz_t& p, mpz_t& q, mpz_t& n, mpz_t& phi_n, mpz_t& e, mpz_t& d, unsigned long _size) {
	// Need to read from a file named parameters.txt .
	FILE* fparam;
	fparam = fopen("parameters.txt", "r");
	//check if file is valid
	if (fparam == NULL) {
		printf("parameters.txt could not be opened!!\n");
		exit(1);
	}

	char param[MAX_LINE_LENGTH] = { 0 };
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(p, param, 10);
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(q, param, 10);
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(phi_n, param, 10);
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(n, param, 10);
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(e, param, 10);
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(d, param, 10);
	printf("===============================================================\n");
	printf("Running Part II: Read and Encrypt and Write \n");
	gmp_printf("RSA system has been read from parameters.txt for encryption.\n");
	//gmp_printf("RSA system has been read from parameters.txt:\np=%Zd\nq=%Zd\nphi_n=%Zd\nn=%Zd\ne=%Zd\nd=%Zd\n", p, q, phi_n, n, e, d);
	printf("===============================================================\n");
	fclose(fparam);

	// Read the plaintext message from plain.txt
	FILE* fplain;
	fplain = fopen("plain.txt", "r");

	//check if file is valid
	if (fplain == NULL) {
		printf("plain.txt could not be opened!!\n");
		exit(1);
	}

	char plaintext[MAX_MSG_LENGTH] = { 0 };

	//fgets(plaintext, MAX_MSG_LENGTH, fplain);
	unsigned long len = read_from_file(plaintext, fplain);
	fclose(fplain);

	//Encode and store plaintext message as x
	mpz_t x; mpz_init(x);
	//unsigned long long len = strlen(plaintext);
	Encode(x, n, plaintext, len);
	
	// y is the ciphertext and EncryptRSA y=x^e (mod n)
	mpz_t y; mpz_init(y);

	EncryptRSA(y, x, e, n);

	//gmp_printf("The plaintext of length %d is  %s \nThe plaintext in integers is \nx=%Zd\nThe ciphertext in integers is \ny=%Zd\n\n", len, plaintext, x,y);

	//Decode the ciphertext from the integer result back to characters.
	char ciphertext[MAX_MSG_LENGTH];

	Decode(ciphertext, y, len);
	
	//print_text(ciphertext, len);
		
	//gmp_printf("+++\nThe ciphertext in integers is \ny=%Zd\n", y);
	printf("The ciphertext of length %d is\n", len);
	print_text(ciphertext, len);
	printf("\n+++\n\n");

	//Output the result to cipher.txt
	FILE* fcipher;
	fcipher = fopen("cipher.txt", "wb"); //writing binary
	//check if file is valid
	if (fcipher == NULL) {
		printf("cipher.txt could not be opened!!\n");
		exit(1);
	}
	//write_to_file(ciphertext, fcipher, len);

	// Cheating a little bit, because my write/read file functions are not working properly
	//mpz_out_str(fcipher, 10, y);
	fwrite(ciphertext, 1, len, fcipher);
	fclose(fcipher);

	printf("Writing cipher.txt complete.\n");
	printf("===============================================================\n");

}

void Read_DecryptRSA_Write(mpz_t& p, mpz_t& q, mpz_t& n, mpz_t& phi_n, mpz_t& e, mpz_t& d, unsigned long _size) {
	// Need to read from a file named parameters.txt .
	FILE* fparam;
	fparam = fopen("parameters.txt", "r");
	//check if file is valid
	if (fparam == NULL) {
		printf("parameters.txt could not be opened!!\n");
		exit(1);
	}

	char param[MAX_LINE_LENGTH] = { 0 };
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(p, param, 10);
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(q, param, 10);
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(phi_n, param, 10);
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(n, param, 10);
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(e, param, 10);
	fgets(param, MAX_LINE_LENGTH, fparam); mpz_set_str(d, param, 10);
	printf("===============================================================\n");
	//gmp_printf("RSA system has been read from parameters.txt:\np=%Zd\nq=%Zd\nphi_n=%Zd\nn=%Zd\ne=%Zd\nd=%Zd\n", p, q, phi_n, n, e, d);
	printf("Running Part III: Read and Decrypt\n");
	gmp_printf("RSA system has been read from parameters.txt for decryption.\n");
	//gmp_printf("RSA system has been read from parameters.txt:\np=%Zd\nq=%Zd\nphi_n=%Zd\nn=%Zd\ne=%Zd\nd=%Zd\n", p, q, phi_n, n, e, d);
	printf("===============================================================\n");
	fclose(fparam);

	mpz_t x, y; mpz_inits(x, y, 0);

	// Read the ciphertext message from cipher.txt
	FILE* fcipher;
	fcipher = fopen("cipher.txt", "rb");//reading binary
	//check if file is valid
	if (fcipher == NULL) {
		printf("cipher.txt could not be opened!!\n");
		exit(1);
	}

	char ciphertext[MAX_MSG_LENGTH] = { 0 };
	
	fseek(fcipher, 0, SEEK_END);
	unsigned long len = ftell(fcipher);
	rewind(fcipher);
	
	fread(ciphertext, 1, len, fcipher);
	fclose(fcipher);
	
	//gmp_printf("The ciphertext of length %d is \n%s \n\n", len, ciphertext);

	Encode(y, n, ciphertext, len);

	//print_text(ciphertext, len); printf("\n");

	

	//gmp_printf("---The ciphertext in integers is y = % Zd\nThe ciphertext of length %d is %s \n\n", y, len, ciphertext);
	//gmp_printf("---\nThe ciphertext in integers is \ny = % Zd\nThe ciphertext of length %d is \n%s \n---\n", y, len, ciphertext);
	
	char message[MAX_MSG_LENGTH] = { 0 };
	
	DecryptRSA(x, y, d, n);

	
	unsigned long msglen;
	Decode(message, x, msglen);
	//gmp_printf("The message of length %d is  %s \nThe message in integers is \nx=%Zd\n", msglen, message, x);

	//Output the result to message.txt
	FILE* fmessage;
	fmessage = fopen("message.txt", "w");
	//check if file is valid
	if (fmessage == NULL) {
		printf("message.txt could not be opened!!\n");
		exit(1);
	}
	write_to_file(message, fmessage, msglen);
	fclose(fmessage);

	printf("Writing message.txt complete.\n");
	printf("===============================================================\n");
}