#include <string>
#include <fstream>
#include <vector> 
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#define CACERT          "./cacert.pem"

bool certToPemBuf(X509 *cert, std::vector<unsigned char> &pemBuf)
{
	if(cert == NULL)
	{
		return false;
	}
	
	BIO *bio;
	bio = BIO_new(BIO_s_mem());
	if(bio == NULL)
	{
		printf("Could not create new BIO\n");
	    return false;
	}
	 
	if(!PEM_write_bio_X509(bio, cert))
	{
		printf("Could not write certificate to BIO\n");
	    BIO_free(bio);
	}
	 
	unsigned char *certData;
	unsigned int certDataSize = BIO_get_mem_data(bio, &certData);
	 
	pemBuf.assign(certData, certData + certDataSize);
	BIO_free(bio);
	 
	return true;
}

static bool storeCertificateToFile(X509 *cert, const std::string &fileName)
{
	//convert cert to PEM
	std::vector<unsigned char> pemBuf;
	if(!certToPemBuf(cert, pemBuf))
	{   
		return false;
	}

	//write buffer to file
	std::ofstream outFile(fileName.c_str());
	if(!outFile.is_open())
	{
		printf("Could not open file '%s'\n", fileName.c_str());
		return false;
	}

	outFile.write((char *)(&pemBuf[0]), pemBuf.size());
	return true;
}

static void addExtension(X509 *pX509, int nid, const std::string &value)
{
	X509_EXTENSION *ext;
	X509V3_CTX ctx;

	X509V3_set_ctx_nodb (&ctx);

	X509V3_set_ctx (&ctx, pX509, pX509, NULL, NULL, 0);
	ext = X509V3_EXT_conf_nid (NULL, &ctx, nid, const_cast<char *>(value.c_str()));
	if (ext) 
	{
		X509_add_ext(pX509, ext, -1);
		X509_EXTENSION_free(ext);
	}
	else
	{
		printf("error\n");
	}
}

static EVP_PKEY* generateKey()
{
	EVP_PKEY *key = NULL;
	
	EC_KEY *ecKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if(ecKey == NULL) 
	{
		printf("Error generate key with elliptic curve \"secp256r1/prime256v1\"\n");
		return NULL;
	}

	printf("Using elliptic curve \"secp256r1/prime256v1\" for creating new ec key!\n");

	EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
	if (group == NULL) 
	{
		printf("Error get ec group for elliptic curve \"secp256r1/prime256v1\"\n");
		EC_KEY_free(ecKey);
		return NULL;
	}

	if(EC_KEY_set_group(ecKey, group) == 0) 
	{
		printf("Setting ec group failed!\n");
		EC_GROUP_free(group);
		return NULL;
	}

	if (EC_KEY_generate_key(ecKey) != 1)
	{
		printf("Could not generate key: '%s'\n", ERR_error_string(ERR_get_error(), NULL));
		EC_KEY_free(ecKey);
		EC_GROUP_free(group);
		return NULL;
	}

	const EC_GROUP *group_ = EC_KEY_get0_group(ecKey);
	if(NULL == group_)
	{
		printf("Could not get group\n");
		EC_KEY_free(ecKey);
		EC_GROUP_free(group);
		return NULL;
	}

	printf("New key with length: %u\n", (unsigned int)EC_GROUP_get_degree(group_));

	const BIGNUM *bn = EC_KEY_get0_private_key (ecKey);
	if(NULL == bn)
	{
		printf("Could not get private key\n");
		EC_KEY_free(ecKey);
		EC_GROUP_free(group);
		return NULL;
	}
	char *pBnHexStr = BN_bn2hex(bn);

	printf("Private KEY is: %s\n", pBnHexStr);
	OPENSSL_free(pBnHexStr);

	EC_GROUP_free(group);

	EC_KEY_set_asn1_flag(ecKey, OPENSSL_EC_NAMED_CURVE);
												   
	key = EVP_PKEY_new(); // Create algorithm independent key
	if(!EVP_PKEY_assign_EC_KEY(key, ecKey)) // Store the ECC key in an algorithm independent structure
	{
		printf("Failed to assign ECC key.\n");
		EC_KEY_free(ecKey);
	    return NULL;
	}

	return key;
}


int main()
{
	FILE* fp;
	X509* caCert;
	X509* clientCert;
	EVP_PKEY* key;
	X509_NAME* name = NULL;

	if(!(fp = fopen(CACERT, "r")))
	{
		printf("Error reading CA cert file.\n");
		return 0;
	}

	if(!(caCert = PEM_read_X509(fp,NULL,NULL,NULL)))
	{
		printf("Error loading CA cert to memory.\n");
		return 0;
	}

	fclose(fp);

	//generate new key include private key and public key
	key = generateKey();
	if(key == NULL)
	{
		printf("Generate ECC key failed.\n");
		return 0;
	}

	clientCert = X509_new();
	if(clientCert == NULL)
	{
		printf("Could not create cert.\n");
		EVP_PKEY_free(key);
		return 0;
	}

	//setup the certificate
	X509_set_version(clientCert, 2);
	
	//get serial number from CA and assign to generated cert
	unsigned int serial = ASN1_INTEGER_get(X509_get_serialNumber(caCert));
	ASN1_INTEGER_set(X509_get_serialNumber(clientCert), serial);

	// Make the cert valid for the whole epoque (-2 sec)
	time_t time_var = 1;
	X509_time_adj(X509_get_notBefore(clientCert), 0, &time_var);
	time_var = 0x7ffffffe;
	X509_time_adj (X509_get_notAfter(clientCert), 0, &time_var);
	X509_set_pubkey(clientCert, key);

	name = X509_get_subject_name(clientCert);

	std::string vinStr = std::string("VIN:") + "vin";
	std::string daStr = std::string("DA:") + "da";
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) vinStr.c_str(), -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) daStr.c_str(), -1, -1, 0);
	
	X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *) "VWAG", -1, -1, 0);
	X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *) "DE", -1, -1, 0);

	X509_set_issuer_name(clientCert, name);

	addExtension(clientCert, NID_subject_key_identifier, "hash");
	addExtension(clientCert, NID_key_usage, "digitalSignature,keyEncipherment");
	addExtension(clientCert, NID_basic_constraints, "critical, CA:FALSE,pathlen:0");
	addExtension(clientCert, NID_authority_key_identifier, "keyid");
	addExtension(clientCert, NID_ext_key_usage, "clientAuth");

	//self-sign the certificate
	if(!X509_sign(clientCert, key, EVP_sha256())) 
	{
		printf("Could not sign certificate.\n");
		return 0;
	}

	if(storeCertificateToFile(clientCert, "./cl_unsigned.pem"))
	{
		printf("Store the client.pem successfully.\n");
	}
	else
	{
		printf("Store the client.pem error\n");
	
	}
}






