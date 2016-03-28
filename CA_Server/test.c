#include <stdio.h>
#include <time.h>
#include "mysql.h"
#include "string.h"
#include "CAServer.c"


#define ERR_DB_CONNECTION   0xDA
#define ERR_DB_QUERY        0xDB

#define DB_WRITE_CERTSN		0xD0
#define DB_WRITE_

#define CERT_ISSUER_NAME 	"JoonYoung"

#define DB_HOST 		"127.0.0.1"
#define DB_USER 		"root"
#define DB_PASS 		"ebdqhdks"
#define DB_NAME 		"test"
#define DB_TABLE_NAME 	"cert_list"

MYSQL       *connection=NULL, conn;
MYSQL_RES   *sql_result;
MYSQL_ROW   sql_row;
int query_stat;

int get_time_data(int year_offset, char * timedata);
int DB_Generate_CertSN(CERT_INFO * cert);
int DB_Connect();

int main() {

	if(!DB_Connect())
		return 0;

}

int DB_Connect() {
	mysql_init(&conn);

	connection = mysql_real_connect(&conn, DB_HOST, DB_USER, DB_PASS, DB_NAME, 3306, (char *)NULL, 0);

	if (connection == NULL) {
        fprintf(stderr, "MySQL Conn Error : %s", mysql_error(&conn));
        return ERR_DB_CONNECTION;
    }

    sql_result = mysql_store_result(connection);
    mysql_free_result(sql_result);

    while ( (sql_row = mysql_fetch_row(sql_result)) != NULL ) {
    	mysql_free_result(sql_result);
        if(!strncmp("success", sql_row[0], 7))
        	return 1;
    	else
    		return ERR_DB_QUERY;
    }
}

// int DB_Insert(int code, CERT_INFO * cert) {
	
// }

int DB_Generate_CertSN(CERT_INFO * cert) {
	char query[255];
	char issueDate[15];
	char expDate[15];
	get_time_data(0, issueDate);
	get_time_data(0, expDate);

	sprintf(query, "INSERT INTO %s ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s')	VALUES ('%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s');",
		DB_TABLE_NAME, 
		"cert_issuer", "cert_issueDate", "cert_expDate", "cert_userID", "cert_regNum", "cert_tel", "cert_usimNum", "cert_algo", "cert_pubKey", "cert_pubKey_x", "cert_pubKey_y", "cert_sign", "cert_status",
		CERT_ISSUER_NAME, issueDate, expDate, cert->userID, cert->userCI /* registrationNum */, "010-9766-2526"/* cert->phoneNum */, "8df8fh183b1ik19f" /* cert->USIMID */, "SHA2"/* cert->usedAlgorithm */, "pubKey"/* cert-> */, "pubkeyX"/* cert->pubKey_x */, "pubkeyY"/* cert->pubKey_y */, "signsignsignsignsigsngisngisgn", "V");

	printf("%s\n", query);
	query_stat = mysql_query(connection, query);
	if (query_stat != 0) {
		fprintf(stderr, "MySQL Query Error : %s", mysql_error(&conn));
		return ERR_DB_QUERY;
	}
}

int get_time_data(int year_offset, char * timedata) {
	time_t curr_time;
	struct tm *t;

	curr_time = time(NULL);
	t = localtime(&curr_time);
	snprintf(timedata, 5, "%d", t->tm_year + 1900 + year_offset);
	snprintf(timedata, 7, "%s%.2d", timedata, t->tm_mon + 1);
	snprintf(timedata, 9, "%s%.2d", timedata, t->tm_mday);
	snprintf(timedata, 11, "%s%.2d", timedata, t->tm_hour);
	snprintf(timedata, 13, "%s%.2d", timedata, t->tm_min);
	snprintf(timedata, 15, "%s%.2d", timedata, t->tm_sec);

	printf("%s\n", timedata);
	return 1;
}




