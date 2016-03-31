#include "mysql.h"
#include "EBDCrypto.h"

#define DB_HOST 		"127.0.0.1"
#define DB_PORT         3306
#define DB_USER 		"root"
#define DB_PASS 		"ebdqhdks"
#define DB_NAME 		"test"
#define DB_TABLE_NAME 	"cert_list"

MYSQL * DB_Connect(UCHAR * dbhost, UCHAR * dbuser, UCHAR * dbpassword, UCHAR * dbname, UINT dbport);
MYSQL_RES * DB_Perform_Query(MYSQL * connection, SCHAR * sql_query, ULONG query_len);
void get_time_data(SINT year_offset, SCHAR * timedata);
