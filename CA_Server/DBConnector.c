#include <stdio.h>
#include <time.h>
#include "mysql.h"
#include "string.h"
#include "DBConnector.h"

MYSQL * DB_Connect(UCHAR * dbhost, UCHAR * dbuser, UCHAR * dbpassword, UCHAR * dbname, UINT dbport) {
    MYSQL * connection = mysql_init(NULL);
    
    if (!mysql_real_connect(connection, dbhost, dbuser, dbpassword, dbname, dbport, (char *)NULL, 0)) {
        fprintf(stderr, "MySQL Conn Error : %s", mysql_error(connection));
    }
    return connection;
}

MYSQL_RES * DB_Perform_Query(MYSQL * connection, SCHAR * sql_query, ULONG query_len) {
    if (mysql_query(connection, sql_query)) {
        fprintf(stderr, "MySQL Query Error ; %s", mysql_error(connection));
    }
    return mysql_store_result(connection);
}

void get_time_data(SINT year_offset, SCHAR * timedata) {
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
    
    //    printf("%s\n", timedata);
}

//int hash_csr(char * csr) {
//    SHA256_hash(csr, strlen(csr), csr);
//    return 1;
//}

//CREATE TABLE `test`.`cert_list` (
//`cert_sn` BINARY(16) NOT NULL,
//`cert_ver` INT NOT NULL,
//`cert_issuer` VARCHAR(45) NOT NULL,
//`cert_issuedate` DATETIME NOT NULL,
//`cert_expdate` DATETIME NOT NULL,
//`cert_username` VARCHAR(45) NOT NULL,
//`cert_regnum` CHAR(6) NOT NULL,
//`cert_phonenum` VARCHAR(45) NOT NULL,
//`cert_usimid` VARCHAR(100) NOT NULL,
//`cert_userid` VARCHAR(45) NOT NULL,
//`cert_algo` VARCHAR(45) NOT NULL,
//`cert_pubkeyx` BINARY(32) NOT NULL,
//`cert_pubkeyy` BINARY(32) NOT NULL,
//`cert_sign` BINARY(64) NOT NULL,
//`cert_status` CHAR(1) NOT NULL DEFAULT 'V',
//`cert_comment` VARCHAR(500) NULL,
//PRIMARY KEY (`cert_sn`),
//UNIQUE INDEX `cert_sn_UNIQUE` (`cert_sn` ASC));
