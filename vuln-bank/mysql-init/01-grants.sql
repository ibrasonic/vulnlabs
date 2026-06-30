-- Runs once on first MySQL container start (the MySQL image picks up every
-- *.sql file under /docker-entrypoint-initdb.d/ in lexical order).
--
-- The MYSQL_USER / MYSQL_PASSWORD env vars already create the `bank` user
-- with full rights on the `vulnbank` database.  We additionally grant the
-- FILE privilege so Chapter 11's out-of-band SQLi demos
-- (SELECT … INTO OUTFILE, LOAD_FILE) work end-to-end.  Real production
-- deployments should NEVER grant FILE to an application account; doing it
-- here is the deliberate misconfiguration the chapter teaches against.

GRANT FILE ON *.* TO 'bank'@'%';
FLUSH PRIVILEGES;
