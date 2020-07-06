# Audit for GitLab

This is a small script to add a `npm audit` GitLab dependency scanner.  
It generates a JSON audit via npm and converts it to the format that gitlab expects as dep scan report.  

In case a vulnerability equal or higher to `moderate` is found, it will exit with exit code 1, i.e., fail.  
While generating the report, it will also output number of vulnerabilities found (and types) in stdout.
