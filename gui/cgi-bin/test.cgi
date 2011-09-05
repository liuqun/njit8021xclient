#!/bin/sh

szTitle="CGI环境变量测试"
szText=`env|sort`

echo "Content-type: text/html;charset=UTF-8"
echo ""
echo "<html>"
echo   "<head>"
echo     "<title>$szTitle</title>"
echo   "</head>"
echo   "<body>"
echo     "<H1>$szTitle</H1>"
echo     "<pre>$szText</pre>"
echo   "</body>"
echo "</html>"

