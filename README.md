# ioc-parser
IOC Parser is a tool to extract indicators of compromise from security reports in PDF format. A good collection of APT related reports with many IOCs can be found here: [APTNotes](https://github.com/kbandla/APTnotes).
Now it's compatible python 3.
## Usage
**iocp.py [-h] [-p INI] [-i FORMAT] [-o FORMAT] [-d] [-l LIB] --path path**
* *FILE* File/directory path to report(s)
* *-p INI* Pattern file
* *-i FORMAT* Input format (pdf/txt/html)
* *-o FORMAT* Output format (csv/json/yara)
* *-d* Deduplicate matches
* *-l LIB* Parsing library
* *-path path* URL,path of file

you can pipe with CasperJS like that:

**casperjs ioc_casper.js <url> | iocp.py [-p INI] [-i FORMAT] [-o FORMAT] [-d] [-l LIB]**
## Requirements
One of the following PDF parsing libraries:
* [PyPDF2](https://github.com/mstamy2/PyPDF2) - *pip install pypdf2*
* [pdfminer](https://github.com/euske/pdfminer3k) - *pip install pdfminer3k*

For HTML parsing support:
* [BeautifulSoup](http://www.crummy.com/software/BeautifulSoup/) - *pip install beautifulsoup4*

For HTTP(S) support:
* [requests](http://docs.python-requests.org/en/latest/) - *pip install requests*
