#!/usr/bin/env python

###################################################################################################
#
# Copyright (c) 2015, Armin Buescher (armin.buescher@googlemail.com)
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
###################################################################################################
#
# File:             iocp.py
# Description:      IOC Parser is a tool to extract indicators of compromise from security reports
#                   in PDF format.
# Usage:            iocp.py [-h] [-p INI] [-f FORMAT] PDF
# Author:           Armin Buescher (@armbues)
# Contributors:     Angelo Dell'Aera (@angelodellaera)
# Thanks to:        Jose Ramon Palanco
#                   Koen Van Impe (@cudeso)
#
###################################################################################################

import os
import sys
import fnmatch
import argparse
import re
from io import BytesIO,StringIO
from patterns import patterns
try:
    import configparser as ConfigParser
except ImportError:
    import ConfigParser

# Import optional third-party libraries
IMPORTS = []
try:
    from PyPDF2 import PdfFileReader
    IMPORTS.append('pypdf2')
except ImportError:
    pass
try:
    from pdfminer.pdfparser import PDFDocument,PDFParser
    from pdfminer.pdfinterp import PDFResourceManager,process_pdf
    from pdfminer.converter import TextConverter
    from pdfminer.pdfinterp import PDFPageInterpreter
    from pdfminer.layout import LAParams
    IMPORTS.append('pdfminer')
except ImportError:
    pass
try:
    from bs4 import BeautifulSoup
    IMPORTS.append('beautifulsoup')
except ImportError:
    pass
try:
    import requests
    IMPORTS.append('requests')
except ImportError:
    pass

# Import additional project source files
import output
from whitelist import WhiteList

class IOC_Parser(object):
    patterns = {}
    defang = {}

    def __init__(self, output_handle,patterns_ini=None, input_format='pdf', dedup=False, library='pdfminer', output_format='csv', output_handler=None):
        basedir = os.path.dirname(os.path.abspath(__file__))

        self.load_patterns()
        self.whitelist = WhiteList(basedir)
        self.dedup = dedup
        if output_handler:
            self.handler = output_handler
        else:
            self.handler = output.getHandler(output_format, output_handle)

        self.ext_filter = "*." + input_format
        parser_format = "parse_" + input_format
        try:
            self.parser_func = getattr(self, parser_format)
        except AttributeError:
            e = 'Selected parser format is not supported: %s' % (input_format)
            raise NotImplementedError(e)

        self.library = library
        if input_format == 'pdf':
            if library not in IMPORTS:
                e = 'Selected PDF parser library not found: %s' % (library)
                raise ImportError(e)
        elif input_format == 'html':
            if 'beautifulsoup' not in IMPORTS:
                e = 'HTML parser library not found: BeautifulSoup'
                raise ImportError(e)

    def load_patterns(self):
        self.patterns = patterns

    def is_whitelisted(self, ind_match, ind_type):
        try:
            for w in self.whitelist[ind_type]:
                if w.findall(ind_match):
                    return True
        except KeyError as e:
            pass
        return False

    def parse_page(self, fpath, data, page_num):
        for entry in self.patterns:
            white_list = False
            matches = entry['regex'].findall(data)

            for ind_match in matches:
                if isinstance(ind_match, tuple):
                    ind_match = ind_match[0]

                if self.is_whitelisted(ind_match, entry['type']):
                    white_list = True

                if 'defang' in entry and entry['defang']:
                    ind_match = re.sub(b'\[\.\]', b'.', ind_match)

                if self.dedup:
                    if (entry['type'], ind_match) in self.dedup_store:
                        continue

                    self.dedup_store.add((entry['type'], ind_match))

                self.handler.print_match(fpath, page_num, entry['type'], ind_match,white_list= white_list)

    def parse_pdf_pypdf2(self, f, fpath):
        try:
            pdf = PdfFileReader(f, strict=False)

            if self.dedup:
                self.dedup_store = set()

            self.handler.print_header(fpath)
            page_num = 0
            for page in pdf.pages:
                page_num += 1

                data = page.extractText()

                self.parse_page(fpath, bytes(data,'utf-8'), page_num)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse_pdf_pdfminer(self, f, fpath):
        try:
            laparams = LAParams()
            laparams.all_texts = True  
            rsrcmgr = PDFResourceManager()
            pagenos = set()

            if self.dedup:
                self.dedup_store = set()

            self.handler.print_header(fpath)
            page_num = 0
            parser= PDFParser(f)
            doc = PDFDocument(caching=True)

            parser.set_document(doc)
            doc.set_parser(parser)
            for page in doc.get_pages():
                retstr = StringIO()
                device = TextConverter(rsrcmgr, retstr, laparams=laparams)
                interpreter = PDFPageInterpreter(rsrcmgr, device)
                page_num += 1
                interpreter.process_page(page)
                data = retstr.getvalue()
                self.parse_page(fpath, bytes(data,'UTF-8'), page_num)
                retstr.close()
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse_pdf(self, f, fpath):
        parser_format = "parse_pdf_" + self.library
        try:
            self.parser_func = getattr(self, parser_format)
        except AttributeError:
            e = 'Selected PDF parser library is not supported: %s' % (self.library)
            raise NotImplementedError(e)
            
        self.parser_func(f, fpath)

    def parse_txt(self, f, fpath):
        try:
            if self.dedup:
                self.dedup_store = set()

            data = f.read()
            self.handler.print_header(fpath)
            self.parse_page(fpath, data, 1)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse_html(self, f, fpath):
        try:
            if self.dedup:
                self.dedup_store = set()
                
            data = f.read()
            soup = BeautifulSoup(data)
            html = soup.findAll(text=True)

            text = b''
            for elem in html:
                if elem.parent.name in ['style', 'script', '[document]', 'head', 'title']:
                    continue
                elif re.match(b'<!--.*-->', bytes(elem, 'utf-8')):
                    continue
                else:
                    text += bytes(elem, 'utf-8') + b'\n'

            self.handler.print_header(fpath)
            self.parse_page(fpath, text, 1)
            self.handler.print_footer(fpath)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(fpath, e)

    def parse(self, path):
        try:
            if path == sys.stdin:
                data = ''
                lines = sys.stdin.readlines()
                path = lines[0]
                data = ''.join(l for l in lines[1:])
                self.parser_func(BytesIO(bytes(data, 'UTF-8')),path)
                return
            elif path.startswith('http://') or path.startswith('https://'):
                if 'requests' not in IMPORTS:
                    e = 'HTTP library not found: requests'
                    raise ImportError(e)
                headers = { 'User-Agent': 'Mozilla/5.0 Gecko Firefox' }
                r = requests.get(path, headers=headers)
                r.raise_for_status()
                f = BytesIO(r.content)
                self.parser_func(f, path)
                return
            elif os.path.isfile(path):
                with open(path, 'rb') as f:
                    self.parser_func(f, path)
                return
            elif os.path.isdir(path):
                for walk_root, walk_dirs, walk_files in os.walk(path):
                    for walk_file in fnmatch.filter(walk_files, self.ext_filter):
                        fpath = os.path.join(walk_root, walk_file)
                        with open(fpath, 'rb') as f:
                            self.parser_func(f, fpath)
                return

            e = 'File path is not a file, directory or URL: %s' % (path)
            raise IOError(e)
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception as e:
            self.handler.print_error(path, e)

if __name__ == "__main__":
    argparser = argparse.ArgumentParser()
    argparser.add_argument('-path', default=sys.stdin,help='File/directory/URL to report(s)', dest='path')
    argparser.add_argument('-p', dest='INI', default=None, help='Pattern file')
    argparser.add_argument('-i', dest='INPUT_FORMAT', default='pdf', help='Input format (pdf/txt/html)')
    argparser.add_argument('-o', dest='OUTPUT_FORMAT', default='csv', help='Output format (csv/json/yara/netflow)')
    argparser.add_argument('-O', dest='OUTPUT_HANDLE',default=sys.stdout,help='Specify a path file to export results')
    argparser.add_argument('-d', dest='DEDUP', action='store_true', default=False, help='Deduplicate matches')
    argparser.add_argument('-l', dest='LIB', default='pdfminer', help='PDF parsing library (pypdf2/pdfminer)')
    args = argparser.parse_args()

    parser = IOC_Parser(args.OUTPUT_HANDLE, args.INI, args.INPUT_FORMAT, args.DEDUP, args.LIB, args.OUTPUT_FORMAT)
    parser.parse(args.path)
