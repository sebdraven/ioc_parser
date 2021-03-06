import os
import sys
import csv
import json

OUTPUT_FORMATS = ('csv', 'json', 'yara', 'netflow',)


def getHandler(output_format, output_handle):
    output_format = output_format.lower()
    if output_format not in OUTPUT_FORMATS:
        print("[WARNING] Invalid output format specified.. using CSV")
        output_format = 'csv'

    handler_format = "OutputHandler_" + output_format
    handler_class = getattr(sys.modules[__name__], handler_format)

    return handler_class(output_handle)


class OutputHandler(object):
    def __init__(self, output_handle):
        if output_handle == sys.stdout:
            self.output = sys.stdout
        else:
            self.output = open(output_handle, 'w')

    def print_match(self, fpath, page, name, match):
        pass

    def print_header(self, fpath):
        pass

    def print_footer(self, fpath):
        pass

    def print_error(self, fpath, exception):
        print("[ERROR] %s" % (exception))


class OutputHandler_csv(OutputHandler):
    def __init__(self, output_handle):
        self.csv_writer = csv.writer(sys.stdout, delimiter='\t')

    def print_match(self, fpath, page, name, match,white_list=False):
        if type(match) == bytes:
            match = match.decode()
        self.csv_writer.writerow((fpath, page, name, match, white_list))

    def print_error(self, fpath, exception):
        self.csv_writer.writerow((fpath, '0', 'error', exception))


class OutputHandler_json(OutputHandler):
    def print_match(self, fpath, page, name, match, white_list=False):
        data = {
            'path': fpath.rstrip('\r\n'),
            'file': os.path.basename(fpath).rstrip('\r\n'),
            'page': page,
            'type': name,
            'match': match.decode('utf-8'),
            'white_list': white_list
        }

        self.output.write(json.dumps(data) + '\n')

    def print_error(self, fpath, exception):
        data = {
            'path': fpath,
            'file': os.path.basename(fpath),
            'type': 'error',
            'exception': exception
        }
        print(data)
        self.output.write(json.dumps(data))


class OutputHandler_yara(OutputHandler):

    def __init__(self):
        self.rule_enc = ''.join(
            chr(c) if chr(c).isupper() or chr(c).islower() or chr(c).isdigit() else '_' for c in range(256))

    def print_match(self, fpath, page, name, match, white_list=False):
        if name in self.cnt:
            self.cnt[name] += 1
        else:
            self.cnt[name] = 1

        string_id = "$%s%d" % (name, self.cnt[name])
        self.sids.append(string_id)
        string_value = match.replace('\\', '\\\\')
        print("\t\t%s = \"%s\"" % (string_id, string_value))

    def print_header(self, fpath):
        rule_name = os.path.splitext(os.path.basename(fpath))[0].translate(self.rule_enc)

        print("rule %s" % (rule_name))
        print("{")
        print("\tstrings:")

        self.cnt = {}
        self.sids = []

    def print_footer(self, fpath):
        cond = ' or '.join(self.sids)

        print("\tcondition:")
        print("\t\t" + cond)
        print("}")


class OutputHandler_netflow(OutputHandler):
    def __init__(self):
        print("host 255.255.255.255")

    def print_match(self, fpath, page, name, match, white_list=False):
        if not white_list:
            data = {
                'type': name,
                'match': match
            }
            if data["type"] == "IP":
                print(" or host %s " % data["match"])
