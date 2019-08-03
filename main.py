#!/usr/bin python3
import json
import shlex

SIGN_FILE = 'sign.json'
LOG_FILE = '2019-02-17-gbc.log'
SIGNATURES = 'signatures'
SIGN_ID = 'id'
TITLE = 'title'
DESC = 'description'
DETECTION = 'detection'
SELECTION = 'selection'
PROTOCOL = 'protocol'
DEST_PORT = 'destination_port'
DEST_IP = 'destination_ip'
CONTENT = 'content'


def get_sign_by_id(json_list, sign_id):
    for v in json_list:
        if sign_id in v[SIGN_ID]:
            return v
    return None


sign_list = list()

print("Importing Signatures...")
with open(SIGN_FILE, 'r') as json_file:
    json = json.load(json_file)
    for sign in json[SIGNATURES]:
        sign_list.append(sign)
print("Importing Done.")

print("Analyzing log files...")
alert = dict()
with open(LOG_FILE, 'rb') as log_file:
    line = str(log_file.readline().strip())[2:-1]

    # Read the number of lines in log file
    limit = 150000
    cnt = 1
    while line:
        # Pre-process each line of log
        new_array = list()
        try:
            array_line = shlex.split(line)
            index = line.find(array_line[8])
            array_line[8] = line[index:]
            new_array = array_line[:9]
        except ValueError:
            # print('Error at line: ' + line)
            continue
        # Check condition in signature vs each line of log
        for value in sign_list:
            result = True
            selection_value = value[DETECTION][SELECTION]
            if PROTOCOL in selection_value:
                result &= selection_value[PROTOCOL] in new_array[7]
            if DEST_PORT in selection_value:
                result &= selection_value[DEST_PORT] in new_array[5]
            if DEST_IP in selection_value:
                result &= selection_value[DEST_IP] in new_array[4]
            if CONTENT in selection_value:
                result &= selection_value[CONTENT] in new_array[8]
            if result:
                if value[SIGN_ID] not in alert:
                    alert[value[SIGN_ID]] = list()
                alert[value[SIGN_ID]].append(new_array)

        # Read the next lone
        line = str(log_file.readline().strip())[2:-1]
        cnt += 1
        if cnt % 10000 == 0:
            print('Running at line {}...'.format(cnt))
        if cnt > limit:
            break

print("Analysis Done.")
print()
print("-----------------Report-------------------")
if len(alert) == 0:
    print("No detection")
else:
    print('These logs match signatures:')
    for k, values in alert.items():
        sign = get_sign_by_id(sign_list, k)
        print('Title: ' + sign[TITLE])
        print('Description: ' + sign[DESC])
        for value in values:
            print('Time: {}. Destination Ip: {}. Destination Port: {}. Protocol: {}. Content: {}'
                  .format(value[0], value[4], value[5], value[7], value[8]))
        print('----------------------------------------')
        print()
