import csv

def get_rules():

    filtering_rule = {"rule_id":'', 
                    "direction":'',
                    "src_addr":'',
                    "dest_addr":'',
                    "protocol":'',
                    "src_port":'',
                    "dest_port":'',
                    "action":''}

    filtering_rules = []


    with open('/media/primesh/F4D0EA80D0EA4906/PROJECTS/firewall/firewall/filtering_rules.csv') as csv_file:
        filtering_rules_file = csv.reader(csv_file, delimiter=',')
        line_count = 0
        for row in filtering_rules_file:
            if line_count == 0:
                line_count += 1
            else:
                line_count += 1

                filtering_rule["rule_id"]   = row[0]
                filtering_rule["direction"] = row[1]
                filtering_rule["src_addr"]  = row[2]
                filtering_rule["dest_addr"] = row[3]
                filtering_rule["protocol"]  = row[4]
                filtering_rule["src_port"]  = row[5]
                filtering_rule["dest_port"] = row[6]
                filtering_rule["action"]    = row[7]
                filtering_rules.append(filtering_rule.copy())

    return filtering_rules



if __name__ == "__main__":
    get_rules()