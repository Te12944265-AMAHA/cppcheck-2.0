"""
Parse cppcheck output XML files into CSV file
"""


import csv
import requests
import xml.etree.ElementTree as ET

fields = [
    "id",
    "severity",
    "msg",
    "verbose",
    "cwe",
    "file",
    "line",
    "column",
    "symbol",
    "info",
]

subfields = [
    "file",
    "line",
    "column",
    "info",
]


def read_file(fname):
    with open(fname, "r") as f:
        return f.read()


def write_file(fname, string):
    with open(fname, "w") as f:
        return f.write(string)


def parseXML(xmlfile):
    # create element tree object
    tree = ET.parse(xmlfile)
    # get root element
    root = tree.getroot()
    # create empty list for news items
    errors = []
    # iterate news items
    print("Number of violations:", len(root.findall("./errors/error")))
    for error in root.findall("./errors/error"):
        err = {attrib: "" for attrib in fields}
        error_info = error.attrib
        for attrib in fields:
            res = error_info.get(attrib, None)
            if res != None:
                err[attrib] = res
        # iterate child elements of item
        locs = []
        symbol = None
        for child in error:
            if child.tag == "location":
                loc_info = {attrib: "" for attrib in subfields}
                for attrib in subfields:
                    res = child.attrib.get(attrib, None)
                    if res != None:
                        loc_info[attrib] = res
                locs.append(loc_info)
            elif child.tag == "symbol":
                symbol = child.text
        for loc_info in locs:
            for attrib in subfields:
                err[attrib] = loc_info[attrib]
            if symbol != None:
                err["symbol"] = symbol

            errors.append(err)
    # return news items list
    return errors


def savetoCSV(errors, filename, parse_fields):
    # writing to csv file
    with open(filename, "w") as csvfile:
        # creating a csv dict writer object
        writer = csv.DictWriter(csvfile, fieldnames=parse_fields)
        # writing headers (field names)
        writer.writeheader()
        # writing data rows
        writer.writerows(errors)


def parseRules(filename):
    rules = read_file(filename).split("Rule ")[1:]
    res = {}
    for rule in rules:
        rule_infos = rule.split("\n")
        rule_id_req = rule_infos[0].split(" ")
        rule_dict = {}
        rule_dict["id"] = rule_id_req[0]
        rule_dict["category"] = rule_id_req[1]
        rule_dict["text"] = " ".join(
            list(
                filter(
                    lambda info: not info.isspace() and info != "",
                    rule_infos[1:],
                )
            )
        )
        res[rule_id_req[0]] = rule_dict
    return res


def main():
    xml_file = "out1.xml"
    # parse xml file
    errors = parseXML(xml_file)
    # store error items in a csv file
    savetoCSV(errors, "errors.csv", fields)
    rules = parseRules("../addons/misra_rules.txt")
    rule_ids = rules.keys()
    rule_violation_cnt = {rule_id: 0 for rule_id in rule_ids}
    categories = ["Required", "Mandatory", "Advisory"]
    rule_violation_per_category = {cat: set() for cat in categories}
    substring = "misra-c2012-"
    for error in errors:
        if error["id"].startswith(substring):
            rule_id = error["id"][len(substring) :]
            rule_violation_cnt[rule_id] += 1
            cat = rules[rule_id]["category"]
            rule_violation_per_category[cat].add(rule_id)
    compliance_report = []
    report_attribs = ["Guideline", "Category", "Violations"]
    for rule_id, cnt in rule_violation_cnt.items():
        record = {attrib: "" for attrib in report_attribs}
        record["Guideline"] = "Rule " + rule_id
        record["Category"] = rules[rule_id]["category"]
        record["Violations"] = str(cnt)
        compliance_report.append(record)
    savetoCSV(compliance_report, "compliance_report.csv", report_attribs)
    print(rule_violation_per_category)
    print("total #rules:", len(rule_violation_cnt.keys()))

    import jinja2
    import pdfkit
    from datetime import datetime

    vio_mand = len(rule_violation_per_category["Mandatory"])
    vio_req = len(rule_violation_per_category["Required"])
    vio_adv = len(rule_violation_per_category["Advisory"])
    compliance_str = "Compliant" if vio_mand + vio_req == 0 else "Noncompliant"
    mandatory_str = f"{vio_mand} mandatory guideline"
    if vio_mand > 1:
        mandatory_str += "s"
    required_str = f"{vio_req} required guideline"
    if vio_req > 1:
        required_str += "s"
    advisory_str = f"{vio_adv} advisory guideline"
    if vio_adv > 1:
        advisory_str += "s"

    today_date = datetime.today().strftime("%b %d, %Y")

    context = {
        "compliance_str": compliance_str,
        "mandatory_str": mandatory_str,
        "required_str": required_str,
        "advisory_str": advisory_str,
        "today_date": today_date,
    }

    html_template = read_file("table_template.html")
    pos_table_body_start = html_template.find("<tbody>")
    lines = html_template[pos_table_body_start:].splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        has_rule = line.find("Rule")
        if has_rule >= 0:
            rule_end = line.find("</")
            rule_id = line[has_rule + 5 : rule_end]
            cnt = rule_violation_cnt[rule_id]
            cnt_pos = lines[i + 2].find(">")
            lines[i + 2] = (
                lines[i + 2][: cnt_pos + 1]
                + str(cnt)
                + lines[i + 2][cnt_pos + 2 :]
            )
            i += 3
        else:
            i += 1

    path_to_file = "new_html.html"
    new_html = html_template[:pos_table_body_start] + "\n".join(lines)
    write_file(path_to_file, new_html)

    template_loader = jinja2.FileSystemLoader("./")
    template_env = jinja2.Environment(loader=template_loader)
    template = template_env.get_template(path_to_file)
    output_text = template.render(context)
    # Define path to wkhtmltopdf.exe
    path_to_wkhtmltopdf = "/usr/bin/wkhtmltopdf"

    # Define path to HTML file

    # Point pdfkit configuration to wkhtmltopdf.exe
    config = pdfkit.configuration(wkhtmltopdf=path_to_wkhtmltopdf)

    # Convert HTML file to PDF
    pdfkit.from_string(
        output_text, "sample.pdf", configuration=config, css="style.css"
    )


if __name__ == "__main__":

    # calling main function
    main()
