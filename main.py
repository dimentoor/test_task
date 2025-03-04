import xml.etree.ElementTree as ET
import json
import os

import url


def parse_oval(file_path):
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"File not found: {file_path}")

    tree = ET.parse(file_path)
    root = tree.getroot()

    ns = {
        'oval': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
        'linux': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux'
    }

    # <definitions>
    vulnerabilities = []
    for definition in root.findall('.//oval:definition', ns):
        vuln_id = definition.get('id', 'unknown')
        title = definition.find('oval:metadata/oval:title', ns)
        severity = definition.find('oval:metadata/oval:advisory/oval:severity', ns)
        description = definition.find('oval:metadata/oval:description', ns)

        references = []
        for ref in definition.findall('oval:metadata/oval:reference', ns):
            references.append({
                "id": ref.get('ref_id', 'unknown'),
                "url": ref.get('ref_url', ''),
                "source": ref.get('source', '')
            })

        criteria = []
        for criterion in definition.findall('.//oval:criteria//oval:criterion', ns):
            criteria.append({
                "comment": criterion.get('comment', ''),
                "test_ref": criterion.get('test_ref', '')
            })

        vulnerabilities.append({
            "id": vuln_id,
            "title": title.text if title is not None else "",
            "severity": severity.text if severity is not None else "",
            "description": description.text if description is not None else "",
            "references": references,
            "criteria": criteria
        })

    # <tests>
    tests = []
    for test in root.findall('.//oval:tests/linux:rpminfo_test', ns):
        tests.append({
            "id": test.get('id', 'unknown'),
            "comment": test.get('comment', '')
        })

    # <objects>
    objects = []
    for obj in root.findall('.//oval:objects/linux:rpminfo_object', ns):
        name = ""
        name_elem = obj.find('linux:name', ns)
        if name_elem is not None and name_elem.text:
            name = name_elem.text.strip()

        objects.append({
            "id": obj.get('id', 'unknown'),
            "type": obj.tag.split('}')[-1],
            "name": name
        })

    # <states>
    states = []
    for state in root.findall('.//oval:states/linux:rpminfo_state', ns):
        operation = ""
        for child in state:
            if "operation" in child.attrib:
                operation = f"{child.attrib['operation']} {child.text.strip() if child.text else ''}"
                break
        states.append({
            "id": state.get('id', 'unknown'),
            "type": state.tag.split('}')[-1],
            "operation": operation.strip()
        })

    result = {
        "vulnerabilities": vulnerabilities,
        "tests": tests,
        "objects": objects,
        "states": states
    }

    return result


file_path = url.file_path
if os.path.exists(file_path):
    parsed_data = parse_oval(file_path)

    # output JSON
    output_file = "parsed_oval.json"
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(parsed_data, f, indent=4, ensure_ascii=False)

    print(f"Данные сохранены в {output_file}")
else:
    print(f"Файл {file_path} не найден.")


# check-----
# tree = ET.parse(file_path)
# root = tree.getroot()
# print(f"Root tag: {root.tag}")

# for elem in root.iter():
#     print(elem.tag)

# for elem in root.iter():
#     if "}" in elem.tag:
#         ns_uri = elem.tag.split("}")[0][1:]
#         tag_name = elem.tag.split("}")[1]
#         print(f"Тег: {tag_name}, Пространство имен: {ns_uri}")


# tests_root = root.find('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5}tests')
# print(tests_root)
# tests = []
# for test in tests_root.findall('.//{http://oval.mitre.org/XMLSchema/oval-definitions-5#linux}rpminfo_test'):
#     tests.append({
#         "id": test.get('id', 'unknown'),
#         "comment": test.get('comment', '')
#     })
#
# print(tests)
