import os, csv, json, io 

def detect_format(filename, content):
    ext = os.path.splitext(filename)[1].lower()

    if ext == '.json':
        return 'json'
    elif ext == '.csv':
        return 'csv'
    elif ext in ('.txt', '.log'):
        return 'text'
    else:
        if content.strip().startswith('{') or content.strip().startswith('['):
            return 'json'
        elif ',' in content.split('\n')[0]:
            return 'csv'
        else:
            return 'text'

def parse_file(file_bytes, filename):
    content = file_bytes.decode('utf-8')
    file_format = detect_format(filename, content)

    if file_format == 'csv':
        reader = csv.DictReader(io.StringIO(content))
        return [row for row in reader]

    elif file_format == 'json':
        try:
            parsed = json.loads(content)
            if isinstance(parsed, list):
                return parsed
            else:
                return [parsed]
        except json.JSONDecodeError:
            entries = []
            for line in content.strip().split('\n'):
                if line.strip():
                    entries.append(json.loads(line))
            return entries

    else: 
        return [
            {"raw_line": line.strip()}
            for line in content.split('\n')
            if line.strip()
        ]