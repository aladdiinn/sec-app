with open('app.py', 'r', encoding='utf-8') as f:
    lines = f.readlines()
    start = -1
    end = -1
    for i, l in enumerate(lines):
        if 'cat << PY_EOF > /opt/securepulse/node_push_agent.py' in l:
            start = i
        if start != -1 and 'PY_EOF' in l and i > start:
            end = i
            break
            
    for i in range(start, end):
        line = lines[i]
        # remove {{ and }}
        line = line.replace('{{', '').replace('}}', '')
        # look for remaining { or }
        if '{' in line or '}' in line:
            # ignore known bash variables if any leaked
            if '{base_url}' not in line and '{target_ip}' not in line and '{target_node_name}' not in line:
                print(f"Line {i+1}: {lines[i].strip()}")
