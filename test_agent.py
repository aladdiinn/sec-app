with open('app.py', 'r', encoding='utf-8') as f:
    code = f.read()
import re
m = re.search(r'cat << PY_EOF > /opt/securepulse/node_push_agent\.py(.*?)PY_EOF', code, re.DOTALL)
if m:
    agent_code = m.group(1)
    res = agent_code.format(base_url='http', target_ip='10', target_node_name='host')
    m2 = re.search(r'def get_user_mapping.*?return mapping', res, re.DOTALL)
    print(m2.group(0) if m2 else 'not found')
