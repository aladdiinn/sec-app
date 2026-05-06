import os
import re

files_to_update = {
    'events.html': ('Events', 'All security events logged by agents'),
    'alerts.html': ('Alerts', 'Active and resolved security alerts'),
    'logins.html': ('Users & Logins', 'Track active users and login attempts'),
    'processes.html': ('Processes', 'Monitor newly spawned processes'),
    'settings.html': ('Settings', 'Dashboard configuration and profile'),
    'audit_log.html': ('Audit Log', 'Immutable record of all admin actions for compliance'),
    'cron_jobs.html': ('Cron Jobs', 'Track cron job modifications')
}

base_dir = r'c:\Users\Test\Downloads\security-dash\templets'

for fname, (title, sub) in files_to_update.items():
    fpath = os.path.join(base_dir, fname)
    if not os.path.exists(fpath):
        print(f"File not found: {fname}")
        continue
        
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Replace the {% block title %} block with new blocks
    # We want to replace it if it's there
    content = re.sub(r'{%\s*block title\s*%}.*?{%\s*endblock\s*%}', f'{{% block page_title %}}{title}{{% endblock %}}\n{{% block page_sub %}}{sub}{{% endblock %}}', content, count=1, flags=re.DOTALL)
    
    # Remove the .page-header DIV that contains h1/p
    # Some files use <div class="page-header"><div><h1...></div></div>
    content = re.sub(r'<div class="page-header">\s*<div>\s*<h1 class="page-title">.*?</h1>\s*<p class="page-subtitle">.*?</p>\s*</div>\s*</div>', '', content, flags=re.DOTALL)
    
    # If the above fails, try a simpler one (no nested div)
    content = re.sub(r'<div class="page-header">\s*<h1 class="page-title">.*?</h1>\s*<p class="page-subtitle">.*?</p>\s*</div>', '', content, flags=re.DOTALL)

    with open(fpath, 'w', encoding='utf-8') as f:
        f.write(content)
        
print("Updated all page headers correctly.")
