import os
import re

files_to_update = {
    'events.html': ('Events', 'All security events logged by agents'),
    'alerts.html': ('Alerts', 'Active and resolved security alerts'),
    'logins.html': ('Users & Logins', 'Track active users and login attempts'),
    'processes.html': ('Processes', 'Monitor newly spawned processes'),
    'settings.html': ('Settings', 'Dashboard configuration and profile'),
    'audit.html': ('Audit Log', 'Administrative actions and system events'),
    'cron_jobs.html': ('Cron Jobs', 'Track cron job modifications')
}

base_dir = r'c:\Users\Test\Downloads\security-dash\templets'

for fname, (title, sub) in files_to_update.items():
    fpath = os.path.join(base_dir, fname)
    if not os.path.exists(fpath):
        continue
        
    with open(fpath, 'r', encoding='utf-8') as f:
        content = f.read()
        
    # Replace the {% block title %} block with new blocks
    content = re.sub(r'{%\s*block title\s*%}.*?{%\s*endblock\s*%}', f'{{% block page_title %}}{title}{{% endblock %}}\n{{% block page_sub %}}{sub}{{% endblock %}}', content, count=1)
    
    # Remove the .page-header
    # It usually looks like:
    # <div class="page-header">
    #     <div>
    #         <h1 class="page-title">...</h1>
    #         <p class="page-subtitle">...</p>
    #     </div>
    #   <maybe filters>
    # </div>
    
    # Actually, we can just remove:
    content = re.sub(r'<div>\s*<h1 class="page-title">.*?</h1>\s*<p class="page-subtitle">.*?</p>\s*</div>', '', content, flags=re.DOTALL)
    
    # And if the .page-header becomes completely empty, we can remove it, or just let it be (it has margin-bottom).
    # Some pages have filters in .page-header! So we ONLY remove the text div.
    
    with open(fpath, 'w', encoding='utf-8') as f:
        f.write(content)
        
print("Updated all page headers.")
