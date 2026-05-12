import os

file_path = r'c:\Users\Test\OneDrive\Desktop\security-dash\models.py'

with open(file_path, 'rb') as f:
    content = f.read()

# Try to find the last known good part by searching for "ProjectEndpoint" and its repr
# We'll use a broader search
target_marker = b'class ProjectEndpoint(db.Model):'
index = content.find(target_marker)

if index != -1:
    # Now find the next __repr__ after this class definition
    repr_start = content.find(b'def __repr__(self):', index)
    if repr_start != -1:
        # Find the end of that line and the following return line
        next_line_end = content.find(b'\n', repr_start)
        if next_line_end != -1:
            return_line_end = content.find(b'\n', next_line_end + 1)
            if return_line_end != -1:
                # We want everything up to return_line_end
                new_content = content[:return_line_end].strip()
                
                # Add the new models
                new_models = b'''


# --- SOAR & Automation ---

class Playbook(db.Model):
    """Automated response workflows."""
    __tablename__ = "playbooks"

    id          = db.Column(db.Integer, primary_key=True)
    name        = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    actions     = db.Column(db.Text)  # JSON string
    is_active   = db.Column(db.Boolean, default=True)
    created_at  = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<Playbook {self.name}>"


class NotificationRoute(db.Model):
    """Orchestrates where alerts are sent based on server tags (Site/Role)."""
    __tablename__ = "notification_routes"

    id              = db.Column(db.Integer, primary_key=True)
    match_type      = db.Column(db.String(32), nullable=False) # site | role | default
    match_value     = db.Column(db.String(128), nullable=True) # e.g. "Cloud", "standby"
    recipient_email = db.Column(db.String(255), nullable=False)
    is_active       = db.Column(db.Boolean, default=True)

    def __repr__(self):
        return f"<NotificationRoute {self.match_type}:{self.match_value} -> {self.recipient_email}>"
'''
                new_content += new_models
                
                with open(file_path, 'wb') as f:
                    f.write(new_content)
                print("Successfully fixed models.py")
            else:
                print("Could not find end of return line")
        else:
            print("Could not find end of repr line")
    else:
        print("Could not find __repr__ for ProjectEndpoint")
else:
    print("Could not find ProjectEndpoint class")
