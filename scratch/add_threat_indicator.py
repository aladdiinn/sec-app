import os

file_path = r'c:\Users\Test\OneDrive\Desktop\security-dash\models.py'

with open(file_path, 'rb') as f:
    content = f.read()

# Insert ThreatIndicator before Playbook
target_marker = b'class Playbook(db.Model):'
index = content.find(target_marker)

if index != -1:
    # Go back a bit to insert it before the comment/heading
    # Looking for "# --- SOAR & Automation ---"
    header_marker = b'# --- SOAR & Automation ---'
    header_index = content.find(header_marker)
    
    if header_index != -1:
        new_content = content[:header_index]
        
        threat_intel = b'''
# --- Threat Intelligence ---

class ThreatIndicator(db.Model):
    """Known malicious IPs, domains, or hashes."""
    __tablename__ = "threat_indicators"

    id             = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(32), default="ip")  # ip | domain | hash
    value          = db.Column(db.String(255), nullable=False, index=True)
    source         = db.Column(db.String(255), default="manual")
    severity       = db.Column(db.String(16), default="medium")
    created_at     = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<ThreatIndicator {self.indicator_type}:{self.value}>"

'''
        new_content += threat_intel
        new_content += content[header_index:]
        
        with open(file_path, 'wb') as f:
            f.write(new_content)
        print("Successfully added ThreatIndicator to models.py")
    else:
        # Fallback if header not found
        new_content = content[:index]
        threat_intel = b'''
class ThreatIndicator(db.Model):
    """Known malicious IPs, domains, or hashes."""
    __tablename__ = "threat_indicators"

    id             = db.Column(db.Integer, primary_key=True)
    indicator_type = db.Column(db.String(32), default="ip")  # ip | domain | hash
    value          = db.Column(db.String(255), nullable=False, index=True)
    source         = db.Column(db.String(255), default="manual")
    severity       = db.Column(db.String(16), default="medium")
    created_at     = db.Column(db.DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))

    def __repr__(self):
        return f"<ThreatIndicator {self.indicator_type}:{self.value}>"

'''
        new_content += threat_intel
        new_content += content[index:]
        
        with open(file_path, 'wb') as f:
            f.write(new_content)
        print("Successfully added ThreatIndicator to models.py (no header found)")
else:
    print("Could not find Playbook class")
