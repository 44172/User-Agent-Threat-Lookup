# app.py UA lookup
from flask import Flask, render_template, request
from dotenv import load_dotenv
import requests
import os
import fnmatch

load_dotenv()

app = Flask(__name__)
SOURCES = {
    "LETHAL-FORENSICS": "https://raw.githubusercontent.com/LETHAL-FORENSICS/Microsoft-Analyzer-Suite/main/Blacklists/UserAgent-Blacklist.csv",
    "APACHE_BAD_BOTS": "https://raw.githubusercontent.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/master/Apache_2.4/custom.d/blacklist-user-agents.conf",
    "APACHE_ADDITIONAL": "https://raw.githubusercontent.com/mitchellkrogza/apache-ultimate-bad-bot-blocker/master/_generator_lists/bad-user-agents-fail2ban-additional.list",
    "Awesome_List_suspicious_UA":"https://raw.githubusercontent.com/mthcht/awesome-lists/main/Lists/suspicious_http_user_agents_list.csv",
    "iAugurs_Bad_bot_list":"https://gist.github.com/iAugur/22355bcd285f66262cc57be3de53517d.js"
}

_suspicious_agents = None

def get_suspicious_agents():
    global _suspicious_agents
    if _suspicious_agents is None:
        _suspicious_agents = {}
        for name, url in SOURCES.items():
            _suspicious_agents[name] = set()
            try:
                # Use the correct raw URL for iAugur
                fetch_url = url if "gist.githubusercontent.com" in url else url
                if name == "iAugurs_Bad_bot_list":
                    fetch_url = "https://gist.githubusercontent.com/iAugur/22355bcd285f66262cc57be3de53517d/raw"
                
                response = requests.get(fetch_url)
                response.raise_for_status()
                for line in response.text.splitlines():
                    if line.strip() and not line.startswith("#"):
                        # Parse iAugur's SetEnvIfNoCase format
                        if "SetEnvIfNoCase" in line and "BlockedAgent" in line:
                            start = line.find('"') + 1
                            end = line.rfind('"')
                            if start > 0 and end > start:
                                agent = line[start:end].replace("\\", "").strip()
                                _suspicious_agents[name].add(agent.lower())
                        # Parse Apache BrowserMatchNoCase format
                        elif "BrowserMatchNoCase" in line and "bad_bot" in line:
                            start = line.find('"') + 1
                            end = line.find('"', start)
                            if start > 0 and end > start:
                                agent = line[start:end].replace("\\b", "").replace("\\", "").strip()
                                _suspicious_agents[name].add(agent.lower())
                        # Parse simple list files
                        elif url.endswith(".list"):
                            _suspicious_agents[name].add(line.strip().lower())
                        # Parse CSV files
                        elif url.endswith(".csv") and not line.startswith("UserAgent"):
                            agent = line.split(',')[0].strip().strip('"')
                            _suspicious_agents[name].add(agent.lower())
            except requests.RequestException as e:
                print(f"Error fetching {name}: {e}")
    return _suspicious_agents   

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        data = request.get_json(silent=True) or request.form
        user_agent = data.get("user_agent", "").strip()
        
        if not user_agent:
            return render_template("index.html", error="User agent cannot be empty.")
        
        matches = [] # List of {source, pattern, confidence}
        user_agent_lower = user_agent.lower()

        agents = get_suspicious_agents()
        
        for source, patterns in agents.items():
            for pattern in patterns:
                if fnmatch.fnmatchcase(user_agent_lower, pattern.lower()):
                    confidence = "High" if pattern == user_agent_lower else "Medium"
                    matches.append({"source": source, "pattern": pattern, "confidence": confidence})

        # Calculate score
        score = sum(80 for m in matches if m["confidence"] == "High") + sum(40 for m in matches if m["confidence"] == "Medium")
        score = min(score, 100)
        summary = f"{len(matches)} match(es) found." if matches else "No matches found in known malicious user agent databases."

        return render_template("index.html", 
                               user_agent=user_agent, 
                               summary=summary, 
                               score=score,
                               matches=matches) # Pass matches to template

    return render_template("index.html")   

if __name__ == "__main__":
    app.run(port=5010, debug=True)   