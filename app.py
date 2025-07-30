from flask import Flask, request, render_template, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
import os
import json
import sqlite3
from datetime import datetime
import mapping
import re
import boto3
import yaml
import waf_analyzer

UPLOAD_FOLDER = 'uploads'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
ipset_refs = {}  # { arn: {name: name, rules: [list of rules using it] }}
regexpattern_refs = {} 

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def sanitize_for_json(obj):
    if isinstance(obj, bytes):
        return obj.decode('utf-8')  # decode bytes to string
    if isinstance(obj, dict):
        return {k: sanitize_for_json(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize_for_json(i) for i in obj]
    return obj

def collect_references(statement, rule_name, webacl_name):
    if not isinstance(statement, dict):
        return

    if "IPSetReferenceStatement" in statement:
        arn = statement["IPSetReferenceStatement"]["ARN"]
        # Extract name from ARN
        parts = arn.split('/')
        ipset_name = parts[-2] if len(parts) >= 2 else arn

        if arn not in ipset_refs:
            ipset_refs[arn] = {"name": ipset_name, "rules": []}
        ipset_refs[arn]["rules"].append({"web_acl": webacl_name, "rule_name": rule_name})

    if "RegexPatternSetReferenceStatement" in statement:
        arn = statement["RegexPatternSetReferenceStatement"]["ARN"]
        # Extract name from ARN
        parts = arn.split('/')
        regex_name = parts[-2] if len(parts) >= 2 else arn

        if arn not in regexpattern_refs:
            regexpattern_refs[arn] = {"name": regex_name, "rules": []}
        regexpattern_refs[arn]["rules"].append({"web_acl": webacl_name, "rule_name": rule_name})

    # Recurse deeper into nested statements
    for value in statement.values():
        if isinstance(value, dict):
            collect_references(value, rule_name, webacl_name)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    collect_references(item, rule_name, webacl_name)

def save_refs():
    with open(os.path.join(UPLOAD_FOLDER, "ipset_refs.json"), "w") as f:
        json.dump(ipset_refs, f)
    with open(os.path.join(UPLOAD_FOLDER, "regexpattern_refs.json"), "w") as f:
        json.dump(regexpattern_refs, f)

def load_refs():
    global ipset_refs, regexpattern_refs
    ipset_path = os.path.join(UPLOAD_FOLDER, "ipset_refs.json")
    regex_path = os.path.join(UPLOAD_FOLDER, "regexpattern_refs.json")
    if os.path.isfile(ipset_path):
        with open(ipset_path) as f:
            ipset_refs = json.load(f)
    if os.path.isfile(regex_path):
        with open(regex_path) as f:
            regexpattern_refs = json.load(f)
            
# Home route - list uploaded files
@app.route('/')
def index():
    files = [
        f for f in os.listdir(UPLOAD_FOLDER)
        if os.path.isfile(os.path.join(UPLOAD_FOLDER, f))
        and not (f.startswith("ipset_refs") or f.startswith("regexpattern_refs"))
    ]
    return render_template("index.html", files=files)

@app.route('/api/<file_id>/<rule_name>')
def get_files(file_id,rule_name):
    with open(f"{UPLOAD_FOLDER}/{file_id}") as f:
        data = json.load(f)
    rules = data.get("Rules", [])
    producers, consumers = mapping.find_label_relationships(rules)
    result = mapping.build_relationship(rule_name, rules, producers, consumers)
    return json.dumps(result)

# Upload endpoint
@app.route('/upload', methods=['POST'])
def upload():
    if 'file' not in request.files:
        return "No file part", 400
    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400
    if '.json' not in file.filename:
        return "Invalid file type", 400
    filename = secure_filename(file.filename)
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(filepath)

    return redirect(url_for('index'))

#view rules list
@app.route('/viewRules/<file_id>')
def process(file_id):
    with open(f"{UPLOAD_FOLDER}/{file_id}") as f:
        data = json.load(f)
    rules = data.get("Rules", [])
    return render_template("view_rules.html", rules=rules, file_id=file_id)  

# View mermaid graph
@app.route("/view/<file_id>/<rule_name>")
def view(file_id, rule_name):
    with open(f"{UPLOAD_FOLDER}/{file_id}") as f:
        data = json.load(f)
    rules = data.get("Rules", [])
    producers, consumers = mapping.find_label_relationships(rules)
    result = mapping.build_relationship(rule_name, rules, producers, consumers)
    graph = mapping.generate_mermaid_from_relationship(result, rule_name)
    #get the rule statement
    for rule in rules:
        if rule["Name"] == rule_name:
            rule_statement = rule["Statement"]
            break
    return render_template("viewer.html", graph=graph, rule_name=rule_name, rule_statement=rule_statement)

@app.route("/view-vis/<file_id>/<rule_name>")
def view_vis(file_id, rule_name):
    with open(f"{UPLOAD_FOLDER}/{file_id}") as f:
        data = json.load(f)
    rules = data.get("Rules", [])
    producers, consumers = mapping.find_label_relationships(rules)
    result = mapping.build_relationship(rule_name, rules, producers, consumers)
    #clean_map = mapping.clean_node(result)
    graph = mapping.generate_mermaid_from_relationship(result, rule_name)
    vis_data = mapping.mermaid_to_vis(graph)
    # Get the rule statement
    rule_statement = next((rule["Statement"] for rule in rules if rule["Name"] == rule_name), None)
    return render_template(
        "viewer_vis.html",
        nodes=vis_data["nodes"],
        edges=vis_data["edges"],
        rule_name=rule_name,
        rule_statement=rule_statement,
    )
    
#load from AWS
@app.route('/load_aws', methods=['POST'])
def load_aws():
    access_key = request.form.get('access_key')
    secret_key = request.form.get('secret_key')
    session_token = request.form.get('session_token')  # optional
    region = request.form.get('region')

    if not (access_key and secret_key and region):
        return "Missing required AWS credentials", 400

    if region == 'global':
        boto_region = 'us-east-1'  # CloudFront always uses us-east-1
        scope = 'CLOUDFRONT'
    else:
        boto_region = region
        scope = 'REGIONAL'

    session_params = {
        'aws_access_key_id': access_key,
        'aws_secret_access_key': secret_key,
        'region_name': boto_region
    }
    if session_token:
        session_params['aws_session_token'] = session_token

    try:
        session = boto3.Session(**session_params)
        waf = session.client('wafv2')

        # Fetch and save WebACLs
        response = waf.list_web_acls(Scope=scope)
        webacls = response.get('WebACLs', [])

        for acl in webacls:
            acl_name = acl['Name']
            acl_id = acl['Id']

            acl_details = waf.get_web_acl(
                Name=acl_name,
                Scope=scope,
                Id=acl_id
            )

            # Save WebACL as separate file
            acl_filename = f"WebACL_{acl_name}.json"
            acl_filepath = os.path.join(UPLOAD_FOLDER, acl_filename)
            with open(acl_filepath, "w") as f:
                json.dump(sanitize_for_json(acl_details['WebACL']), f, indent=2)

            # Save referenced IP sets
            for rule in acl_details['WebACL'].get('Rules', []):
                rule_name = rule.get('Name')
                statement = rule.get('Statement')
                collect_references(statement, rule_name, acl_name)
            
        # Save referenced IP sets
        for arn, ref_info in ipset_refs.items():
            parts = arn.split('/')
            ipset_name = ref_info['name']
            ipset_id = parts[-1]

            ipset = waf.get_ip_set(
                Name=ipset_name,
                Scope=scope,
                Id=ipset_id
            )
            
            # Save the IPSet JSON
            ipset_filename = f"IPSet_{ipset_name}.json"
            ipset_filepath = os.path.join(UPLOAD_FOLDER, ipset_filename)
            with open(ipset_filepath, "w") as f:
                json.dump(sanitize_for_json(ipset['IPSet']), f, indent=2)

        # Save referenced RegexPatternSets
        for arn, ref_info in regexpattern_refs.items():
            parts = arn.split('/')
            regex_name = ref_info['name']
            regex_id = parts[-1]

            regexset = waf.get_regex_pattern_set(
                Name=regex_name,
                Scope=scope,
                Id=regex_id
            )
            
            # Save the RegexPatternSet JSON
            regex_filename = f"RegexPatternSet_{regex_name}.json"
            regex_filepath = os.path.join(UPLOAD_FOLDER, regex_filename)
            with open(regex_filepath, "w") as f:
                json.dump(sanitize_for_json(regexset['RegexPatternSet']), f, indent=2)
        # Save references to files
        save_refs()
        return redirect(url_for('index'))
    except Exception as e:
        return f"Error connecting to AWS: {str(e)}", 500

@app.route('/view-ipset/<filename>')
def view_ipset(filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.isfile(filepath):
        return "IPSet file not found", 404

    # Load IPSet content
    with open(filepath) as f:
        ipset_content = json.load(f)
        
    #load refs
    load_refs()

    # Extract arn from file content
    arn = ipset_content.get("ARN", "")
    
    # Find related rules
    rules = ipset_refs[arn]["rules"]
    
    return render_template(
        'view_ipset.html',
        ipset_name=ipset_content.get("Name", ""),
        ipset_content=ipset_content,
        rules=rules,
        active_page="mapper"
    )

@app.route('/view-regex/<filename>')
def view_regex(filename):
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    if not os.path.isfile(filepath):
        return "RegexPatternSet file not found", 404

    #load refs
    load_refs()

    # Load RegexPatternSet content
    with open(filepath) as f:
        regex_content = json.load(f)

    # Extract ARN from file content
    arn = regex_content.get("ARN", "")

    # Find related rules
    rules = regexpattern_refs[arn].get('rules', [])

    return render_template(
        'view_regex.html',
        regex_name=regex_content.get("Name", ""),
        regex_content=regex_content,
        rules=rules,
        active_page="mapper"
    )


### WCU ANALYZER
@app.route('/wcu-analyzer', methods=['GET', 'POST'])
def wcu_analyzer():
    user_input = ""
    format_selected = "json"
    static_result = None
    ai_result = None
    static_error = None

    if request.method == 'POST':
        user_input = request.form.get("input_text", "")
        format_selected = request.form.get("format", "json")

        try:
            # Parse input
            if format_selected == "yaml":
                parsed_data = yaml.safe_load(user_input)
            else:
                parsed_data = json.loads(user_input)

            # Placeholder: perform static analysis (to be implemented)
            static_result = waf_analyzer.calculate_wcu_static(parsed_data)
        except Exception as e:
            static_error = str(e)

        # Placeholder: perform AI analysis (to be implemented)
        ai_result = {"summary": "AI analysis will be added here."}

    return render_template(
        "wcu_analyzer.html",
        user_input=user_input,
        format_selected=format_selected,
        static_result=static_result,
        static_error=static_error,
        ai_result=ai_result,
        active_page="wcu"
    )

if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0",port=5001)
