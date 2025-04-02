from flask import Flask, request, render_template, redirect, url_for, send_from_directory
from werkzeug.utils import secure_filename
import os
import json
import sqlite3
from datetime import datetime
import mapping
import re

UPLOAD_FOLDER = 'uploads'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Home route - list uploaded files
@app.route('/')
def index():
    files = [f for f in os.listdir(UPLOAD_FOLDER) if os.path.isfile(os.path.join(UPLOAD_FOLDER, f))]
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
    return render_template("viewer.html", graph=graph, rule_name=rule_name)

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
    return render_template(
        "viewer_vis.html",
        nodes=vis_data["nodes"],
        edges=vis_data["edges"],
        rule_name=rule_name
    )

if __name__ == '__main__':
    app.run(debug=True,host="0.0.0.0",port=5001)
